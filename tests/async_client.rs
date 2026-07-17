#![cfg(feature = "async")]

use std::{sync::Arc, time::Duration};

use bacnet_rs::{
    app::Apdu,
    client::{AsyncBacnetClient, ClientConfig, DiscoveredRouter},
    network::{NetworkAddress, Npdu},
    object::{
        database::ObjectDatabase, AnalogValue, Device, ObjectIdentifier, ObjectType,
        PropertyIdentifier, Segmentation,
    },
    property::PropertyValue,
    server::AsyncBacnetIpServer,
    service::{
        ConfirmedServiceChoice, IAmRequest, ReadPropertyRequest, ReadPropertyResponse,
        UnconfirmedServiceChoice,
    },
};
use tokio::net::UdpSocket;

fn parse_confirmed_request(frame: &[u8]) -> Apdu {
    let (_, npdu_length) = Npdu::decode(&frame[4..]).expect("decode NPDU");
    Apdu::decode(&frame[4 + npdu_length..]).expect("decode APDU")
}

fn read_property_ack(request: Apdu) -> (u32, Vec<u8>) {
    let Apdu::ConfirmedRequest {
        invoke_id,
        service_choice: ConfirmedServiceChoice::ReadProperty,
        service_data,
        ..
    } = request
    else {
        panic!("expected ReadProperty request")
    };
    let request = ReadPropertyRequest::decode(&service_data).unwrap();
    let instance = request.object_identifier.instance;
    let mut response = ReadPropertyResponse::new(
        request.object_identifier,
        request.property_identifier,
        vec![PropertyValue::Real(instance as f32)],
    );
    response.property_array_index = request.property_array_index;
    let mut service_data = Vec::new();
    response.encode(&mut service_data).unwrap();
    let apdu = Apdu::ComplexAck {
        segmented: false,
        more_follows: false,
        invoke_id,
        sequence_number: None,
        proposed_window_size: None,
        service_choice: ConfirmedServiceChoice::ReadProperty,
        service_data,
    };
    (instance, wrap_response(apdu))
}

fn wrap_response(apdu: Apdu) -> Vec<u8> {
    let mut payload = Npdu::new().encode();
    payload.extend_from_slice(&apdu.encode());
    let length = payload.len() + 4;
    let mut frame = vec![0x81, 0x0A, (length >> 8) as u8, length as u8];
    frame.extend_from_slice(&payload);
    frame
}

fn i_am_frame(device_id: u32, route: Option<NetworkAddress>) -> Vec<u8> {
    let mut npdu = Npdu::new();
    if let Some(route) = route {
        npdu.set_source(route);
    }
    let iam = IAmRequest::new(
        ObjectIdentifier::new(ObjectType::Device, device_id),
        1476,
        Segmentation::NoSegmentation,
        99,
    );
    let mut service_data = Vec::new();
    iam.encode(&mut service_data).unwrap();
    let mut payload = npdu.encode();
    payload.extend_from_slice(&[0x10, UnconfirmedServiceChoice::IAm as u8]);
    payload.extend_from_slice(&service_data);
    let length = payload.len() + 4;
    let mut frame = vec![0x81, 0x0A, (length >> 8) as u8, length as u8];
    frame.extend_from_slice(&payload);
    frame
}

async fn test_client(timeout: Duration, retries: u8) -> AsyncBacnetClient {
    AsyncBacnetClient::from_config(ClientConfig {
        host: "127.0.0.1".to_string(),
        port: 0,
        timeout,
        retries,
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn concurrent_reads_are_sent_before_either_response_arrives() {
    let device = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = device.local_addr().unwrap();
    let responder = tokio::spawn(async move {
        let mut buffer = [0_u8; 1500];
        let mut requests = Vec::new();
        for _ in 0..2 {
            let (length, source) = device.recv_from(&mut buffer).await.unwrap();
            requests.push((parse_confirmed_request(&buffer[..length]), source));
        }

        // Respond in reverse order to prove invoke-ID routing, rather than
        // request ordering, selects each waiting caller.
        for (request, source) in requests.into_iter().rev() {
            let (_, frame) = read_property_ack(request);
            device.send_to(&frame, source).await.unwrap();
        }
    });

    let client = test_client(Duration::from_secs(1), 0).await;
    let first = ObjectIdentifier::new(ObjectType::AnalogValue, 1);
    let second = ObjectIdentifier::new(ObjectType::AnalogValue, 2);
    let (first_result, second_result) = tokio::join!(
        client.read_property(address, first, PropertyIdentifier::PresentValue),
        client.read_property(address, second, PropertyIdentifier::PresentValue),
    );

    assert_eq!(first_result.unwrap(), vec![PropertyValue::Real(1.0)]);
    assert_eq!(second_result.unwrap(), vec![PropertyValue::Real(2.0)]);
    responder.await.unwrap();
}

#[tokio::test]
async fn timed_out_transaction_is_retried_without_blocking_the_endpoint() {
    let device = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = device.local_addr().unwrap();
    let responder = tokio::spawn(async move {
        let mut buffer = [0_u8; 1500];
        let (first_length, _) = device.recv_from(&mut buffer).await.unwrap();
        let first = parse_confirmed_request(&buffer[..first_length]);

        let (second_length, source) = device.recv_from(&mut buffer).await.unwrap();
        let second = parse_confirmed_request(&buffer[..second_length]);
        let (
            Apdu::ConfirmedRequest { invoke_id: a, .. },
            Apdu::ConfirmedRequest { invoke_id: b, .. },
        ) = (&first, &second)
        else {
            unreachable!()
        };
        assert_eq!(a, b, "a retry must retain its transaction invoke ID");
        let (_, frame) = read_property_ack(second);
        device.send_to(&frame, source).await.unwrap();
    });

    let client = test_client(Duration::from_millis(40), 1).await;
    let object = ObjectIdentifier::new(ObjectType::AnalogValue, 7);
    assert_eq!(
        client
            .read_property(address, object, PropertyIdentifier::PresentValue)
            .await
            .unwrap(),
        vec![PropertyValue::Real(7.0)]
    );
    responder.await.unwrap();
}

#[tokio::test]
async fn cancelled_requests_release_invoke_ids_before_new_work_is_admitted() {
    let device = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = device.local_addr().unwrap();
    let (all_received, received) = tokio::sync::oneshot::channel();
    let responder = tokio::spawn(async move {
        let mut buffer = [0_u8; 1500];
        for _ in 0..=u8::MAX {
            device.recv_from(&mut buffer).await.unwrap();
        }
        all_received.send(()).unwrap();

        let (length, source) = device.recv_from(&mut buffer).await.unwrap();
        let (_, frame) = read_property_ack(parse_confirmed_request(&buffer[..length]));
        device.send_to(&frame, source).await.unwrap();
    });

    let client = test_client(Duration::from_secs(5), 0).await;
    let object = ObjectIdentifier::new(ObjectType::AnalogValue, 9);
    let mut requests = Vec::new();
    for _ in 0..=u8::MAX {
        let client = client.clone();
        requests.push(tokio::spawn(async move {
            client
                .read_property(address, object, PropertyIdentifier::PresentValue)
                .await
        }));
    }
    received.await.unwrap();
    for request in requests {
        request.abort();
    }
    tokio::task::yield_now().await;

    assert_eq!(
        client
            .read_property(address, object, PropertyIdentifier::PresentValue)
            .await
            .unwrap(),
        vec![PropertyValue::Real(9.0)]
    );
    responder.await.unwrap();
}

#[tokio::test]
async fn who_is_collects_and_dedupes_i_am_responses() {
    let device = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = device.local_addr().unwrap();
    let responder = tokio::spawn(async move {
        let mut buffer = [0_u8; 1500];
        let (_, source) = device.recv_from(&mut buffer).await.unwrap();
        let frame = i_am_frame(1234, None);
        device.send_to(&frame, source).await.unwrap();
        device.send_to(&frame, source).await.unwrap();
    });

    let client = test_client(Duration::from_millis(200), 0).await;
    let devices = client.who_is_to(address, None, None).await.unwrap();
    assert_eq!(devices.len(), 1, "duplicate I-Am must be de-duplicated");
    assert_eq!(devices[0].device_id, 1234);
    assert_eq!(devices[0].address, address);
    assert_eq!(devices[0].route, None);
    assert_eq!(devices[0].max_apdu, 1476);
    responder.await.unwrap();
}

#[tokio::test]
async fn routed_i_am_yields_route_used_for_confirmed_requests() {
    let router = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = router.local_addr().unwrap();
    let route = NetworkAddress::new(100, vec![146, 52]);
    let responder = tokio::spawn({
        let route = route.clone();
        async move {
            let mut buffer = [0_u8; 1500];
            let (_, source) = router.recv_from(&mut buffer).await.unwrap();
            router
                .send_to(&i_am_frame(13458, Some(route.clone())), source)
                .await
                .unwrap();

            // The follow-up confirmed request must carry the discovered
            // route as its NPDU destination.
            let (length, source) = router.recv_from(&mut buffer).await.unwrap();
            let (npdu, npdu_length) = Npdu::decode(&buffer[4..length]).unwrap();
            assert_eq!(npdu.destination, Some(route));
            let apdu = Apdu::decode(&buffer[4 + npdu_length..length]).unwrap();
            let (_, frame) = read_property_ack(apdu);
            router.send_to(&frame, source).await.unwrap();
        }
    });

    let client = test_client(Duration::from_millis(200), 0).await;
    let devices = client.who_is_to(address, None, None).await.unwrap();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].route, Some(route));

    let object = ObjectIdentifier::new(ObjectType::AnalogValue, 5);
    let values = client
        .read_property(
            devices[0].target(),
            object,
            PropertyIdentifier::PresentValue,
        )
        .await
        .unwrap();
    assert_eq!(values, vec![PropertyValue::Real(5.0)]);
    responder.await.unwrap();
}

#[tokio::test]
async fn who_is_router_collects_advertised_networks() {
    let router = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = router.local_addr().unwrap();
    let responder = tokio::spawn(async move {
        let mut buffer = [0_u8; 1500];
        let (length, source) = router.recv_from(&mut buffer).await.unwrap();
        assert_eq!(buffer[..2], [0x81, 0x0A], "expected unicast Who-Is-Router");
        assert!(length >= 7);
        let frame = [
            0x81, 0x0A, 0x00, 0x0B, // BVLC Original-Unicast-NPDU
            0x01, 0x80, // NPDU network-layer message
            0x01, // I-Am-Router-To-Network
            0x00, 0x64, // network 100
            0x01, 0x2C, // network 300
        ];
        router.send_to(&frame, source).await.unwrap();
    });

    let client = test_client(Duration::from_millis(200), 0).await;
    let routers = client.who_is_router_to(address, None).await.unwrap();
    assert_eq!(
        routers,
        vec![DiscoveredRouter {
            address,
            networks: vec![100, 300],
        }]
    );
    responder.await.unwrap();
}

#[tokio::test]
async fn discovery_window_does_not_block_confirmed_requests() {
    let device = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = device.local_addr().unwrap();
    let responder = tokio::spawn(async move {
        let mut buffer = [0_u8; 1500];
        // The Who-Is arrives first but is answered only after the confirmed
        // read has been served, proving the window doesn't serialize traffic.
        let (_, whois_source) = device.recv_from(&mut buffer).await.unwrap();
        let (length, source) = device.recv_from(&mut buffer).await.unwrap();
        let (_, frame) = read_property_ack(parse_confirmed_request(&buffer[..length]));
        device.send_to(&frame, source).await.unwrap();
        device
            .send_to(&i_am_frame(77, None), whois_source)
            .await
            .unwrap();
    });

    let client = test_client(Duration::from_millis(500), 0).await;
    let object = ObjectIdentifier::new(ObjectType::AnalogValue, 3);
    let (devices, values) = tokio::join!(
        client.who_is_to(address, None, None),
        client.read_property(address, object, PropertyIdentifier::PresentValue),
    );
    assert_eq!(values.unwrap(), vec![PropertyValue::Real(3.0)]);
    let devices = devices.unwrap();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].device_id, 77);
    responder.await.unwrap();
}

#[tokio::test]
async fn hosted_server_supports_async_object_inspection_and_writes() {
    let database = Arc::new(ObjectDatabase::new(Device::new(
        1234,
        "Async test device".to_string(),
    )));
    let mut value = AnalogValue::new(1, "Setpoint".to_string());
    value.present_value = 21.5;
    let object = value.identifier;
    database.add_object(Box::new(value)).unwrap();

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let server = AsyncBacnetIpServer::from_socket(socket, Arc::clone(&database));
    let (shutdown, stopped) = tokio::sync::oneshot::channel::<()>();
    let server_task = tokio::spawn(server.run_until(async {
        let _ = stopped.await;
    }));

    let client = test_client(Duration::from_secs(1), 0).await;
    let (objects, snapshot) = tokio::join!(
        client.read_object_list(address, 1234),
        client.read_object_properties(address, object),
    );
    let objects = objects.unwrap();
    assert!(objects.contains(&ObjectIdentifier::new(ObjectType::Device, 1234)));
    assert!(objects.contains(&object));
    assert!(snapshot
        .unwrap()
        .properties
        .iter()
        .any(|property| property.property_identifier == PropertyIdentifier::PresentValue));

    client
        .write_property(
            address,
            object,
            PropertyIdentifier::PresentValue,
            &PropertyValue::Real(24.0),
            Some(8),
        )
        .await
        .unwrap();
    assert_eq!(
        client
            .read_property(address, object, PropertyIdentifier::PresentValue)
            .await
            .unwrap(),
        vec![PropertyValue::Real(24.0)]
    );

    shutdown.send(()).unwrap();
    server_task.await.unwrap().unwrap();
}
