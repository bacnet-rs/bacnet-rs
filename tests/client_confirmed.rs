//! End-to-end tests for the client's confirmed-request path (ReadProperty /
//! WriteProperty) over loopback.
//!
//! Each test spins up a tiny in-process "device" that receives one confirmed
//! request, extracts its invoke ID, and replies with a frame the test builds
//! using the crate's own encoders. This exercises the real
//! `send_confirmed_request` transaction path: invoke-ID allocation, the
//! BVLC/NPDU/APDU framing, and the ComplexAck / SimpleAck / Error handling added
//! across commits 2-4.

#![cfg(feature = "std")]

use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use bacnet_rs::{
    app::Apdu,
    client::{BacnetClient, ClientError, PropertyReadOutcome, WriteOutcome},
    network::Npdu,
    object::{ObjectIdentifier, ObjectType, PropertyIdentifier},
    property::PropertyValue,
    service::{
        AbortReason, ConfirmedServiceChoice, PropertyResult, ReadAccessResult,
        ReadPropertyMultipleRequest, ReadPropertyMultipleResponse, ReadPropertyRequest,
        ReadPropertyResponse, RejectReason,
    },
};

/// Extract the invoke ID and service choice from a received confirmed-request
/// frame (BVLC + NPDU + APDU).
fn parse_confirmed_request(frame: &[u8]) -> (u8, ConfirmedServiceChoice) {
    match parse_confirmed_request_apdu(frame) {
        Apdu::ConfirmedRequest {
            invoke_id,
            service_choice,
            ..
        } => (invoke_id, service_choice),
        other => panic!("expected ConfirmedRequest, got {other:?}"),
    }
}

fn parse_confirmed_request_apdu(frame: &[u8]) -> Apdu {
    let (_npdu, npdu_len) = Npdu::decode(&frame[4..]).expect("decode NPDU");
    Apdu::decode(&frame[4 + npdu_len..]).expect("decode APDU")
}

/// Wrap a response APDU in NPDU + BVLC (Original-Unicast-NPDU) framing.
fn wrap_response(apdu: Apdu) -> Vec<u8> {
    let mut message = Npdu::new().encode();
    message.extend_from_slice(&apdu.encode());

    let mut frame = vec![0x81, 0x0A, 0x00, 0x00];
    frame.extend_from_slice(&message);
    let len = frame.len() as u16;
    frame[2] = (len >> 8) as u8;
    frame[3] = (len & 0xFF) as u8;
    frame
}

/// Spawn a one-shot loopback device: it waits for a single confirmed request
/// and replies with `make_response(invoke_id, service_choice)`. Returns the
/// device's address.
fn spawn_device<F>(make_response: F) -> SocketAddr
where
    F: FnOnce(u8, ConfirmedServiceChoice) -> Apdu + Send + 'static,
{
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind device");
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let addr = socket.local_addr().unwrap();

    thread::spawn(move || {
        let mut buf = [0u8; 1500];
        if let Ok((len, src)) = socket.recv_from(&mut buf) {
            let (invoke_id, service_choice) = parse_confirmed_request(&buf[..len]);
            let frame = wrap_response(make_response(invoke_id, service_choice));
            socket.send_to(&frame, src).expect("send response");
        }
    });

    addr
}

/// Like [`spawn_device`] but answers every confirmed request until the peer
/// goes idle (1s with no request), calling `make_response` for each. Used for
/// flows that issue several requests, e.g. write then a polled read-back.
fn spawn_device_loop<F>(mut make_response: F) -> SocketAddr
where
    F: FnMut(u8, ConfirmedServiceChoice) -> Apdu + Send + 'static,
{
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind device");
    socket
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let addr = socket.local_addr().unwrap();

    thread::spawn(move || {
        let mut buf = [0u8; 1500];
        while let Ok((len, src)) = socket.recv_from(&mut buf) {
            let (invoke_id, service_choice) = parse_confirmed_request(&buf[..len]);
            let frame = wrap_response(make_response(invoke_id, service_choice));
            socket.send_to(&frame, src).expect("send response");
        }
    });

    addr
}

fn spawn_request_device_loop<F>(mut make_response: F) -> SocketAddr
where
    F: FnMut(Apdu) -> Apdu + Send + 'static,
{
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind device");
    socket
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let addr = socket.local_addr().unwrap();

    thread::spawn(move || {
        let mut buf = [0u8; 1500];
        while let Ok((len, src)) = socket.recv_from(&mut buf) {
            let request = parse_confirmed_request_apdu(&buf[..len]);
            let frame = wrap_response(make_response(request));
            socket.send_to(&frame, src).expect("send response");
        }
    });

    addr
}

fn complex_ack(
    invoke_id: u8,
    service_choice: ConfirmedServiceChoice,
    service_data: Vec<u8>,
) -> Apdu {
    Apdu::ComplexAck {
        segmented: false,
        more_follows: false,
        invoke_id,
        sequence_number: None,
        proposed_window_size: None,
        service_choice,
        service_data,
    }
}

fn read_property_request_ack(
    invoke_id: u8,
    request: &ReadPropertyRequest,
    values: Vec<PropertyValue>,
) -> Apdu {
    let mut response = ReadPropertyResponse::new(
        request.object_identifier,
        request.property_identifier,
        values,
    );
    response.property_array_index = request.property_array_index;
    let mut service_data = Vec::new();
    response.encode(&mut service_data).expect("encode response");
    complex_ack(
        invoke_id,
        ConfirmedServiceChoice::ReadProperty,
        service_data,
    )
}

fn object_for_index(device_id: u32, index: u32) -> ObjectIdentifier {
    if index == 1 {
        ObjectIdentifier::new(ObjectType::Device, device_id)
    } else {
        ObjectIdentifier::new(ObjectType::AnalogValue, index - 1)
    }
}

fn rpm_object_list_ack(
    invoke_id: u8,
    request: &ReadPropertyMultipleRequest,
    device_id: u32,
) -> Apdu {
    let results = request
        .read_access_specifications
        .iter()
        .flat_map(|access| {
            access.property_references.iter().map(|reference| {
                let index = reference
                    .property_array_index
                    .expect("test expects indexed RPM references");
                PropertyResult::value(
                    reference.property_identifier,
                    Some(index),
                    vec![PropertyValue::ObjectIdentifier(object_for_index(
                        device_id, index,
                    ))],
                )
            })
        })
        .collect();
    let response = ReadPropertyMultipleResponse::new(vec![ReadAccessResult::new(
        ObjectIdentifier::new(ObjectType::Device, device_id),
        results,
    )]);
    let mut service_data = Vec::new();
    response
        .encode(&mut service_data)
        .expect("encode RPM response");
    complex_ack(
        invoke_id,
        ConfirmedServiceChoice::ReadPropertyMultiple,
        service_data,
    )
}

fn rpm_properties_ack(
    invoke_id: u8,
    object: ObjectIdentifier,
    results: Vec<PropertyResult>,
) -> Apdu {
    let response = ReadPropertyMultipleResponse::new(vec![ReadAccessResult::new(object, results)]);
    let mut service_data = Vec::new();
    response
        .encode(&mut service_data)
        .expect("encode RPM response");
    complex_ack(
        invoke_id,
        ConfirmedServiceChoice::ReadPropertyMultiple,
        service_data,
    )
}

/// Build a ComplexAck carrying a ReadProperty response with a single value.
fn read_property_ack(invoke_id: u8, object: ObjectIdentifier, value: PropertyValue) -> Apdu {
    let response = ReadPropertyResponse::new(object, PropertyIdentifier::PresentValue, vec![value]);
    let mut service_data = Vec::new();
    response.encode(&mut service_data).expect("encode response");
    Apdu::ComplexAck {
        segmented: false,
        more_follows: false,
        invoke_id,
        sequence_number: None,
        proposed_window_size: None,
        service_choice: ConfirmedServiceChoice::ReadProperty,
        service_data,
    }
}

fn test_client() -> BacnetClient {
    BacnetClient::builder()
        .local_addr("127.0.0.1")
        .timeout(Duration::from_secs(3))
        .build()
        .expect("build client")
}

#[test]
fn read_property_decodes_complex_ack() {
    let object = ObjectIdentifier::new(ObjectType::AnalogValue, 1);

    let addr = spawn_device(move |invoke_id, _service_choice| {
        let response = ReadPropertyResponse::new(
            object,
            PropertyIdentifier::PresentValue,
            vec![PropertyValue::Real(72.5)],
        );
        let mut service_data = Vec::new();
        response.encode(&mut service_data).expect("encode response");

        Apdu::ComplexAck {
            segmented: false,
            more_follows: false,
            invoke_id,
            sequence_number: None,
            proposed_window_size: None,
            service_choice: ConfirmedServiceChoice::ReadProperty,
            service_data,
        }
    });

    let values = test_client()
        .read_property(addr, object, PropertyIdentifier::PresentValue)
        .expect("read should succeed");

    assert_eq!(values, vec![PropertyValue::Real(72.5)]);
}

#[test]
fn read_property_surfaces_error_pdu() {
    let object = ObjectIdentifier::new(ObjectType::AnalogValue, 99);

    // Error class 1 (object), code 32 (unknown-object) for example.
    let addr = spawn_device(|invoke_id, _service_choice| Apdu::Error {
        invoke_id,
        service_choice: ConfirmedServiceChoice::ReadProperty,
        error_class: 1,
        error_code: 32,
    });

    let err = test_client()
        .read_property(addr, object, PropertyIdentifier::PresentValue)
        .expect_err("device returned an error PDU");

    assert!(
        matches!(err, ClientError::PropertyError { class: 1, code: 32 }),
        "expected PropertyError(1, 32), got {err:?}"
    );
}

#[test]
fn confirmed_request_retries_after_timeout() {
    let object = ObjectIdentifier::new(ObjectType::AnalogValue, 1);
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let address = socket.local_addr().unwrap();
    let attempts = Arc::new(AtomicUsize::new(0));
    let observed_attempts = Arc::clone(&attempts);
    thread::spawn(move || {
        let mut buffer = [0_u8; 1500];
        while let Ok((length, source)) = socket.recv_from(&mut buffer) {
            let attempt = observed_attempts.fetch_add(1, Ordering::SeqCst) + 1;
            if attempt == 1 {
                continue;
            }
            let (invoke_id, _) = parse_confirmed_request(&buffer[..length]);
            let frame = wrap_response(read_property_ack(
                invoke_id,
                object,
                PropertyValue::Real(17.5),
            ));
            socket.send_to(&frame, source).unwrap();
            break;
        }
    });
    let client = BacnetClient::builder()
        .local_addr("127.0.0.1")
        .timeout(Duration::from_millis(100))
        .retries(1)
        .build()
        .unwrap();

    assert_eq!(
        client
            .read_property(address, object, PropertyIdentifier::PresentValue)
            .unwrap(),
        vec![PropertyValue::Real(17.5)]
    );
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
}

#[test]
fn object_list_prefers_one_complete_read_and_retains_device_object() {
    let device_id = 1234;
    let device_object = ObjectIdentifier::new(ObjectType::Device, device_id);
    let expected = vec![
        device_object,
        ObjectIdentifier::new(ObjectType::AnalogValue, 1),
        ObjectIdentifier::new(ObjectType::AnalogValue, 2),
    ];
    let response_values = expected
        .iter()
        .copied()
        .map(PropertyValue::ObjectIdentifier)
        .collect::<Vec<_>>();
    let addr = spawn_request_device_loop(move |request| {
        let Apdu::ConfirmedRequest {
            invoke_id,
            service_choice: ConfirmedServiceChoice::ReadProperty,
            service_data,
            ..
        } = request
        else {
            panic!("expected complete ReadProperty request")
        };
        let request = ReadPropertyRequest::decode(&service_data).unwrap();
        assert_eq!(request.property_array_index, None);
        read_property_request_ack(invoke_id, &request, response_values.clone())
    });

    assert_eq!(
        test_client()
            .read_object_list(addr, device_id)
            .expect("complete Object_List should succeed"),
        expected
    );
}

#[test]
fn object_list_does_not_hide_read_access_errors_with_fallbacks() {
    let requests = Arc::new(AtomicUsize::new(0));
    let observed_requests = Arc::clone(&requests);
    let addr = spawn_request_device_loop(move |request| {
        observed_requests.fetch_add(1, Ordering::SeqCst);
        let Apdu::ConfirmedRequest {
            invoke_id,
            service_choice,
            ..
        } = request
        else {
            unreachable!()
        };
        Apdu::Error {
            invoke_id,
            service_choice,
            error_class: 2,
            error_code: 27,
        }
    });

    assert!(matches!(
        test_client().read_object_list(addr, 1234),
        Err(ClientError::PropertyError { class: 2, code: 27 })
    ));
    assert_eq!(requests.load(Ordering::SeqCst), 1);
}

#[test]
fn object_list_uses_multiple_indexed_rpm_batches_when_complete_read_is_too_large() {
    let device_id = 1234;
    let length = 40_u32;
    let rpm_requests = Arc::new(AtomicUsize::new(0));
    let observed_rpm_requests = Arc::clone(&rpm_requests);
    let addr = spawn_request_device_loop(move |request| {
        let Apdu::ConfirmedRequest {
            invoke_id,
            service_choice,
            service_data,
            ..
        } = request
        else {
            unreachable!()
        };
        match service_choice {
            ConfirmedServiceChoice::ReadProperty => {
                let request = ReadPropertyRequest::decode(&service_data).unwrap();
                match request.property_array_index {
                    None => Apdu::Abort {
                        server: true,
                        invoke_id,
                        abort_reason: AbortReason::ApduTooLong,
                    },
                    Some(0) => read_property_request_ack(
                        invoke_id,
                        &request,
                        vec![PropertyValue::Unsigned(length.into())],
                    ),
                    index => panic!("unexpected individual array read {index:?}"),
                }
            }
            ConfirmedServiceChoice::ReadPropertyMultiple => {
                observed_rpm_requests.fetch_add(1, Ordering::SeqCst);
                let request = ReadPropertyMultipleRequest::decode(&service_data).unwrap();
                rpm_object_list_ack(invoke_id, &request, device_id)
            }
            service => panic!("unexpected service {service:?}"),
        }
    });

    let objects = test_client().read_object_list(addr, device_id).unwrap();
    assert_eq!(objects.len(), length as usize);
    assert_eq!(
        objects[0],
        ObjectIdentifier::new(ObjectType::Device, device_id)
    );
    assert_eq!(
        objects[39],
        ObjectIdentifier::new(ObjectType::AnalogValue, 39)
    );
    assert_eq!(rpm_requests.load(Ordering::SeqCst), 2);
}

#[test]
fn object_list_falls_back_to_individual_indexes_when_rpm_is_unsupported() {
    let device_id = 1234;
    let length = 3_u32;
    let individual_reads = Arc::new(AtomicUsize::new(0));
    let observed_individual_reads = Arc::clone(&individual_reads);
    let addr = spawn_request_device_loop(move |request| {
        let Apdu::ConfirmedRequest {
            invoke_id,
            service_choice,
            service_data,
            ..
        } = request
        else {
            unreachable!()
        };
        match service_choice {
            ConfirmedServiceChoice::ReadProperty => {
                let request = ReadPropertyRequest::decode(&service_data).unwrap();
                match request.property_array_index {
                    None => Apdu::Abort {
                        server: true,
                        invoke_id,
                        abort_reason: AbortReason::ApduTooLong,
                    },
                    Some(0) => read_property_request_ack(
                        invoke_id,
                        &request,
                        vec![PropertyValue::Unsigned(length.into())],
                    ),
                    Some(index) => {
                        observed_individual_reads.fetch_add(1, Ordering::SeqCst);
                        read_property_request_ack(
                            invoke_id,
                            &request,
                            vec![PropertyValue::ObjectIdentifier(object_for_index(
                                device_id, index,
                            ))],
                        )
                    }
                }
            }
            ConfirmedServiceChoice::ReadPropertyMultiple => Apdu::Reject {
                invoke_id,
                reject_reason: RejectReason::UnrecognizedService,
            },
            service => panic!("unexpected service {service:?}"),
        }
    });

    let objects = test_client().read_object_list(addr, device_id).unwrap();
    assert_eq!(
        objects,
        (1..=length)
            .map(|index| object_for_index(device_id, index))
            .collect::<Vec<_>>()
    );
    assert_eq!(individual_reads.load(Ordering::SeqCst), length as usize);
}

#[test]
fn object_list_reduces_rpm_batch_size_after_apdu_too_long() {
    let device_id = 1234;
    let length = 4_u32;
    let rpm_requests = Arc::new(AtomicUsize::new(0));
    let observed_rpm_requests = Arc::clone(&rpm_requests);
    let addr = spawn_request_device_loop(move |request| {
        let Apdu::ConfirmedRequest {
            invoke_id,
            service_choice,
            service_data,
            ..
        } = request
        else {
            unreachable!()
        };
        match service_choice {
            ConfirmedServiceChoice::ReadProperty => {
                let request = ReadPropertyRequest::decode(&service_data).unwrap();
                match request.property_array_index {
                    None => Apdu::Abort {
                        server: true,
                        invoke_id,
                        abort_reason: AbortReason::ApduTooLong,
                    },
                    Some(0) => read_property_request_ack(
                        invoke_id,
                        &request,
                        vec![PropertyValue::Unsigned(length.into())],
                    ),
                    index => panic!("unexpected individual array read {index:?}"),
                }
            }
            ConfirmedServiceChoice::ReadPropertyMultiple => {
                observed_rpm_requests.fetch_add(1, Ordering::SeqCst);
                let request = ReadPropertyMultipleRequest::decode(&service_data).unwrap();
                let count = request.read_access_specifications[0]
                    .property_references
                    .len();
                if count > 2 {
                    Apdu::Abort {
                        server: true,
                        invoke_id,
                        abort_reason: AbortReason::ApduTooLong,
                    }
                } else {
                    rpm_object_list_ack(invoke_id, &request, device_id)
                }
            }
            service => panic!("unexpected service {service:?}"),
        }
    });

    let objects = test_client().read_object_list(addr, device_id).unwrap();
    assert_eq!(objects.len(), length as usize);
    assert_eq!(rpm_requests.load(Ordering::SeqCst), 3);
}

#[cfg(feature = "async")]
#[tokio::test]
async fn object_list_async_stream_uses_the_same_fallback_engine() {
    use tokio_stream::StreamExt;

    let device_id = 1234;
    let length = 40_u32;
    let addr = spawn_request_device_loop(move |request| {
        let Apdu::ConfirmedRequest {
            invoke_id,
            service_choice,
            service_data,
            ..
        } = request
        else {
            unreachable!()
        };
        match service_choice {
            ConfirmedServiceChoice::ReadProperty => {
                let request = ReadPropertyRequest::decode(&service_data).unwrap();
                match request.property_array_index {
                    None => Apdu::Abort {
                        server: true,
                        invoke_id,
                        abort_reason: AbortReason::ApduTooLong,
                    },
                    Some(0) => read_property_request_ack(
                        invoke_id,
                        &request,
                        vec![PropertyValue::Unsigned(length.into())],
                    ),
                    index => panic!("unexpected individual array read {index:?}"),
                }
            }
            ConfirmedServiceChoice::ReadPropertyMultiple => {
                let request = ReadPropertyMultipleRequest::decode(&service_data).unwrap();
                rpm_object_list_ack(invoke_id, &request, device_id)
            }
            service => panic!("unexpected service {service:?}"),
        }
    });

    let client = Arc::new(test_client());
    let mut stream = client.read_object_list_stream(addr, device_id);
    let first = stream.next().await.unwrap().unwrap();
    assert_eq!(first, ObjectIdentifier::new(ObjectType::Device, device_id));

    let mut remaining = Vec::new();
    while let Some(object) = stream.next().await {
        remaining.push(object.unwrap());
    }
    assert_eq!(remaining.len(), length as usize - 1);
    assert_eq!(
        remaining.last(),
        Some(&ObjectIdentifier::new(ObjectType::AnalogValue, 39))
    );
}

#[test]
fn object_properties_prefers_one_rpm_all_request_and_retains_property_errors() {
    let object = ObjectIdentifier::new(ObjectType::AnalogValue, 7);
    let requests = Arc::new(AtomicUsize::new(0));
    let observed_requests = Arc::clone(&requests);
    let addr = spawn_request_device_loop(move |request| {
        observed_requests.fetch_add(1, Ordering::SeqCst);
        let Apdu::ConfirmedRequest {
            invoke_id,
            service_choice: ConfirmedServiceChoice::ReadPropertyMultiple,
            service_data,
            ..
        } = request
        else {
            panic!("expected RPM ALL request")
        };
        let request = ReadPropertyMultipleRequest::decode(&service_data).unwrap();
        assert_eq!(
            request.read_access_specifications[0].property_references[0].property_identifier,
            PropertyIdentifier::All
        );
        rpm_properties_ack(
            invoke_id,
            object,
            vec![
                PropertyResult::value(
                    PropertyIdentifier::ObjectName,
                    None,
                    vec![PropertyValue::CharacterString("Temperature".into())],
                ),
                PropertyResult::value(
                    PropertyIdentifier::PresentValue,
                    None,
                    vec![PropertyValue::Real(21.5)],
                ),
                PropertyResult::error(PropertyIdentifier::Description, None, 2, 32),
            ],
        )
    });

    let snapshot = test_client().read_object_properties(addr, object).unwrap();

    assert_eq!(snapshot.object_identifier, object);
    assert_eq!(snapshot.properties.len(), 3);
    assert!(matches!(
        snapshot.properties[2].outcome,
        PropertyReadOutcome::Error { class: 2, code: 32 }
    ));
    assert_eq!(requests.load(Ordering::SeqCst), 1);
}

#[test]
fn object_properties_falls_back_to_individual_reads_without_rpm() {
    let object = ObjectIdentifier::new(ObjectType::AnalogValue, 7);
    let rpm_requests = Arc::new(AtomicUsize::new(0));
    let observed_rpm_requests = Arc::clone(&rpm_requests);
    let addr = spawn_request_device_loop(move |request| {
        let Apdu::ConfirmedRequest {
            invoke_id,
            service_choice,
            service_data,
            ..
        } = request
        else {
            unreachable!()
        };
        match service_choice {
            ConfirmedServiceChoice::ReadPropertyMultiple => {
                observed_rpm_requests.fetch_add(1, Ordering::SeqCst);
                Apdu::Reject {
                    invoke_id,
                    reject_reason: RejectReason::UnrecognizedService,
                }
            }
            ConfirmedServiceChoice::ReadProperty => {
                let request = ReadPropertyRequest::decode(&service_data).unwrap();
                if request.property_identifier == PropertyIdentifier::Description {
                    Apdu::Error {
                        invoke_id,
                        service_choice,
                        error_class: 2,
                        error_code: 32,
                    }
                } else {
                    let values = match request.property_identifier {
                        PropertyIdentifier::PropertyList => vec![
                            PropertyValue::Enumerated(PropertyIdentifier::PresentValue.into()),
                            PropertyValue::Enumerated(PropertyIdentifier::Description.into()),
                        ],
                        PropertyIdentifier::ObjectIdentifier => {
                            vec![PropertyValue::ObjectIdentifier(object)]
                        }
                        PropertyIdentifier::ObjectName => {
                            vec![PropertyValue::CharacterString("Temperature".into())]
                        }
                        PropertyIdentifier::ObjectType => {
                            vec![PropertyValue::Enumerated(u32::from(object.object_type))]
                        }
                        PropertyIdentifier::PresentValue => vec![PropertyValue::Real(21.5)],
                        property => panic!("unexpected property {property:?}"),
                    };
                    read_property_request_ack(invoke_id, &request, values)
                }
            }
            service => panic!("unexpected service {service:?}"),
        }
    });

    let snapshot = test_client().read_object_properties(addr, object).unwrap();

    assert_eq!(snapshot.properties.len(), 6);
    let description = snapshot
        .properties
        .iter()
        .find(|property| property.property_identifier == PropertyIdentifier::Description)
        .unwrap();
    assert_eq!(
        description.outcome,
        PropertyReadOutcome::Error { class: 2, code: 32 }
    );
    assert_eq!(rpm_requests.load(Ordering::SeqCst), 2);
}

#[test]
fn object_properties_reduces_rpm_batch_size_after_apdu_too_long() {
    let object = ObjectIdentifier::new(ObjectType::AnalogValue, 7);
    let advertised = [
        PropertyIdentifier::PresentValue,
        PropertyIdentifier::Description,
        PropertyIdentifier::StatusFlags,
        PropertyIdentifier::Units,
        PropertyIdentifier::OutOfService,
    ];
    let expected_property_count = advertised.len() + 4;
    let rpm_batches = Arc::new(AtomicUsize::new(0));
    let observed_rpm_batches = Arc::clone(&rpm_batches);
    let addr = spawn_request_device_loop(move |request| {
        let Apdu::ConfirmedRequest {
            invoke_id,
            service_choice,
            service_data,
            ..
        } = request
        else {
            unreachable!()
        };
        match service_choice {
            ConfirmedServiceChoice::ReadProperty => {
                let request = ReadPropertyRequest::decode(&service_data).unwrap();
                assert_eq!(
                    request.property_identifier,
                    PropertyIdentifier::PropertyList
                );
                read_property_request_ack(
                    invoke_id,
                    &request,
                    advertised
                        .iter()
                        .copied()
                        .map(|property| PropertyValue::Enumerated(property.into()))
                        .collect(),
                )
            }
            ConfirmedServiceChoice::ReadPropertyMultiple => {
                let request = ReadPropertyMultipleRequest::decode(&service_data).unwrap();
                let references = &request.read_access_specifications[0].property_references;
                if references.len() == 1
                    && references[0].property_identifier == PropertyIdentifier::All
                {
                    return Apdu::Abort {
                        server: true,
                        invoke_id,
                        abort_reason: AbortReason::ApduTooLong,
                    };
                }
                observed_rpm_batches.fetch_add(1, Ordering::SeqCst);
                if references.len() > 3 {
                    Apdu::Abort {
                        server: true,
                        invoke_id,
                        abort_reason: AbortReason::ApduTooLong,
                    }
                } else {
                    rpm_properties_ack(
                        invoke_id,
                        object,
                        references
                            .iter()
                            .map(|reference| {
                                PropertyResult::value(
                                    reference.property_identifier,
                                    None,
                                    vec![PropertyValue::Unsigned(1)],
                                )
                            })
                            .collect(),
                    )
                }
            }
            service => panic!("unexpected service {service:?}"),
        }
    });

    let snapshot = test_client().read_object_properties(addr, object).unwrap();

    assert_eq!(snapshot.properties.len(), expected_property_count);
    assert!(rpm_batches.load(Ordering::SeqCst) > 3);
}

#[test]
fn write_property_accepts_simple_ack() {
    let object = ObjectIdentifier::new(ObjectType::AnalogValue, 1);

    let addr = spawn_device(|invoke_id, _service_choice| Apdu::SimpleAck {
        invoke_id,
        service_choice: ConfirmedServiceChoice::WriteProperty as u8,
    });

    test_client()
        .write_property(
            addr,
            object,
            PropertyIdentifier::PresentValue,
            &PropertyValue::Real(50.0),
            Some(8),
        )
        .expect("write should be acknowledged");
}

#[test]
fn write_property_verified_confirms_when_readback_matches() {
    let object = ObjectIdentifier::new(ObjectType::AnalogValue, 1);

    // Two requests: WriteProperty -> SimpleAck, then ReadProperty -> the value
    // we just wrote, so the verify succeeds.
    let addr = spawn_device_loop(move |invoke_id, service_choice| match service_choice {
        ConfirmedServiceChoice::WriteProperty => Apdu::SimpleAck {
            invoke_id,
            service_choice: ConfirmedServiceChoice::WriteProperty as u8,
        },
        ConfirmedServiceChoice::ReadProperty => {
            read_property_ack(invoke_id, object, PropertyValue::Real(3.0))
        }
        other => panic!("unexpected service {other:?}"),
    });

    let outcome = test_client()
        .write_property_verified(
            addr,
            object,
            PropertyIdentifier::PresentValue,
            &PropertyValue::Real(3.0),
            Some(8),
        )
        .expect("write+verify should not error");

    assert_eq!(outcome, WriteOutcome::Verified);
}

#[test]
fn write_property_verified_reports_not_effective_when_overridden() {
    let object = ObjectIdentifier::new(ObjectType::AnalogValue, 4);

    // Device accepts the write (SimpleAck) but the read-back still reports the
    // old value 2.0 — e.g. a higher-priority slot is winning.
    let addr = spawn_device_loop(move |invoke_id, service_choice| match service_choice {
        ConfirmedServiceChoice::WriteProperty => Apdu::SimpleAck {
            invoke_id,
            service_choice: ConfirmedServiceChoice::WriteProperty as u8,
        },
        ConfirmedServiceChoice::ReadProperty => {
            read_property_ack(invoke_id, object, PropertyValue::Real(2.0))
        }
        other => panic!("unexpected service {other:?}"),
    });

    let outcome = test_client()
        .write_property_verified(
            addr,
            object,
            PropertyIdentifier::PresentValue,
            &PropertyValue::Real(3.0),
            Some(8),
        )
        .expect("write+verify should not error");

    assert_eq!(
        outcome,
        WriteOutcome::NotEffective {
            read_back: PropertyValue::Real(2.0)
        }
    );
}
