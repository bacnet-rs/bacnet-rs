use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs, UdpSocket},
    sync::Arc,
};

use crate::{
    app::{Apdu, MaxApduSize, MaxSegments},
    datalink::bip::{BvlcFunction, BvlcHeader},
    network::Npdu,
    object::database::ObjectDatabase,
    service::{
        cov_notification::CovNotification, event_notification::EventNotification, AbortReason,
        ConfirmedServiceChoice, RejectReason, UnconfirmedServiceChoice,
    },
};

use super::{ObjectService, ServerDispatcher, ServerError, ServerResponse};

#[cfg(feature = "async")]
use tokio::task::JoinSet;

const MAX_BACNET_IP_FRAME: usize = 65_535;
#[cfg(feature = "async")]
const DEFAULT_MAX_CONCURRENT_REQUESTS: usize = 32;

/// A BACnet/IP endpoint serving one hosted [`ObjectDatabase`].
///
/// The endpoint owns one UDP socket. [`serve_once`](Self::serve_once) processes
/// exactly one datagram, which lets applications integrate it into their own
/// loop without creating a socket per object or remote device.
pub struct BacnetIpServer {
    socket: UdpSocket,
    dispatcher: ServerDispatcher,
    receive_buffer: Vec<u8>,
    observer: Option<RequestObserver>,
}

/// One request a server decoded, and whatever it answered with.
///
/// `response` is `None` for a request that needs no reply — an unconfirmed
/// service the device ignores, or a Who-Is outside its instance range.
pub struct ServedRequest<'a> {
    /// Where the datagram came from.
    pub source: Option<SocketAddr>,
    /// The decoded request.
    pub request: &'a Apdu,
    /// The reply this device produced, if any.
    pub response: Option<&'a Apdu>,
}

type RequestObserver = Box<dyn Fn(&ServedRequest<'_>) + Send + Sync>;

impl BacnetIpServer {
    pub fn bind<A: ToSocketAddrs>(
        address: A,
        database: Arc<ObjectDatabase>,
    ) -> Result<Self, ServerError> {
        let socket = UdpSocket::bind(address)?;
        Ok(Self::from_socket(socket, database))
    }

    pub fn from_socket(socket: UdpSocket, database: Arc<ObjectDatabase>) -> Self {
        Self {
            socket,
            dispatcher: ServerDispatcher::new(ObjectService::new(database)),
            receive_buffer: vec![0; MAX_BACNET_IP_FRAME],
            observer: None,
        }
    }

    /// Show every decoded request, and what it was answered with, to `observer`.
    ///
    /// For tracing what a remote client is actually asking for: which service,
    /// against which object, and whether the device liked it. The observer runs
    /// on the serve loop, so it should be cheap — writing a line, not doing I/O
    /// that can block.
    ///
    /// A datagram whose APDU will not decode is not observed: there is no
    /// request to describe, only bytes. The reject that goes back still does.
    pub fn observe_requests(
        &mut self,
        observer: impl Fn(&ServedRequest<'_>) + Send + Sync + 'static,
    ) {
        self.observer = Some(Box::new(observer));
    }

    pub fn local_addr(&self) -> Result<SocketAddr, ServerError> {
        Ok(self.socket.local_addr()?)
    }

    pub fn socket(&self) -> &UdpSocket {
        &self.socket
    }

    pub fn object_service(&self) -> &ObjectService {
        self.dispatcher.object_service()
    }

    pub fn dispatcher(&self) -> &ServerDispatcher {
        &self.dispatcher
    }

    /// A handle for originating event notifications from this device.
    pub fn notifier(&self) -> Result<Notifier, ServerError> {
        Ok(Notifier {
            socket: self.socket.try_clone()?,
            invoke_id: std::sync::atomic::AtomicU8::new(1),
        })
    }

    /// Receive and process one UDP datagram.
    ///
    /// Returns `true` when the datagram produced a BACnet response and `false`
    /// when it was ignored or did not require one.
    pub fn serve_once(&mut self) -> Result<bool, ServerError> {
        let (length, source) = self.socket.recv_from(&mut self.receive_buffer)?;

        let Some(response) = process_datagram(
            &self.dispatcher,
            &self.receive_buffer[..length],
            Some(source),
            self.observer.as_ref(),
        )?
        else {
            return Ok(false);
        };

        self.socket
            .send_to(&response.frame, response.destination.unwrap_or(source))?;
        Ok(true)
    }
}

/// An asynchronous BACnet/IP endpoint serving one hosted [`ObjectDatabase`].
///
/// One Tokio UDP socket receives and sends every packet. Requests are dispatched
/// concurrently through a bounded blocking task pool so synchronous hosted
/// object access does not block the async receive loop.
#[cfg(feature = "async")]
pub struct AsyncBacnetIpServer {
    socket: Arc<tokio::net::UdpSocket>,
    dispatcher: ServerDispatcher,
    max_concurrent_requests: usize,
}

#[cfg(feature = "async")]
impl AsyncBacnetIpServer {
    /// Bind an async server with a default limit of 32 in-flight requests.
    pub async fn bind<A: tokio::net::ToSocketAddrs>(
        address: A,
        database: Arc<ObjectDatabase>,
    ) -> Result<Self, ServerError> {
        let socket = tokio::net::UdpSocket::bind(address).await?;
        Ok(Self::from_socket(socket, database))
    }

    /// Build an async server around an existing Tokio UDP socket.
    pub fn from_socket(socket: tokio::net::UdpSocket, database: Arc<ObjectDatabase>) -> Self {
        Self {
            socket: Arc::new(socket),
            dispatcher: ServerDispatcher::new(ObjectService::new(database)),
            max_concurrent_requests: DEFAULT_MAX_CONCURRENT_REQUESTS,
        }
    }

    /// Set the maximum number of requests dispatched at the same time.
    pub fn with_max_concurrent_requests(mut self, limit: usize) -> Result<Self, ServerError> {
        if limit == 0 {
            return Err(ServerError::InvalidConfiguration(
                "max_concurrent_requests must be greater than zero".to_string(),
            ));
        }
        self.max_concurrent_requests = limit;
        Ok(self)
    }

    pub fn max_concurrent_requests(&self) -> usize {
        self.max_concurrent_requests
    }

    pub fn local_addr(&self) -> Result<SocketAddr, ServerError> {
        Ok(self.socket.local_addr()?)
    }

    pub fn object_service(&self) -> &ObjectService {
        self.dispatcher.object_service()
    }

    pub fn dispatcher(&self) -> &ServerDispatcher {
        &self.dispatcher
    }

    /// Receive and serve requests until the task is cancelled or the socket
    /// reports an I/O error.
    ///
    /// Malformed requests and individual response-send failures are logged and
    /// do not stop the receive loop. The server is consumed so only one task can
    /// receive from its socket.
    pub async fn run(self) -> Result<(), ServerError> {
        self.run_until(std::future::pending()).await
    }

    /// Receive and serve requests until `shutdown` completes.
    ///
    /// Once shutdown begins, no new datagrams are received and all accepted
    /// requests are allowed to finish before this method returns.
    pub async fn run_until<F>(self, shutdown: F) -> Result<(), ServerError>
    where
        F: std::future::Future<Output = ()>,
    {
        let mut requests = JoinSet::new();
        let mut receive_buffer = vec![0; MAX_BACNET_IP_FRAME];
        tokio::pin!(shutdown);

        let outcome = loop {
            if requests.len() >= self.max_concurrent_requests {
                tokio::select! {
                    _ = &mut shutdown => break Ok(()),
                    completed = requests.join_next() => log_request_completion(completed),
                }
                continue;
            }

            tokio::select! {
                _ = &mut shutdown => break Ok(()),
                completed = requests.join_next(), if !requests.is_empty() => {
                    log_request_completion(completed);
                }
                received = self.socket.recv_from(&mut receive_buffer) => {
                    let (length, source) = match received {
                        Ok(received) => received,
                        Err(error) => break Err(ServerError::Io(error)),
                    };
                    let packet = receive_buffer[..length].to_vec();
                    requests.spawn(serve_async_request(
                        Arc::clone(&self.socket),
                        self.dispatcher.clone(),
                        source,
                        packet,
                    ));
                }
            }
        };

        while let Some(completed) = requests.join_next().await {
            log_request_completion(Some(completed));
        }
        outcome
    }
}

#[cfg(feature = "async")]
async fn serve_async_request(
    socket: Arc<tokio::net::UdpSocket>,
    dispatcher: ServerDispatcher,
    source: SocketAddr,
    buffer: Vec<u8>,
) -> Result<(), ServerError> {
    let response = tokio::task::spawn_blocking(move || {
        process_datagram(&dispatcher, &buffer, Some(source), None)
    })
    .await
    .map_err(|error| ServerError::AsyncTask(error.to_string()))??;
    if let Some(response) = response {
        socket
            .send_to(&response.frame, response.destination.unwrap_or(source))
            .await?;
    }
    Ok(())
}

#[cfg(feature = "async")]
fn log_request_completion(
    completed: Option<Result<Result<(), ServerError>, tokio::task::JoinError>>,
) {
    match completed {
        Some(Ok(Ok(()))) | None => {}
        Some(Ok(Err(error))) => {
            log::warn!("failed to serve hosted BACnet request: {error}");
        }
        Some(Err(error)) => {
            log::error!("hosted BACnet request task failed: {error}");
        }
    }
}

fn process_datagram(
    dispatcher: &ServerDispatcher,
    data: &[u8],
    source: Option<SocketAddr>,
    observer: Option<&RequestObserver>,
) -> Result<Option<DatagramResponse>, ServerError> {
    let Some((request_npdu, apdu_data, destination)) = decode_bacnet_ip_frame(data) else {
        return Ok(None);
    };
    if request_npdu.is_network_message() {
        return Ok(None);
    }
    let response = match Apdu::decode(apdu_data) {
        Ok(request_apdu) => {
            // Dispatching consumes the request, so an observer needs its own
            // copy. Only made when one is installed: this is a debugging path,
            // and a device serving a gateway should not pay for it otherwise.
            let observed = observer.map(|_| request_apdu.clone());
            let response = dispatcher.dispatch(&request_npdu, request_apdu, source)?;

            if let (Some(observer), Some(request)) = (observer, &observed) {
                observer(&ServedRequest {
                    source,
                    request,
                    response: response.as_ref().map(|response| &response.apdu),
                });
            }
            response
        }
        Err(_) => response_for_undecodable_apdu(&request_npdu, apdu_data),
    };
    let Some(response) = response else {
        return Ok(None);
    };

    let npdu = response.npdu.encode();
    let apdu = response.apdu.encode();
    Ok(Some(DatagramResponse {
        frame: wrap_bvlc_parts(BvlcFunction::OriginalUnicastNpdu, &[&npdu, &apdu]),
        destination,
    }))
}

struct DatagramResponse {
    frame: Vec<u8>,
    destination: Option<SocketAddr>,
}

fn response_for_undecodable_apdu(request_npdu: &Npdu, data: &[u8]) -> Option<ServerResponse> {
    if data.first().map(|byte| byte >> 4) != Some(0) || data.len() < 3 {
        return None;
    }

    let invoke_id = data[2];
    let apdu = if data[0] & 0x08 != 0 {
        Apdu::Abort {
            server: true,
            invoke_id,
            abort_reason: AbortReason::SegmentationNotSupported,
        }
    } else {
        let reason = match data.get(3) {
            Some(service) if ConfirmedServiceChoice::try_from(*service).is_err() => {
                RejectReason::UnrecognizedService
            }
            _ => RejectReason::InvalidTag,
        };
        Apdu::Reject {
            invoke_id,
            reject_reason: reason,
        }
    };

    let mut npdu = Npdu::new();
    if let Some(source) = request_npdu.source.clone() {
        npdu.set_destination(source);
        npdu.hop_count = Some(255);
    }
    Some(ServerResponse { npdu, apdu })
}

fn decode_bacnet_ip_frame(data: &[u8]) -> Option<(Npdu, &[u8], Option<SocketAddr>)> {
    let header = BvlcHeader::decode(data).ok()?;
    if usize::from(header.length) != data.len() {
        return None;
    }

    let (npdu_start, destination) = match header.function {
        BvlcFunction::OriginalUnicastNpdu | BvlcFunction::OriginalBroadcastNpdu => (4, None),
        BvlcFunction::ForwardedNpdu if data.len() > 10 => {
            let address = Ipv4Addr::new(data[4], data[5], data[6], data[7]);
            let port = u16::from_be_bytes([data[8], data[9]]);
            (10, Some(SocketAddr::V4(SocketAddrV4::new(address, port))))
        }
        _ => return None,
    };

    let (npdu, npdu_length) = Npdu::decode(&data[npdu_start..]).ok()?;
    Some((npdu, &data[npdu_start + npdu_length..], destination))
}

/// Sends device-originated messages that are not replies to a request.
///
/// The server loop is strictly request/response, but a device performing
/// intrinsic reporting has to originate event notifications. A `Notifier` holds
/// its own handle on the server's socket so it can transmit while the loop is
/// blocked in `recv_from`.
pub struct Notifier {
    socket: UdpSocket,
    invoke_id: std::sync::atomic::AtomicU8,
}

impl Notifier {
    /// Send an event notification to `destination`.
    ///
    /// `confirmed` follows the recipient's `issue_confirmed_notifications` flag: a
    /// recipient that asked for confirmed delivery may ignore unconfirmed traffic
    /// entirely, so the choice has to come from its Recipient_List entry rather
    /// than from a device-wide default.
    ///
    /// The SimpleAck a confirmed notification earns is not awaited. The server
    /// loop owns the receive side of this socket, so consuming the reply here
    /// would race it; unacknowledged notifications are not retried yet.
    pub fn send_event_notification(
        &self,
        destination: SocketAddr,
        notification: &EventNotification,
        confirmed: bool,
    ) -> Result<(), ServerError> {
        let mut service_data = Vec::new();
        notification
            .encode(&mut service_data)
            .map_err(ServerError::from)?;

        let apdu = if confirmed {
            Apdu::ConfirmedRequest {
                segmented: false,
                more_follows: false,
                segmented_response_accepted: false,
                max_segments: MaxSegments::Unspecified,
                max_response_size: MaxApduSize::Up1476,
                invoke_id: self.next_invoke_id(),
                sequence_number: None,
                proposed_window_size: None,
                service_choice: ConfirmedServiceChoice::ConfirmedEventNotification,
                service_data,
            }
        } else {
            Apdu::UnconfirmedRequest {
                service_choice: UnconfirmedServiceChoice::UnconfirmedEventNotification,
                service_data,
            }
        };

        let npdu = if confirmed {
            // A confirmed request asks the recipient to reply.
            let mut npdu = Npdu::new();
            npdu.control.expecting_reply = true;
            npdu.encode()
        } else {
            Npdu::new().encode()
        };

        let frame = wrap_bvlc_parts(BvlcFunction::OriginalUnicastNpdu, &[&npdu, &apdu.encode()]);
        self.socket.send_to(&frame, destination)?;
        Ok(())
    }

    /// Send a COV notification to `destination`.
    ///
    /// Same confirmed/unconfirmed reasoning as an event notification: the
    /// subscriber said which it wanted when it subscribed.
    pub fn send_cov_notification(
        &self,
        destination: SocketAddr,
        notification: &CovNotification,
        confirmed: bool,
    ) -> Result<(), ServerError> {
        let mut service_data = Vec::new();
        notification
            .encode(&mut service_data)
            .map_err(ServerError::from)?;

        let apdu = if confirmed {
            Apdu::ConfirmedRequest {
                segmented: false,
                more_follows: false,
                segmented_response_accepted: false,
                max_segments: MaxSegments::Unspecified,
                max_response_size: MaxApduSize::Up1476,
                invoke_id: self.next_invoke_id(),
                sequence_number: None,
                proposed_window_size: None,
                service_choice: ConfirmedServiceChoice::ConfirmedCovNotification,
                service_data,
            }
        } else {
            Apdu::UnconfirmedRequest {
                service_choice: UnconfirmedServiceChoice::UnconfirmedCOVNotification,
                service_data,
            }
        };

        let npdu = if confirmed {
            let mut npdu = Npdu::new();
            npdu.control.expecting_reply = true;
            npdu.encode()
        } else {
            Npdu::new().encode()
        };

        let frame = wrap_bvlc_parts(BvlcFunction::OriginalUnicastNpdu, &[&npdu, &apdu.encode()]);
        self.socket.send_to(&frame, destination)?;
        Ok(())
    }

    /// Invoke ids cycle 0-255; confirmed notifications are not tracked, so this
    /// only needs to avoid reusing an id for two requests in flight at once.
    fn next_invoke_id(&self) -> u8 {
        self.invoke_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }
}

#[cfg(test)]
fn wrap_bvlc(function: BvlcFunction, payload: &[u8]) -> Vec<u8> {
    wrap_bvlc_parts(function, &[payload])
}

fn wrap_bvlc_parts(function: BvlcFunction, payload_parts: &[&[u8]]) -> Vec<u8> {
    let payload_length: usize = payload_parts.iter().map(|part| part.len()).sum();
    let length = 4 + payload_length;
    let mut frame = Vec::with_capacity(length);
    frame.extend_from_slice(&BvlcHeader::new(function, length as u16).encode());
    for part in payload_parts {
        frame.extend_from_slice(part);
    }
    frame
}

#[cfg(test)]
mod tests {
    use std::{thread, time::Duration};

    use crate::{
        client::{BacnetClient, PropertyReadOutcome},
        object::{
            AnalogValue, Device, ObjectIdentifier, ObjectType, PropertyIdentifier, PropertyValue,
        },
        service::{AbortReason, ConfirmedServiceChoice},
    };

    use super::*;

    #[test]
    fn hosted_analog_value_can_be_discovered_read_and_written() {
        let mut device = Device::new(1234, "Test device".to_string());
        device.vendor_identifier = 1;
        let database = Arc::new(ObjectDatabase::new(device));

        let mut analog_value = AnalogValue::new(1, "Setpoint".to_string());
        analog_value.present_value = 21.5;
        database.add_object(Box::new(analog_value)).unwrap();

        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let address = socket.local_addr().unwrap();
        let mut server = BacnetIpServer::from_socket(socket, Arc::clone(&database));

        let server_thread = thread::spawn(move || {
            for _ in 0..7 {
                assert!(server.serve_once().unwrap());
            }
        });

        let client = BacnetClient::builder()
            .local_addr("127.0.0.1")
            .port(0)
            .timeout(Duration::from_millis(500))
            .build()
            .unwrap();
        let discovered = client.discover_device(address).unwrap();
        assert_eq!(discovered.device_id, 1234);

        let object = ObjectIdentifier::new(ObjectType::AnalogValue, 1);
        let device_object = ObjectIdentifier::new(ObjectType::Device, discovered.device_id);
        let object_list = client
            .read_property(address, device_object, PropertyIdentifier::ObjectList)
            .unwrap();
        assert!(object_list.contains(&PropertyValue::ObjectIdentifier(object)));

        let property_list = client
            .read_property(address, device_object, PropertyIdentifier::PropertyList)
            .unwrap();
        assert!(property_list.contains(&PropertyValue::Enumerated(
            PropertyIdentifier::ObjectList.into()
        )));
        for excluded in [
            PropertyIdentifier::ObjectIdentifier,
            PropertyIdentifier::ObjectName,
            PropertyIdentifier::ObjectType,
            PropertyIdentifier::PropertyList,
        ] {
            assert!(!property_list.contains(&PropertyValue::Enumerated(excluded.into())));
        }

        assert_eq!(
            client
                .read_property(address, object, PropertyIdentifier::PresentValue)
                .unwrap(),
            vec![PropertyValue::Real(21.5)]
        );

        let snapshot = client.read_object_properties(address, object).unwrap();
        assert!(snapshot.properties.iter().any(|property| {
            property.property_identifier == PropertyIdentifier::ObjectName
                && property.outcome
                    == PropertyReadOutcome::Value(vec![PropertyValue::CharacterString(
                        "Setpoint".into(),
                    )])
        }));
        assert!(snapshot.properties.iter().any(|property| {
            property.property_identifier == PropertyIdentifier::PresentValue
                && property.outcome == PropertyReadOutcome::Value(vec![PropertyValue::Real(21.5)])
        }));

        client
            .write_property(
                address,
                object,
                PropertyIdentifier::PresentValue,
                &PropertyValue::Real(24.0),
                Some(8),
            )
            .unwrap();
        assert_eq!(
            client
                .read_property(address, object, PropertyIdentifier::PresentValue)
                .unwrap(),
            vec![PropertyValue::Real(24.0)]
        );

        server_thread.join().unwrap();
        assert_eq!(
            database
                .get_property(object, PropertyIdentifier::PresentValue)
                .unwrap(),
            PropertyValue::Real(24.0)
        );
        let PropertyValue::Array(priority_array) = database
            .get_property(object, PropertyIdentifier::PriorityArray)
            .unwrap()
        else {
            panic!("priority array did not return an array")
        };
        assert_eq!(priority_array[7], PropertyValue::Real(24.0));
    }

    /// What a device operator needs to see when a client is behaving oddly: the
    /// service that arrived and what went back — here a service the device does
    /// not execute, which is answered with a reject rather than silence.
    #[test]
    fn an_observer_is_shown_the_request_and_the_answer() {
        let database = Arc::new(ObjectDatabase::new(Device::new(
            1234,
            "Test device".to_string(),
        )));
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server = BacnetIpServer::from_socket(socket, database);

        let request = Apdu::ConfirmedRequest {
            segmented: false,
            more_follows: false,
            segmented_response_accepted: false,
            max_segments: crate::app::MaxSegments::Unspecified,
            max_response_size: crate::app::MaxApduSize::Up1476,
            invoke_id: 7,
            sequence_number: None,
            proposed_window_size: None,
            service_choice: ConfirmedServiceChoice::AtomicReadFile,
            service_data: Vec::new(),
        };
        let mut payload = Npdu::new().encode();
        payload.extend_from_slice(&request.encode());
        let frame = wrap_bvlc(BvlcFunction::OriginalUnicastNpdu, &payload);

        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorder = Arc::clone(&seen);
        let observer: RequestObserver = Box::new(move |served: &ServedRequest<'_>| {
            let service = match served.request {
                Apdu::ConfirmedRequest { service_choice, .. } => format!("{service_choice:?}"),
                other => format!("{other:?}"),
            };
            let answer = match served.response {
                Some(Apdu::Reject { reject_reason, .. }) => format!("Reject {reject_reason}"),
                Some(other) => format!("{other:?}"),
                None => "nothing".to_string(),
            };
            recorder
                .lock()
                .unwrap()
                .push(format!("{service}: {answer}"));
        });

        process_datagram(server.dispatcher(), &frame, None, Some(&observer)).unwrap();

        assert_eq!(
            seen.lock().unwrap().as_slice(),
            ["AtomicReadFile: Reject UnrecognizedService"]
        );
    }

    /// A Who-Is for another device is answered with nothing, and the observer is
    /// told that rather than left to infer it from a missing line.
    #[test]
    fn an_observer_sees_a_request_that_needed_no_answer() {
        let database = Arc::new(ObjectDatabase::new(Device::new(
            1234,
            "Test device".to_string(),
        )));
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server = BacnetIpServer::from_socket(socket, database);

        let mut service_data = Vec::new();
        crate::service::WhoIsRequest::for_range(4321, 4321)
            .encode(&mut service_data)
            .unwrap();
        let request = Apdu::UnconfirmedRequest {
            service_choice: UnconfirmedServiceChoice::WhoIs,
            service_data,
        };
        let mut payload = Npdu::new().encode();
        payload.extend_from_slice(&request.encode());
        let frame = wrap_bvlc(BvlcFunction::OriginalUnicastNpdu, &payload);

        let answered = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let recorder = Arc::clone(&answered);
        let observer: RequestObserver = Box::new(move |served: &ServedRequest<'_>| {
            recorder.store(
                served.response.is_some(),
                std::sync::atomic::Ordering::Relaxed,
            );
        });

        process_datagram(server.dispatcher(), &frame, None, Some(&observer)).unwrap();

        assert!(!answered.load(std::sync::atomic::Ordering::Relaxed));
    }

    #[test]
    fn segmented_confirmed_request_is_aborted() {
        let database = Arc::new(ObjectDatabase::new(Device::new(
            1234,
            "Test device".to_string(),
        )));
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server = BacnetIpServer::from_socket(socket, database);

        let request = Apdu::ConfirmedRequest {
            segmented: true,
            more_follows: false,
            segmented_response_accepted: false,
            max_segments: crate::app::MaxSegments::Unspecified,
            max_response_size: crate::app::MaxApduSize::Up1476,
            invoke_id: 7,
            sequence_number: Some(0),
            proposed_window_size: Some(1),
            service_choice: ConfirmedServiceChoice::ReadProperty,
            service_data: Vec::new(),
        };
        let mut payload = Npdu::new().encode();
        payload.extend_from_slice(&request.encode());
        let frame = wrap_bvlc(BvlcFunction::OriginalUnicastNpdu, &payload);

        let response = process_datagram(server.dispatcher(), &frame, None, None)
            .unwrap()
            .unwrap();
        let (_, apdu_data, _) = decode_bacnet_ip_frame(&response.frame).unwrap();
        assert!(matches!(
            Apdu::decode(apdu_data).unwrap(),
            Apdu::Abort {
                server: true,
                invoke_id: 7,
                abort_reason,
            } if abort_reason == AbortReason::SegmentationNotSupported
        ));
    }

    #[test]
    fn network_messages_and_malformed_application_traffic_are_ignored() {
        let database = Arc::new(ObjectDatabase::new(Device::new(
            1234,
            "Test device".to_string(),
        )));
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server = BacnetIpServer::from_socket(socket, database);

        let network_message = wrap_bvlc(BvlcFunction::OriginalBroadcastNpdu, &[0x01, 0x80, 0x00]);
        assert!(
            process_datagram(server.dispatcher(), &network_message, None, None)
                .unwrap()
                .is_none()
        );

        let malformed_apdu = wrap_bvlc(BvlcFunction::OriginalUnicastNpdu, &[0x01, 0x00, 0x00]);
        assert!(
            process_datagram(server.dispatcher(), &malformed_apdu, None, None)
                .unwrap()
                .is_none()
        );

        let malformed_who_is = wrap_bvlc(
            BvlcFunction::OriginalBroadcastNpdu,
            &[0x01, 0x00, 0x10, 0x08, 0x09, 0x01, 0xFF],
        );
        assert!(
            process_datagram(server.dispatcher(), &malformed_who_is, None, None)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn unknown_confirmed_service_receives_unrecognized_service_reject() {
        let database = Arc::new(ObjectDatabase::new(Device::new(
            1234,
            "Test device".to_string(),
        )));
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server = BacnetIpServer::from_socket(socket, database);
        let frame = wrap_bvlc(
            BvlcFunction::OriginalUnicastNpdu,
            &[0x01, 0x00, 0x00, 0x05, 42, 18],
        );

        let response = process_datagram(server.dispatcher(), &frame, None, None)
            .unwrap()
            .unwrap();
        let (_, apdu_data, _) = decode_bacnet_ip_frame(&response.frame).unwrap();
        assert!(matches!(
            Apdu::decode(apdu_data).unwrap(),
            Apdu::Reject {
                invoke_id: 42,
                reject_reason: RejectReason::UnrecognizedService,
            }
        ));
    }

    #[test]
    fn forwarded_who_is_replies_to_the_originating_address() {
        let database = Arc::new(ObjectDatabase::new(Device::new(
            1234,
            "Test device".to_string(),
        )));
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server = BacnetIpServer::from_socket(socket, database);
        let origin = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 9), 47_809));
        let mut forwarded_payload = vec![127, 0, 0, 9];
        forwarded_payload.extend_from_slice(&47_809_u16.to_be_bytes());
        forwarded_payload.extend_from_slice(&[0x01, 0x00, 0x10, 0x08]);
        let frame = wrap_bvlc(BvlcFunction::ForwardedNpdu, &forwarded_payload);

        let response = process_datagram(server.dispatcher(), &frame, None, None)
            .unwrap()
            .unwrap();
        assert_eq!(response.destination, Some(origin));
        let (_, apdu_data, _) = decode_bacnet_ip_frame(&response.frame).unwrap();
        assert!(matches!(
            Apdu::decode(apdu_data).unwrap(),
            Apdu::UnconfirmedRequest {
                service_choice: crate::service::UnconfirmedServiceChoice::IAm,
                ..
            }
        ));
    }

    #[cfg(feature = "async")]
    mod asynchronous {
        use std::sync::atomic::{AtomicUsize, Ordering};

        use crate::{
            app::{MaxApduSize, MaxSegments},
            object::{BacnetObject, ObjectError},
            service::{ReadPropertyRequest, ReadPropertyResponse},
        };

        use super::*;

        struct SlowAnalogValue {
            identifier: ObjectIdentifier,
            name: String,
            present_value: f32,
            active_reads: Arc<AtomicUsize>,
            maximum_active_reads: Arc<AtomicUsize>,
        }

        impl BacnetObject for SlowAnalogValue {
            fn identifier(&self) -> ObjectIdentifier {
                self.identifier
            }

            fn get_property(
                &self,
                property: PropertyIdentifier,
            ) -> Result<PropertyValue, ObjectError> {
                match property {
                    PropertyIdentifier::ObjectName => {
                        Ok(PropertyValue::CharacterString(self.name.clone()))
                    }
                    PropertyIdentifier::PresentValue => {
                        let active = self.active_reads.fetch_add(1, Ordering::SeqCst) + 1;
                        self.maximum_active_reads
                            .fetch_max(active, Ordering::SeqCst);
                        thread::sleep(Duration::from_millis(100));
                        self.active_reads.fetch_sub(1, Ordering::SeqCst);
                        Ok(PropertyValue::Real(self.present_value))
                    }
                    _ => Err(ObjectError::UnknownProperty),
                }
            }

            fn set_property(
                &mut self,
                _property: PropertyIdentifier,
                _value: PropertyValue,
            ) -> Result<(), ObjectError> {
                Err(ObjectError::PropertyNotWritable)
            }

            fn is_property_writable(&self, _property: PropertyIdentifier) -> bool {
                false
            }

            fn property_list(&self) -> Vec<PropertyIdentifier> {
                vec![
                    PropertyIdentifier::ObjectName,
                    PropertyIdentifier::PresentValue,
                ]
            }
        }

        fn read_property_frame(object: ObjectIdentifier, invoke_id: u8) -> Vec<u8> {
            let request = ReadPropertyRequest::new(object, PropertyIdentifier::PresentValue);
            let mut service_data = Vec::new();
            request.encode(&mut service_data).unwrap();
            let apdu = Apdu::ConfirmedRequest {
                segmented: false,
                more_follows: false,
                segmented_response_accepted: false,
                max_segments: MaxSegments::Unspecified,
                max_response_size: MaxApduSize::Up1476,
                invoke_id,
                sequence_number: None,
                proposed_window_size: None,
                service_choice: ConfirmedServiceChoice::ReadProperty,
                service_data,
            };
            let mut payload = Npdu::new().encode();
            payload.extend_from_slice(&apdu.encode());
            wrap_bvlc(BvlcFunction::OriginalUnicastNpdu, &payload)
        }

        async fn exchange(
            socket: &tokio::net::UdpSocket,
            server: SocketAddr,
            frame: &[u8],
        ) -> (u8, Vec<PropertyValue>) {
            socket.send_to(frame, server).await.unwrap();
            receive_response(socket, server).await
        }

        async fn receive_response(
            socket: &tokio::net::UdpSocket,
            server: SocketAddr,
        ) -> (u8, Vec<PropertyValue>) {
            let mut response = vec![0; MAX_BACNET_IP_FRAME];
            let (length, source) =
                tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut response))
                    .await
                    .expect("server response timed out")
                    .unwrap();
            assert_eq!(source, server);

            let (_, apdu_data, _) = decode_bacnet_ip_frame(&response[..length]).unwrap();
            let Apdu::ComplexAck {
                invoke_id,
                service_choice: ConfirmedServiceChoice::ReadProperty,
                service_data,
                ..
            } = Apdu::decode(apdu_data).unwrap()
            else {
                panic!("expected ReadProperty complex acknowledgement")
            };
            let response = ReadPropertyResponse::decode(&service_data).unwrap();
            (invoke_id, response.property_values)
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn concurrent_clients_can_reuse_invoke_ids_without_crossed_responses() {
            let database = Arc::new(ObjectDatabase::new(Device::new(
                1234,
                "Test device".to_string(),
            )));
            let active_reads = Arc::new(AtomicUsize::new(0));
            let maximum_active_reads = Arc::new(AtomicUsize::new(0));
            for (instance, present_value) in [(1, 11.0), (2, 22.0), (3, 33.0)] {
                database
                    .add_object(Box::new(SlowAnalogValue {
                        identifier: ObjectIdentifier::new(ObjectType::AnalogValue, instance),
                        name: format!("Slow value {instance}"),
                        present_value,
                        active_reads: Arc::clone(&active_reads),
                        maximum_active_reads: Arc::clone(&maximum_active_reads),
                    }))
                    .unwrap();
            }

            let server_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let server = AsyncBacnetIpServer::from_socket(server_socket, database)
                .with_max_concurrent_requests(2)
                .unwrap();
            let server_address = server.local_addr().unwrap();
            let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();
            let server_task = tokio::spawn(async move {
                server
                    .run_until(async {
                        let _ = shutdown_receiver.await;
                    })
                    .await
            });

            let first_client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let second_client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let third_client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let first_frame =
                read_property_frame(ObjectIdentifier::new(ObjectType::AnalogValue, 1), 7);
            let second_frame =
                read_property_frame(ObjectIdentifier::new(ObjectType::AnalogValue, 2), 7);
            let third_frame =
                read_property_frame(ObjectIdentifier::new(ObjectType::AnalogValue, 3), 7);

            let (first, second, third) = tokio::join!(
                exchange(&first_client, server_address, &first_frame),
                exchange(&second_client, server_address, &second_frame),
                exchange(&third_client, server_address, &third_frame),
            );

            assert_eq!(first, (7, vec![PropertyValue::Real(11.0)]));
            assert_eq!(second, (7, vec![PropertyValue::Real(22.0)]));
            assert_eq!(third, (7, vec![PropertyValue::Real(33.0)]));
            assert_eq!(maximum_active_reads.load(Ordering::SeqCst), 2);

            shutdown_sender.send(()).unwrap();
            tokio::time::timeout(Duration::from_secs(2), server_task)
                .await
                .expect("server shutdown timed out")
                .unwrap()
                .unwrap();
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn graceful_shutdown_drains_an_accepted_request() {
            let database = Arc::new(ObjectDatabase::new(Device::new(
                1234,
                "Test device".to_string(),
            )));
            let active_reads = Arc::new(AtomicUsize::new(0));
            database
                .add_object(Box::new(SlowAnalogValue {
                    identifier: ObjectIdentifier::new(ObjectType::AnalogValue, 1),
                    name: "Slow value".to_string(),
                    present_value: 11.0,
                    active_reads: Arc::clone(&active_reads),
                    maximum_active_reads: Arc::new(AtomicUsize::new(0)),
                }))
                .unwrap();

            let server_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let server = AsyncBacnetIpServer::from_socket(server_socket, database);
            let server_address = server.local_addr().unwrap();
            let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();
            let server_task = tokio::spawn(async move {
                server
                    .run_until(async {
                        let _ = shutdown_receiver.await;
                    })
                    .await
            });

            let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let frame = read_property_frame(ObjectIdentifier::new(ObjectType::AnalogValue, 1), 9);
            client.send_to(&frame, server_address).await.unwrap();
            tokio::time::timeout(Duration::from_secs(2), async {
                while active_reads.load(Ordering::SeqCst) == 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("request was not accepted");

            shutdown_sender.send(()).unwrap();
            assert_eq!(
                receive_response(&client, server_address).await,
                (9, vec![PropertyValue::Real(11.0)])
            );
            tokio::time::timeout(Duration::from_secs(2), server_task)
                .await
                .expect("server shutdown timed out")
                .unwrap()
                .unwrap();
        }

        #[tokio::test]
        async fn concurrency_limit_must_be_nonzero() {
            let database = Arc::new(ObjectDatabase::new(Device::new(
                1234,
                "Test device".to_string(),
            )));
            let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let error = AsyncBacnetIpServer::from_socket(socket, database)
                .with_max_concurrent_requests(0)
                .err()
                .expect("zero concurrency limit should fail");
            assert!(matches!(error, ServerError::InvalidConfiguration(_)));
        }
    }
}
