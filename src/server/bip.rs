use std::{
    io,
    net::{SocketAddr, ToSocketAddrs, UdpSocket},
    sync::Arc,
};

use thiserror::Error;

use crate::{
    app::{Apdu, ApplicationError},
    encoding::EncodingError,
    network::{NetworkError, Npdu},
    object::{database::ObjectDatabase, ObjectError},
    service::{
        AbortReason, ConfirmedServiceChoice, ReadPropertyRequest, RejectReason,
        UnconfirmedServiceChoice, WhoIsRequest, WritePropertyRequest,
    },
};

use super::ObjectService;

const BVLC_ORIGINAL_UNICAST: u8 = 0x0A;
const BVLC_ORIGINAL_BROADCAST: u8 = 0x0B;
const MAX_BACNET_IP_FRAME: usize = 65_535;

/// Errors returned by a hosted BACnet/IP endpoint.
#[derive(Debug, Error)]
pub enum ServerError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("encoding error: {0}")]
    Encoding(#[from] EncodingError),

    #[error("application-layer error: {0}")]
    Application(#[from] ApplicationError),

    #[error("network-layer error: {0}")]
    Network(#[from] NetworkError),

    #[error("hosted object error: {0}")]
    Object(#[from] ObjectError),
}

/// A BACnet/IP endpoint serving one hosted [`ObjectDatabase`].
///
/// The endpoint owns one UDP socket. [`serve_once`](Self::serve_once) processes
/// exactly one datagram, which lets applications integrate it into their own
/// loop without creating a socket per object or remote device.
pub struct BacnetIpServer {
    socket: UdpSocket,
    objects: ObjectService,
}

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
            objects: ObjectService::new(database),
        }
    }

    pub fn local_addr(&self) -> Result<SocketAddr, ServerError> {
        Ok(self.socket.local_addr()?)
    }

    pub fn socket(&self) -> &UdpSocket {
        &self.socket
    }

    pub fn object_service(&self) -> &ObjectService {
        &self.objects
    }

    /// Receive and process one UDP datagram.
    ///
    /// Returns `true` when the datagram produced a BACnet response and `false`
    /// when it was valid traffic that did not require one.
    pub fn serve_once(&self) -> Result<bool, ServerError> {
        let mut buffer = vec![0; MAX_BACNET_IP_FRAME];
        let (length, source) = self.socket.recv_from(&mut buffer)?;

        let Some(response) = self.handle_datagram(&buffer[..length])? else {
            return Ok(false);
        };

        self.socket.send_to(&response, source)?;
        Ok(true)
    }

    fn handle_datagram(&self, data: &[u8]) -> Result<Option<Vec<u8>>, ServerError> {
        let Some((request_npdu, apdu_data)) = decode_bacnet_ip_frame(data)? else {
            return Ok(None);
        };
        if request_npdu.is_network_message() {
            return Ok(None);
        }

        let apdu = Apdu::decode(apdu_data)?;
        let response = match apdu {
            Apdu::UnconfirmedRequest {
                service_choice: UnconfirmedServiceChoice::WhoIs,
                service_data,
            } => {
                let request = if service_data.is_empty() {
                    WhoIsRequest::new()
                } else {
                    WhoIsRequest::decode(&service_data)?
                };
                let iam = self.objects.i_am()?;
                if !request.matches(iam.device_identifier.instance) {
                    return Ok(None);
                }

                let mut service_data = Vec::new();
                iam.encode(&mut service_data)?;
                Apdu::UnconfirmedRequest {
                    service_choice: UnconfirmedServiceChoice::IAm,
                    service_data,
                }
            }
            Apdu::ConfirmedRequest {
                segmented: true,
                invoke_id,
                ..
            } => Apdu::Abort {
                server: true,
                invoke_id,
                abort_reason: AbortReason::SegmentationNotSupported,
            },
            Apdu::ConfirmedRequest {
                segmented: false,
                invoke_id,
                service_choice: ConfirmedServiceChoice::ReadProperty,
                service_data,
                ..
            } => match ReadPropertyRequest::decode(&service_data) {
                Ok(request) => match self.objects.read_property(&request) {
                    Ok(response) => {
                        let mut service_data = Vec::new();
                        response.encode(&mut service_data)?;
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
                    Err(error) => {
                        object_error_apdu(invoke_id, ConfirmedServiceChoice::ReadProperty, error)
                    }
                },
                Err(_) => Apdu::Reject {
                    invoke_id,
                    reject_reason: RejectReason::InvalidTag,
                },
            },
            Apdu::ConfirmedRequest {
                segmented: false,
                invoke_id,
                service_choice: ConfirmedServiceChoice::WriteProperty,
                service_data,
                ..
            } => match WritePropertyRequest::decode(&service_data) {
                Ok(request) => match self.objects.write_property(&request) {
                    Ok(()) => Apdu::SimpleAck {
                        invoke_id,
                        service_choice: ConfirmedServiceChoice::WriteProperty as u8,
                    },
                    Err(error) => {
                        object_error_apdu(invoke_id, ConfirmedServiceChoice::WriteProperty, error)
                    }
                },
                Err(_) => Apdu::Reject {
                    invoke_id,
                    reject_reason: RejectReason::InvalidTag,
                },
            },
            Apdu::ConfirmedRequest {
                invoke_id,
                service_choice,
                ..
            } => Apdu::Reject {
                invoke_id,
                reject_reason: if matches!(
                    service_choice,
                    ConfirmedServiceChoice::ReadProperty | ConfirmedServiceChoice::WriteProperty
                ) {
                    RejectReason::InvalidParameterDataType
                } else {
                    RejectReason::UnrecognizedService
                },
            },
            _ => return Ok(None),
        };

        let mut response_npdu = Npdu::new();
        if let Some(source) = request_npdu.source {
            response_npdu.set_destination(source);
            response_npdu.hop_count = Some(255);
        }

        let mut payload = response_npdu.encode();
        payload.extend_from_slice(&response.encode());
        Ok(Some(wrap_bvlc(BVLC_ORIGINAL_UNICAST, &payload)))
    }
}

fn decode_bacnet_ip_frame(data: &[u8]) -> Result<Option<(Npdu, &[u8])>, ServerError> {
    if data.len() < 6 || data[0] != 0x81 {
        return Ok(None);
    }
    if !matches!(data[1], BVLC_ORIGINAL_UNICAST | BVLC_ORIGINAL_BROADCAST) {
        return Ok(None);
    }
    if usize::from(u16::from_be_bytes([data[2], data[3]])) != data.len() {
        return Ok(None);
    }

    let (npdu, npdu_length) = Npdu::decode(&data[4..])?;
    Ok(Some((npdu, &data[4 + npdu_length..])))
}

fn wrap_bvlc(function: u8, payload: &[u8]) -> Vec<u8> {
    let length = 4 + payload.len();
    let mut frame = Vec::with_capacity(length);
    frame.extend_from_slice(&[0x81, function, (length >> 8) as u8, (length & 0xff) as u8]);
    frame.extend_from_slice(payload);
    frame
}

fn object_error_apdu(
    invoke_id: u8,
    service_choice: ConfirmedServiceChoice,
    error: ObjectError,
) -> Apdu {
    let (error_class, error_code) = match error {
        ObjectError::NotFound | ObjectError::InstanceNotFound => (1, 31),
        ObjectError::PropertyNotFound | ObjectError::UnknownProperty => (2, 32),
        ObjectError::PropertyNotWritable | ObjectError::WriteAccessDenied => (2, 40),
        ObjectError::InvalidPropertyType => (2, 9),
        ObjectError::InvalidValue(_) => (2, 37),
        ObjectError::PropertyIsNotArray => (2, 50),
        ObjectError::InvalidArrayIndex => (2, 42),
        ObjectError::TypeNotSupported | ObjectError::InvalidConfiguration(_) => (1, 0),
    };
    Apdu::Error {
        invoke_id,
        service_choice,
        error_class,
        error_code,
    }
}

#[cfg(test)]
mod tests {
    use std::{thread, time::Duration};

    use crate::{
        client::BacnetClient,
        object::{
            AnalogValue, Device, ObjectIdentifier, ObjectType, PropertyIdentifier, PropertyValue,
        },
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
        let server = BacnetIpServer::from_socket(socket, Arc::clone(&database));

        let server_thread = thread::spawn(move || {
            for _ in 0..6 {
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
        assert!(property_list.contains(&PropertyValue::Enumerated(
            PropertyIdentifier::PropertyList.into()
        )));

        assert_eq!(
            client
                .read_property(address, object, PropertyIdentifier::PresentValue)
                .unwrap(),
            vec![PropertyValue::Real(21.5)]
        );

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
        let frame = wrap_bvlc(BVLC_ORIGINAL_UNICAST, &payload);

        let response = server.handle_datagram(&frame).unwrap().unwrap();
        let (_, apdu_data) = decode_bacnet_ip_frame(&response).unwrap().unwrap();
        assert!(matches!(
            Apdu::decode(apdu_data).unwrap(),
            Apdu::Abort {
                server: true,
                invoke_id: 7,
                abort_reason,
            } if abort_reason == AbortReason::SegmentationNotSupported
        ));
    }
}
