use crate::{
    app::{Apdu, MaxApduSize},
    network::Npdu,
    object::ObjectError,
    service::{
        AbortReason, ConfirmedServiceChoice, ReadPropertyMultipleRequest, ReadPropertyRequest,
        RejectReason, UnconfirmedServiceChoice, WhoIsRequest, WritePropertyRequest,
    },
};

use super::{object_service::object_error_codes, ObjectService, ServerError};

/// A transport-independent response produced by [`ServerDispatcher`].
#[derive(Debug)]
pub struct ServerResponse {
    pub npdu: Npdu,
    pub apdu: Apdu,
}

/// Dispatches decoded BACnet requests against hosted objects.
///
/// Datalink adapters decode their framing and pass the NPDU and APDU here. The
/// dispatcher contains no socket handling, so the same service implementation
/// can be reused by BACnet/IP, test harnesses, and future datalinks.
#[derive(Clone)]
pub struct ServerDispatcher {
    objects: ObjectService,
}

impl ServerDispatcher {
    pub fn new(objects: ObjectService) -> Self {
        Self { objects }
    }

    pub fn object_service(&self) -> &ObjectService {
        &self.objects
    }

    pub fn dispatch(
        &self,
        request_npdu: &Npdu,
        request_apdu: Apdu,
    ) -> Result<Option<ServerResponse>, ServerError> {
        if request_npdu.is_network_message() {
            return Ok(None);
        }

        let response_apdu = match request_apdu {
            Apdu::UnconfirmedRequest {
                service_choice: UnconfirmedServiceChoice::WhoIs,
                service_data,
            } => {
                let request = if service_data.is_empty() {
                    WhoIsRequest::new()
                } else {
                    let Ok(request) = WhoIsRequest::decode(&service_data) else {
                        return Ok(None);
                    };
                    request
                };
                let device = self.objects.database().get_device_id();
                if !request.matches(device.instance) {
                    return Ok(None);
                }
                let iam = self.objects.i_am()?;

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
            } => abort(invoke_id, AbortReason::SegmentationNotSupported),
            Apdu::ConfirmedRequest {
                segmented: false,
                segmented_response_accepted,
                max_response_size,
                invoke_id,
                service_choice,
                service_data,
                ..
            } => {
                let response = self.dispatch_confirmed(invoke_id, service_choice, &service_data)?;
                enforce_max_apdu(
                    invoke_id,
                    response,
                    max_response_size,
                    segmented_response_accepted,
                )
            }
            _ => return Ok(None),
        };

        let mut response_npdu = Npdu::new();
        if let Some(source) = request_npdu.source.clone() {
            response_npdu.set_destination(source);
            response_npdu.hop_count = Some(255);
        }

        Ok(Some(ServerResponse {
            npdu: response_npdu,
            apdu: response_apdu,
        }))
    }

    fn dispatch_confirmed(
        &self,
        invoke_id: u8,
        service_choice: ConfirmedServiceChoice,
        service_data: &[u8],
    ) -> Result<Apdu, ServerError> {
        match service_choice {
            ConfirmedServiceChoice::ReadProperty => match ReadPropertyRequest::decode(service_data)
            {
                Ok(request) => match self.objects.read_property(&request) {
                    Ok(response) => {
                        let mut service_data = Vec::new();
                        response.encode(&mut service_data)?;
                        Ok(complex_ack(invoke_id, service_choice, service_data))
                    }
                    Err(error) => Ok(object_error_apdu(invoke_id, service_choice, error)),
                },
                Err(_) => Ok(reject(invoke_id, RejectReason::InvalidTag)),
            },
            ConfirmedServiceChoice::ReadPropertyMultiple => {
                match ReadPropertyMultipleRequest::decode(service_data) {
                    Ok(request) => {
                        let response = self.objects.read_property_multiple(&request);
                        let mut service_data = Vec::new();
                        response.encode(&mut service_data)?;
                        Ok(complex_ack(invoke_id, service_choice, service_data))
                    }
                    Err(_) => Ok(reject(invoke_id, RejectReason::InvalidTag)),
                }
            }
            ConfirmedServiceChoice::WriteProperty => {
                match WritePropertyRequest::decode(service_data) {
                    Ok(request) => match self.objects.write_property(&request) {
                        Ok(()) => Ok(Apdu::SimpleAck {
                            invoke_id,
                            service_choice: service_choice as u8,
                        }),
                        Err(error) => Ok(object_error_apdu(invoke_id, service_choice, error)),
                    },
                    Err(_) => Ok(reject(invoke_id, RejectReason::InvalidTag)),
                }
            }
            _ => Ok(reject(invoke_id, RejectReason::UnrecognizedService)),
        }
    }
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

fn reject(invoke_id: u8, reason: RejectReason) -> Apdu {
    Apdu::Reject {
        invoke_id,
        reject_reason: reason,
    }
}

fn abort(invoke_id: u8, reason: AbortReason) -> Apdu {
    Apdu::Abort {
        server: true,
        invoke_id,
        abort_reason: reason,
    }
}

fn enforce_max_apdu(
    invoke_id: u8,
    response: Apdu,
    max_response_size: MaxApduSize,
    segmented_response_accepted: bool,
) -> Apdu {
    if response.encoded_len() <= max_response_size.size() {
        return response;
    }

    let reason = if segmented_response_accepted {
        AbortReason::SegmentationNotSupported
    } else {
        AbortReason::ApduTooLong
    };
    abort(invoke_id, reason)
}

fn object_error_apdu(
    invoke_id: u8,
    service_choice: ConfirmedServiceChoice,
    error: ObjectError,
) -> Apdu {
    let (error_class, error_code) = object_error_codes(&error);
    Apdu::Error {
        invoke_id,
        service_choice,
        error_class,
        error_code,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::{
        app::{MaxApduSize, MaxSegments},
        network::NetworkAddress,
        object::{
            database::ObjectDatabase, AnalogValue, Device, ObjectIdentifier, ObjectType,
            PropertyIdentifier, PropertyValue,
        },
        service::{
            PropertyReference, PropertyResultValue, ReadAccessSpecification,
            ReadPropertyMultipleResponse,
        },
    };

    use super::*;

    fn dispatcher_with_analog_values(count: u32) -> ServerDispatcher {
        let database = Arc::new(ObjectDatabase::new(Device::new(
            1234,
            "Test device".to_string(),
        )));
        for instance in 1..=count {
            let mut value = AnalogValue::new(instance, format!("Value {instance}"));
            value.present_value = instance as f32;
            database.add_object(Box::new(value)).unwrap();
        }
        ServerDispatcher::new(ObjectService::new(database))
    }

    fn confirmed_request(
        service_choice: ConfirmedServiceChoice,
        service_data: Vec<u8>,
        max_response_size: MaxApduSize,
        segmented_response_accepted: bool,
    ) -> Apdu {
        Apdu::ConfirmedRequest {
            segmented: false,
            more_follows: false,
            segmented_response_accepted,
            max_segments: MaxSegments::Unspecified,
            max_response_size,
            invoke_id: 9,
            sequence_number: None,
            proposed_window_size: None,
            service_choice,
            service_data,
        }
    }

    #[test]
    fn read_property_multiple_returns_values_errors_and_routed_reply() {
        let dispatcher = dispatcher_with_analog_values(1);
        let object = ObjectIdentifier::new(ObjectType::AnalogValue, 1);
        let request = ReadPropertyMultipleRequest::new(vec![ReadAccessSpecification::new(
            object,
            vec![
                PropertyReference::new(PropertyIdentifier::PresentValue),
                PropertyReference::new(PropertyIdentifier::AckRequired),
            ],
        )]);
        let mut service_data = Vec::new();
        request.encode(&mut service_data).unwrap();

        let source = NetworkAddress::new(416, vec![1, 2, 3, 4, 0xBA, 0xC0]);
        let mut npdu = Npdu::new();
        npdu.set_source(source.clone());
        let response = dispatcher
            .dispatch(
                &npdu,
                confirmed_request(
                    ConfirmedServiceChoice::ReadPropertyMultiple,
                    service_data,
                    MaxApduSize::Up1476,
                    false,
                ),
            )
            .unwrap()
            .unwrap();

        assert_eq!(response.npdu.destination, Some(source));
        let Apdu::ComplexAck { service_data, .. } = response.apdu else {
            panic!("expected ReadPropertyMultiple complex acknowledgement")
        };
        let decoded = ReadPropertyMultipleResponse::decode(&service_data).unwrap();
        assert_eq!(
            decoded.read_access_results[0].results[0].value,
            PropertyResultValue::Value(vec![PropertyValue::Real(1.0)])
        );
        assert_eq!(
            decoded.read_access_results[0].results[1].value,
            PropertyResultValue::Error(2, 32)
        );
    }

    #[test]
    fn all_selector_expands_to_the_hosted_property_list() {
        let dispatcher = dispatcher_with_analog_values(1);
        let object = ObjectIdentifier::new(ObjectType::AnalogValue, 1);
        let request = ReadPropertyMultipleRequest::new(vec![ReadAccessSpecification::new(
            object,
            vec![PropertyReference::new(PropertyIdentifier::All)],
        )]);
        let mut service_data = Vec::new();
        request.encode(&mut service_data).unwrap();

        let response = dispatcher
            .dispatch(
                &Npdu::new(),
                confirmed_request(
                    ConfirmedServiceChoice::ReadPropertyMultiple,
                    service_data,
                    MaxApduSize::Up1476,
                    false,
                ),
            )
            .unwrap()
            .unwrap();
        let Apdu::ComplexAck { service_data, .. } = response.apdu else {
            panic!("expected ReadPropertyMultiple complex acknowledgement")
        };
        let decoded = ReadPropertyMultipleResponse::decode(&service_data).unwrap();
        let properties: Vec<_> = decoded.read_access_results[0]
            .results
            .iter()
            .map(|result| result.property_identifier)
            .collect();
        assert!(properties.contains(&PropertyIdentifier::PresentValue));
        assert!(properties.contains(&PropertyIdentifier::PriorityArray));
        assert!(properties.contains(&PropertyIdentifier::PropertyList));
    }

    #[test]
    fn oversized_response_uses_the_appropriate_abort_reason() {
        let dispatcher = dispatcher_with_analog_values(20);
        let device = ObjectIdentifier::new(ObjectType::Device, 1234);
        let request = ReadPropertyMultipleRequest::new(vec![ReadAccessSpecification::new(
            device,
            vec![PropertyReference::new(PropertyIdentifier::ObjectList)],
        )]);
        let mut service_data = Vec::new();
        request.encode(&mut service_data).unwrap();

        for (segmentation_accepted, expected_reason) in [
            (false, AbortReason::ApduTooLong),
            (true, AbortReason::SegmentationNotSupported),
        ] {
            let response = dispatcher
                .dispatch(
                    &Npdu::new(),
                    confirmed_request(
                        ConfirmedServiceChoice::ReadPropertyMultiple,
                        service_data.clone(),
                        MaxApduSize::Up50,
                        segmentation_accepted,
                    ),
                )
                .unwrap()
                .unwrap();
            assert!(matches!(
                response.apdu,
                Apdu::Abort {
                    server: true,
                    invoke_id: 9,
                    abort_reason,
                } if abort_reason == expected_reason
            ));
        }
    }
}
