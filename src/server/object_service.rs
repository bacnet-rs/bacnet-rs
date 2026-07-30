use std::{net::SocketAddr, sync::Arc};

use crate::{
    object::{
        database::ObjectDatabase, ObjectError, ObjectIdentifier, ObjectType, PropertyIdentifier,
        PropertyValue, Segmentation,
    },
    property::{
        BacnetAddress, CovSubscriptionValue, ObjectPropertyReference, Recipient, RecipientProcess,
    },
    service::{
        ConfirmedServiceChoice, IAmRequest, PropertyReference, PropertyResult, ReadAccessResult,
        ReadPropertyMultipleRequest, ReadPropertyMultipleResponse, ReadPropertyRequest,
        ReadPropertyResponse, SubscribeCovPropertyRequest, SubscribeCovRequest,
        WritePropertyRequest,
    },
};

/// Executes BACnet object services against a hosted object database.
#[derive(Clone)]
pub struct ObjectService {
    database: Arc<ObjectDatabase>,
    addresses: super::AddressCache,
    subscriptions: crate::cov::CovSubscriptions,
}

/// Decode the value carried by a WriteProperty request.
///
/// Application tags alone cannot describe BACnet's constructed datatypes: a
/// `BACnetDestination` is a context-tagged sequence, and `Recipient_List` is a
/// list of them. The property identifier is what tells a device how to read
/// those, so they need decoding before the generic tag-driven path, which would
/// otherwise reject them as an invalid data type.
fn decode_written_value(
    property: PropertyIdentifier,
    encoded: &[u8],
) -> Result<PropertyValue, ObjectError> {
    if property == PropertyIdentifier::RecipientList {
        // An empty payload clears the list, which is how a recipient deregisters.
        return crate::property::complex::decode_destinations(encoded)
            .map(PropertyValue::List)
            .map_err(|_| ObjectError::InvalidPropertyType);
    }

    let (value, consumed) = crate::property::decode_property_value(encoded)
        .map_err(|_| ObjectError::InvalidPropertyType)?;
    if consumed != encoded.len() {
        return Err(ObjectError::InvalidPropertyType);
    }
    Ok(value)
}

impl ObjectService {
    pub fn new(database: Arc<ObjectDatabase>) -> Self {
        Self {
            database,
            addresses: super::AddressCache::new(),
            subscriptions: crate::cov::CovSubscriptions::new(),
        }
    }

    /// The device's COV subscription table.
    pub fn subscriptions(&self) -> &crate::cov::CovSubscriptions {
        &self.subscriptions
    }

    /// Register, renew or cancel a COV subscription.
    ///
    /// A request carrying neither a confirmation preference nor a lifetime is a
    /// cancellation. Cancelling something that was never subscribed still
    /// succeeds: the subscriber's intent - not being subscribed - is satisfied.
    pub fn subscribe_cov(
        &self,
        request: &SubscribeCovRequest,
        source: Option<SocketAddr>,
    ) -> Result<(), ObjectError> {
        let Some(address) = source else {
            // Without a source there is nowhere to send notifications.
            return Err(ObjectError::InvalidConfiguration(
                "COV subscription has no source address".to_string(),
            ));
        };

        // Refuse to watch an object that is not here, so a subscriber finds out
        // now rather than never hearing anything.
        if self
            .database
            .get_property(
                request.monitored_object_identifier,
                PropertyIdentifier::PresentValue,
            )
            .is_err()
        {
            return Err(ObjectError::NotFound);
        }

        let key = crate::cov::SubscriptionKey {
            process_identifier: request.subscriber_process_identifier,
            monitored_object: request.monitored_object_identifier,
            monitored_property: None,
            address,
        };

        if request.is_cancellation() {
            self.subscriptions.cancel(&key);
            return Ok(());
        }

        self.subscriptions.subscribe(crate::cov::Subscription {
            key,
            confirmed: request.issue_confirmed_notifications.unwrap_or(false),
            expires_at: self.subscriptions.expiry_for(request.lifetime),
            cov_increment: None,
        });
        Ok(())
    }

    /// Register, renew or cancel a subscription to one named property.
    ///
    /// Differs from [`Self::subscribe_cov`] in what it watches rather than in how
    /// it is maintained: the named property is part of the subscription's
    /// identity, so a subscriber may hold several against one object, and a
    /// cancellation removes only the property it names.
    pub fn subscribe_cov_property(
        &self,
        request: &SubscribeCovPropertyRequest,
        source: Option<SocketAddr>,
    ) -> Result<(), ObjectError> {
        let Some(address) = source else {
            return Err(ObjectError::InvalidConfiguration(
                "COV subscription has no source address".to_string(),
            ));
        };

        // Watching one element of an array would mean tracking the element
        // rather than the property, which the engine does not do. Saying so is
        // better than subscribing to the whole property and reporting changes
        // the subscriber did not ask about.
        if request.monitored_property.property_array_index.is_some() {
            return Err(ObjectError::OptionalFunctionalityNotSupported);
        }

        let property = request.monitored_property.property_identifier;
        // Reading it now is what distinguishes an unknown object from an unknown
        // property, so the subscriber is told which of the two it got wrong.
        self.database
            .get_property(request.monitored_object_identifier, property)?;

        let key = crate::cov::SubscriptionKey {
            process_identifier: request.subscriber_process_identifier,
            monitored_object: request.monitored_object_identifier,
            monitored_property: Some(property),
            address,
        };

        if request.is_cancellation() {
            self.subscriptions.cancel(&key);
            return Ok(());
        }

        self.subscriptions.subscribe(crate::cov::Subscription {
            key,
            confirmed: request.issue_confirmed_notifications.unwrap_or(false),
            expires_at: self.subscriptions.expiry_for(request.lifetime),
            cov_increment: request.cov_increment,
        });
        Ok(())
    }

    /// Device-to-address bindings this service has learned from requests.
    pub fn addresses(&self) -> &super::AddressCache {
        &self.addresses
    }

    pub fn database(&self) -> &Arc<ObjectDatabase> {
        &self.database
    }

    pub fn supports_confirmed_service(&self, service: ConfirmedServiceChoice) -> bool {
        let Some(bit) = services_supported_bit(service) else {
            return false;
        };
        let device = self.database.get_device_id();

        matches!(
            self.database
                .get_property(device, PropertyIdentifier::ProtocolServicesSupported),
            Ok(PropertyValue::BitString(bits))
                if bits.get(bit).copied().unwrap_or(false)
        )
    }

    pub fn read_property(
        &self,
        request: &ReadPropertyRequest,
    ) -> Result<ReadPropertyResponse, ObjectError> {
        let property_values = self.read_property_values(
            request.object_identifier,
            request.property_identifier,
            request.property_array_index,
        )?;
        let mut response = ReadPropertyResponse::new(
            request.object_identifier,
            request.property_identifier,
            property_values,
        );
        response.property_array_index = request.property_array_index;
        Ok(response)
    }

    pub fn read_property_multiple(
        &self,
        request: &ReadPropertyMultipleRequest,
    ) -> ReadPropertyMultipleResponse {
        let read_access_results = request
            .read_access_specifications
            .iter()
            .map(|specification| {
                let references = self.expand_property_references(
                    specification.object_identifier,
                    &specification.property_references,
                );
                let results = match references {
                    Ok(references) => references
                        .into_iter()
                        .map(|reference| {
                            match self.read_property_values(
                                specification.object_identifier,
                                reference.property_identifier,
                                reference.property_array_index,
                            ) {
                                Ok(values) => PropertyResult::value(
                                    reference.property_identifier,
                                    reference.property_array_index,
                                    values,
                                ),
                                Err(error) => {
                                    let (error_class, error_code) = object_error_codes(&error);
                                    PropertyResult::error(
                                        reference.property_identifier,
                                        reference.property_array_index,
                                        error_class,
                                        error_code,
                                    )
                                }
                            }
                        })
                        .collect(),
                    Err(error) => {
                        let (error_class, error_code) = object_error_codes(&error);
                        specification
                            .property_references
                            .iter()
                            .map(|reference| {
                                PropertyResult::error(
                                    reference.property_identifier,
                                    reference.property_array_index,
                                    error_class,
                                    error_code,
                                )
                            })
                            .collect()
                    }
                };

                ReadAccessResult::new(specification.object_identifier, results)
            })
            .collect();

        ReadPropertyMultipleResponse::new(read_access_results)
    }

    fn read_property_values(
        &self,
        object_identifier: ObjectIdentifier,
        property_identifier: PropertyIdentifier,
        property_array_index: Option<u32>,
    ) -> Result<Vec<PropertyValue>, ObjectError> {
        let is_device = object_identifier == self.database.get_device_id();
        let value = match property_identifier {
            PropertyIdentifier::ObjectList if is_device => PropertyValue::Array(
                self.database
                    .get_all_objects()
                    .into_iter()
                    .map(PropertyValue::ObjectIdentifier)
                    .collect(),
            ),
            PropertyIdentifier::ActiveCovSubscriptions if is_device => {
                PropertyValue::List(self.active_cov_subscriptions())
            }
            PropertyIdentifier::PropertyList => {
                let mut properties = self.properties_for(object_identifier)?;
                properties.retain(|property| {
                    !matches!(
                        property,
                        PropertyIdentifier::ObjectIdentifier
                            | PropertyIdentifier::ObjectName
                            | PropertyIdentifier::ObjectType
                            | PropertyIdentifier::PropertyList
                    )
                });
                PropertyValue::Array(
                    properties
                        .into_iter()
                        .map(|property| PropertyValue::Enumerated(property.into()))
                        .collect(),
                )
            }
            _ => self
                .database
                .get_property(object_identifier, property_identifier)?,
        };

        select_array_value(value, property_array_index)
    }

    /// The Device object's Active_COV_Subscriptions, built from the live table.
    ///
    /// The property belongs to the Device object, but the subscriptions belong to
    /// the service that maintains them, and `Device::get_property` has no way to
    /// reach them — so it is answered from the same seam Object_List already uses.
    ///
    /// A subscriber whose address is not a BACnet/IP one is left out rather than
    /// described with an address that would not reach it. Annex J is four octets
    /// and a port; an IPv6 peer has no MAC this field can carry.
    fn active_cov_subscriptions(&self) -> Vec<PropertyValue> {
        let now = self.subscriptions.now();
        let mut live = self.subscriptions.all();

        // The table is a HashMap, which hands them back in whatever order it
        // likes. A client reading the list twice should not see it shuffle.
        live.sort_by_key(|subscription| {
            (
                subscription.key.process_identifier,
                u32::from(subscription.key.monitored_object.object_type),
                subscription.key.monitored_object.instance,
                subscription
                    .key
                    .monitored_property
                    .map_or(0, |property| u32::from(property) + 1),
            )
        });

        live.into_iter()
            .filter_map(|subscription| {
                let mac = super::address_cache::mac_from_socket_address(subscription.key.address)?;
                Some(PropertyValue::CovSubscription(CovSubscriptionValue {
                    recipient: RecipientProcess {
                        recipient: Recipient::Address(BacnetAddress {
                            // Zero is the local network, which is where a
                            // subscriber that reached this socket directly is.
                            network: 0,
                            mac_address: mac,
                        }),
                        process_identifier: subscription.key.process_identifier,
                    },
                    monitored_property: ObjectPropertyReference {
                        object_identifier: subscription.key.monitored_object,
                        // A plain SubscribeCOV names no property — it asks for
                        // the standard set — but this field is not optional, and
                        // Present_Value is the member of that set a subscriber
                        // actually subscribed for.
                        property_identifier: subscription
                            .key
                            .monitored_property
                            .unwrap_or(PropertyIdentifier::PresentValue),
                        array_index: None,
                    },
                    issue_confirmed_notifications: subscription.confirmed,
                    time_remaining: subscription.time_remaining(now),
                    cov_increment: subscription.cov_increment,
                }))
            })
            .collect()
    }

    fn properties_for(
        &self,
        object_identifier: ObjectIdentifier,
    ) -> Result<Vec<PropertyIdentifier>, ObjectError> {
        let mut properties = self.database.property_list(object_identifier)?;
        if object_identifier == self.database.get_device_id()
            && !properties.contains(&PropertyIdentifier::ObjectList)
        {
            properties.push(PropertyIdentifier::ObjectList);
        }
        if object_identifier == self.database.get_device_id()
            && !properties.contains(&PropertyIdentifier::ActiveCovSubscriptions)
        {
            properties.push(PropertyIdentifier::ActiveCovSubscriptions);
        }
        if !properties.contains(&PropertyIdentifier::PropertyList) {
            properties.push(PropertyIdentifier::PropertyList);
        }
        Ok(properties)
    }

    fn expand_property_references(
        &self,
        object_identifier: ObjectIdentifier,
        references: &[PropertyReference],
    ) -> Result<Vec<PropertyReference>, ObjectError> {
        let mut expanded = Vec::new();
        for reference in references {
            if reference.property_identifier == PropertyIdentifier::All {
                let array_index = reference.property_array_index;
                expanded.extend(self.properties_for(object_identifier)?.into_iter().map(
                    |property| {
                        let mut reference = PropertyReference::new(property);
                        reference.property_array_index = array_index;
                        reference
                    },
                ));
            } else {
                expanded.push(reference.clone());
            }
        }
        Ok(expanded)
    }

    pub fn write_property(
        &self,
        request: &WritePropertyRequest,
        source: Option<SocketAddr>,
    ) -> Result<(), ObjectError> {
        if let Some(index) = request.property_array_index {
            match self.database.get_property(
                request.object_identifier,
                request.property_identifier.into(),
            )? {
                PropertyValue::Array(values) if index == 0 || (index as usize) <= values.len() => {
                    return Err(ObjectError::OptionalFunctionalityNotSupported)
                }
                PropertyValue::Array(_) => return Err(ObjectError::InvalidArrayIndex),
                _ => return Err(ObjectError::PropertyIsNotArray),
            }
        }

        let property: PropertyIdentifier = request.property_identifier.into();
        let value = decode_written_value(property, &request.property_value)?;

        // A recipient registering itself tells us where it is: bind the devices it
        // names to the address the request came from.
        if property == PropertyIdentifier::RecipientList {
            if let (Some(source), PropertyValue::List(entries)) = (source, &value) {
                for entry in entries {
                    if let PropertyValue::Destination(destination) = entry {
                        if let crate::property::Recipient::Device(device) = destination.recipient {
                            self.addresses.learn(device, source);
                        }
                    }
                }
            }
        }

        self.database.set_property_with_priority(
            request.object_identifier,
            property,
            value,
            request.priority,
        )
    }

    pub fn i_am(&self) -> Result<IAmRequest, ObjectError> {
        let device = self.database.get_device_id();
        if device.object_type != ObjectType::Device {
            return Err(ObjectError::InvalidConfiguration(
                "object database has no Device object".to_string(),
            ));
        }

        let max_apdu = unsigned_property(
            &self.database,
            device,
            PropertyIdentifier::MaxApduLengthAccepted,
        )?;
        let vendor =
            unsigned_property(&self.database, device, PropertyIdentifier::VendorIdentifier)?;
        let segmentation = match self
            .read_property_values(device, PropertyIdentifier::SegmentationSupported, None)?
            .into_iter()
            .next()
            .ok_or(ObjectError::InvalidPropertyType)?
        {
            PropertyValue::Enumerated(value) => Segmentation::try_from(value)?,
            _ => return Err(ObjectError::InvalidPropertyType),
        };

        Ok(IAmRequest::new(
            device,
            max_apdu
                .try_into()
                .map_err(|_| ObjectError::InvalidPropertyType)?,
            segmentation,
            vendor
                .try_into()
                .map_err(|_| ObjectError::InvalidPropertyType)?,
        ))
    }
}

/// Where a confirmed service sits in Protocol_Services_Supported, for the
/// services this server executes.
///
/// BACnetServicesSupported and BACnetConfirmedServiceChoice are different
/// enumerations that happen to agree up to requestKey (25) and diverge after it:
/// subscribeCOVProperty is service choice 28 but bit 38, while bit 28 is
/// unconfirmedCOVNotification. Indexing the bit string by service choice would
/// therefore consult an unrelated bit — reading `false` for a service that is
/// supported, or `true` for one that is not.
///
/// `None` means this server does not execute the service, whatever the device
/// object advertises.
fn services_supported_bit(service: ConfirmedServiceChoice) -> Option<usize> {
    match service {
        ConfirmedServiceChoice::SubscribeCOV => Some(5),
        ConfirmedServiceChoice::ReadProperty => Some(12),
        ConfirmedServiceChoice::ReadPropertyMultiple => Some(14),
        ConfirmedServiceChoice::WriteProperty => Some(15),
        ConfirmedServiceChoice::SubscribeCOVProperty => Some(38),
        _ => None,
    }
}

pub(crate) fn object_error_codes(error: &ObjectError) -> (u32, u32) {
    match error {
        ObjectError::NotFound | ObjectError::InstanceNotFound => (1, 31),
        ObjectError::PropertyNotFound | ObjectError::UnknownProperty => (2, 32),
        ObjectError::PropertyNotWritable | ObjectError::WriteAccessDenied => (2, 40),
        ObjectError::InvalidPropertyType => (2, 9),
        ObjectError::InvalidValue(_) => (2, 37),
        ObjectError::PropertyIsNotArray => (2, 50),
        ObjectError::InvalidArrayIndex => (2, 42),
        ObjectError::OptionalFunctionalityNotSupported => (2, 45),
        ObjectError::TypeNotSupported | ObjectError::InvalidConfiguration(_) => (1, 0),
    }
}

fn select_array_value(
    value: PropertyValue,
    array_index: Option<u32>,
) -> Result<Vec<PropertyValue>, ObjectError> {
    match (value, array_index) {
        (PropertyValue::Array(values), None) | (PropertyValue::List(values), None) => Ok(values),
        (PropertyValue::Array(values), Some(0)) => {
            Ok(vec![PropertyValue::Unsigned(values.len() as u64)])
        }
        (PropertyValue::Array(values), Some(index)) => values
            .into_iter()
            .nth(index.saturating_sub(1) as usize)
            .map(|value| vec![value])
            .ok_or(ObjectError::InvalidArrayIndex),
        (PropertyValue::List(_), Some(_)) => Err(ObjectError::PropertyIsNotArray),
        (value, None) => Ok(vec![value]),
        (_, Some(_)) => Err(ObjectError::PropertyIsNotArray),
    }
}

fn unsigned_property(
    database: &ObjectDatabase,
    object: ObjectIdentifier,
    property: PropertyIdentifier,
) -> Result<u64, ObjectError> {
    match database.get_property(object, property)? {
        PropertyValue::Unsigned(value) => Ok(value),
        _ => Err(ObjectError::InvalidPropertyType),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::{AnalogValue, BacnetObject, Device};

    fn service_with_analog_value() -> ObjectService {
        let database = Arc::new(ObjectDatabase::new(Device::new(
            1234,
            "Test device".to_string(),
        )));
        database
            .add_object(Box::new(AnalogValue::new(1, "Setpoint".to_string())))
            .unwrap();
        ObjectService::new(database)
    }

    fn read_device_property(
        service: &ObjectService,
        property: PropertyIdentifier,
    ) -> Vec<PropertyValue> {
        service
            .read_property(&ReadPropertyRequest::new(
                service.database().get_device_id(),
                property,
            ))
            .unwrap()
            .property_values
    }

    #[test]
    fn hosted_device_capabilities_follow_the_device_and_database() {
        let mut device = Device::new(1234, "Test device".to_string());
        device.protocol_services_supported =
            crate::object::ProtocolServicesSupported::READ_PROPERTY;
        device.segmentation_supported = Segmentation::Receive;
        let database = Arc::new(ObjectDatabase::new(device));
        database
            .add_object(Box::new(AnalogValue::new(1, "Setpoint".to_string())))
            .unwrap();
        let service = ObjectService::new(database);

        let services_value =
            read_device_property(&service, PropertyIdentifier::ProtocolServicesSupported);
        let [PropertyValue::BitString(services)] = services_value.as_slice() else {
            panic!("expected protocol services bit string")
        };
        assert_eq!(services.len(), 47);
        assert_eq!(
            services
                .iter()
                .enumerate()
                .filter_map(|(index, enabled)| enabled.then_some(index))
                .collect::<Vec<_>>(),
            vec![12]
        );

        let object_types_value =
            read_device_property(&service, PropertyIdentifier::ProtocolObjectTypesSupported);
        let [PropertyValue::BitString(object_types)] = object_types_value.as_slice() else {
            panic!("expected protocol object types bit string")
        };
        assert_eq!(object_types.len(), 63);
        assert!(object_types[u32::from(ObjectType::AnalogValue) as usize]);
        assert!(object_types[u32::from(ObjectType::Device) as usize]);

        assert_eq!(
            read_device_property(&service, PropertyIdentifier::SegmentationSupported),
            vec![PropertyValue::Enumerated(Segmentation::Receive as u32)]
        );
        assert_eq!(
            service.i_am().unwrap().segmentation_supported,
            Segmentation::Receive
        );
    }

    #[test]
    fn database_revision_is_maintained_by_the_hosted_database() {
        let service = service_with_analog_value();
        assert_eq!(
            read_device_property(&service, PropertyIdentifier::DatabaseRevision),
            vec![PropertyValue::Unsigned(2)]
        );

        let object = ObjectIdentifier::new(ObjectType::AnalogValue, 1);
        service
            .database()
            .set_property(
                object,
                PropertyIdentifier::PresentValue,
                PropertyValue::Real(22.0),
            )
            .unwrap();
        assert_eq!(
            read_device_property(&service, PropertyIdentifier::DatabaseRevision),
            vec![PropertyValue::Unsigned(2)]
        );

        service
            .database()
            .set_property(
                object,
                PropertyIdentifier::ObjectName,
                PropertyValue::CharacterString("Renamed setpoint".to_string()),
            )
            .unwrap();
        assert_eq!(
            read_device_property(&service, PropertyIdentifier::DatabaseRevision),
            vec![PropertyValue::Unsigned(3)]
        );
    }

    #[test]
    fn hosted_profile_exposes_required_device_and_analog_value_properties() {
        let service = service_with_analog_value();
        let device_properties = service
            .properties_for(service.database().get_device_id())
            .unwrap();
        for property in [
            PropertyIdentifier::ProtocolServicesSupported,
            PropertyIdentifier::ProtocolObjectTypesSupported,
            PropertyIdentifier::ObjectList,
            PropertyIdentifier::ApduTimeout,
            PropertyIdentifier::NumberOfApduRetries,
            PropertyIdentifier::DeviceAddressBinding,
            PropertyIdentifier::DatabaseRevision,
            PropertyIdentifier::PropertyList,
        ] {
            assert!(
                device_properties.contains(&property),
                "missing {property:?}"
            );
        }

        let analog_value = AnalogValue::new(1, "Setpoint".to_string());
        let analog_properties = analog_value.property_list();
        for property in [
            PropertyIdentifier::PresentValue,
            PropertyIdentifier::StatusFlags,
            PropertyIdentifier::EventState,
            PropertyIdentifier::OutOfService,
            PropertyIdentifier::Units,
            PropertyIdentifier::PriorityArray,
            PropertyIdentifier::RelinquishDefault,
        ] {
            assert!(
                analog_properties.contains(&property),
                "missing {property:?}"
            );
        }
    }

    #[test]
    fn indexed_writes_distinguish_arrays_from_scalar_properties() {
        let service = service_with_analog_value();
        let object = ObjectIdentifier::new(ObjectType::AnalogValue, 1);
        let mut request = WritePropertyRequest::new(
            object,
            PropertyIdentifier::PresentValue.into(),
            vec![0x44, 0x41, 0xA0, 0x00, 0x00],
        );
        request.property_array_index = Some(1);

        assert!(matches!(
            service.write_property(&request, None),
            Err(ObjectError::PropertyIsNotArray)
        ));

        request.property_identifier = PropertyIdentifier::PriorityArray.into();
        assert!(matches!(
            service.write_property(&request, None),
            Err(ObjectError::OptionalFunctionalityNotSupported)
        ));
        request.property_array_index = Some(17);
        assert!(matches!(
            service.write_property(&request, None),
            Err(ObjectError::InvalidArrayIndex)
        ));
        assert_eq!(
            object_error_codes(&ObjectError::OptionalFunctionalityNotSupported),
            (2, 45)
        );
    }
}

#[cfg(test)]
mod recipient_list_tests {
    use super::*;
    use crate::object::{Device, NotificationClass, ObjectType};
    use crate::property::{DestinationValue, Recipient};

    /// EEP registers the dingo gateway by writing Recipient_List, so a device has
    /// to accept a constructed BACnetDestination list. Decoding it generically
    /// fails, which the gateway surfaced as error-class property,
    /// error-code invalid-data-type.
    #[test]
    fn a_written_recipient_list_decodes_into_destinations() {
        let gateway = ObjectIdentifier::new(ObjectType::Device, 5785);
        let destination = DestinationValue {
            valid_days: vec![true; 7],
            from_time: (0, 0, 0, 0),
            to_time: (23, 59, 59, 99),
            recipient: Recipient::Device(gateway),
            process_identifier: 777,
            issue_confirmed_notifications: false,
            transitions: vec![true, true, true],
        };

        let mut encoded = Vec::new();
        destination.encode(&mut encoded).expect("encode");

        let value = decode_written_value(PropertyIdentifier::RecipientList, &encoded)
            .expect("recipient list should decode");

        match value {
            PropertyValue::List(entries) => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0], PropertyValue::Destination(destination));
            }
            other => panic!("unexpected value: {other:?}"),
        }
    }

    #[test]
    fn an_empty_recipient_list_clears_the_registration() {
        let value = decode_written_value(PropertyIdentifier::RecipientList, &[])
            .expect("empty list should decode");
        assert_eq!(value, PropertyValue::List(Vec::new()));
    }

    /// End to end through the service, the way a WriteProperty request arrives.
    #[test]
    fn writing_recipient_list_through_the_service_registers_a_recipient() {
        let database = Arc::new(ObjectDatabase::new(Device::new(
            1234,
            "Alarm device".to_string(),
        )));
        database
            .add_object(Box::new(NotificationClass::new(1, "NC".to_string())))
            .expect("add notification class");
        let service = ObjectService::new(Arc::clone(&database));

        let gateway = ObjectIdentifier::new(ObjectType::Device, 5785);
        let destination = DestinationValue {
            valid_days: vec![true; 7],
            from_time: (0, 0, 0, 0),
            to_time: (23, 59, 59, 99),
            recipient: Recipient::Device(gateway),
            process_identifier: 777,
            issue_confirmed_notifications: false,
            transitions: vec![true, true, true],
        };
        let mut encoded = Vec::new();
        destination.encode(&mut encoded).expect("encode");

        let request = WritePropertyRequest::new(
            ObjectIdentifier::new(ObjectType::NotificationClass, 1),
            PropertyIdentifier::RecipientList.into(),
            encoded,
        );
        service
            .write_property(&request, Some("192.168.6.1:47808".parse().unwrap()))
            .expect("write accepted");

        let stored = database
            .get_property(
                ObjectIdentifier::new(ObjectType::NotificationClass, 1),
                PropertyIdentifier::RecipientList,
            )
            .expect("read back");
        assert_eq!(
            stored,
            PropertyValue::List(vec![PropertyValue::Destination(destination)])
        );
    }
}

#[cfg(test)]
mod cov_subscription_tests {
    use super::*;
    use crate::object::{AnalogValue, Device};

    fn service() -> ObjectService {
        let database = Arc::new(ObjectDatabase::new(Device::new(1234, "Test".to_string())));
        database
            .add_object(Box::new(AnalogValue::new(1, "Zone".to_string())))
            .unwrap();
        ObjectService::new(database)
    }

    fn subscriber() -> SocketAddr {
        "192.168.6.1:47808".parse().unwrap()
    }

    fn request(lifetime: Option<u32>, confirmed: Option<bool>) -> SubscribeCovRequest {
        SubscribeCovRequest {
            subscriber_process_identifier: 777,
            monitored_object_identifier: ObjectIdentifier::new(ObjectType::AnalogValue, 1),
            issue_confirmed_notifications: confirmed,
            lifetime,
        }
    }

    #[test]
    fn subscribing_records_the_subscriber_and_its_preferences() {
        let service = service();
        service
            .subscribe_cov(&request(Some(3600), Some(true)), Some(subscriber()))
            .expect("subscribe");

        let held = service.subscriptions().all();
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].key.process_identifier, 777);
        assert_eq!(held[0].key.address, subscriber());
        assert!(held[0].confirmed);
        assert_eq!(
            held[0].expires_at,
            Some(3600),
            "lifetime against a zero clock"
        );
    }

    /// Both optional fields absent is BACnet's way of cancelling.
    #[test]
    fn a_request_without_lifetime_or_confirmation_cancels() {
        let service = service();
        service
            .subscribe_cov(&request(Some(3600), Some(false)), Some(subscriber()))
            .expect("subscribe");
        assert_eq!(service.subscriptions().len(), 1);

        service
            .subscribe_cov(&request(None, None), Some(subscriber()))
            .expect("cancel");
        assert!(service.subscriptions().is_empty());
    }

    #[test]
    fn cancelling_something_never_subscribed_still_succeeds() {
        let service = service();
        assert!(service
            .subscribe_cov(&request(None, None), Some(subscriber()))
            .is_ok());
    }

    #[test]
    fn a_zero_lifetime_means_until_cancelled() {
        let service = service();
        service
            .subscribe_cov(&request(Some(0), Some(false)), Some(subscriber()))
            .expect("subscribe");
        assert_eq!(service.subscriptions().all()[0].expires_at, None);
    }

    #[test]
    fn subscribing_to_a_missing_object_is_refused() {
        let service = service();
        let mut missing = request(Some(60), Some(false));
        missing.monitored_object_identifier = ObjectIdentifier::new(ObjectType::AnalogValue, 99);

        assert!(matches!(
            service.subscribe_cov(&missing, Some(subscriber())),
            Err(ObjectError::NotFound)
        ));
    }

    #[test]
    fn a_subscription_without_a_source_address_is_refused() {
        let service = service();
        assert!(service
            .subscribe_cov(&request(Some(60), Some(false)), None)
            .is_err());
    }

    #[test]
    fn the_service_advertises_subscribe_cov() {
        assert!(service().supports_confirmed_service(ConfirmedServiceChoice::SubscribeCOV));
    }

    /// Service choice 28 has to be looked up as BACnetServicesSupported bit 38.
    /// Indexed by service choice it lands on unconfirmedCOVNotification, which a
    /// hosted device leaves clear — so the subscribe would be rejected as
    /// unrecognized however loudly the device advertised the service.
    #[test]
    fn the_service_advertises_subscribe_cov_property() {
        assert!(service().supports_confirmed_service(ConfirmedServiceChoice::SubscribeCOVProperty));
    }

    /// The converse mistake: ReadRange is service choice 26, which is I-Am's bit
    /// in the services-supported string and always set on a hosted device.
    #[test]
    fn a_service_this_server_does_not_execute_is_not_advertised() {
        assert!(!service().supports_confirmed_service(ConfirmedServiceChoice::ReadRange));
    }

    fn property_request(
        property: PropertyIdentifier,
        lifetime: Option<u32>,
        confirmed: Option<bool>,
    ) -> SubscribeCovPropertyRequest {
        SubscribeCovPropertyRequest {
            subscriber_process_identifier: 777,
            monitored_object_identifier: ObjectIdentifier::new(ObjectType::AnalogValue, 1),
            issue_confirmed_notifications: confirmed,
            lifetime,
            monitored_property: crate::service::PropertyReference::new(property),
            cov_increment: None,
        }
    }

    #[test]
    fn subscribing_to_a_property_records_what_it_watches() {
        let service = service();
        let mut request =
            property_request(PropertyIdentifier::PresentValue, Some(3600), Some(true));
        request.cov_increment = Some(2.5);
        service
            .subscribe_cov_property(&request, Some(subscriber()))
            .expect("subscribe");

        let held = service.subscriptions().all();
        assert_eq!(held.len(), 1);
        assert_eq!(
            held[0].key.monitored_property,
            Some(PropertyIdentifier::PresentValue)
        );
        assert_eq!(held[0].cov_increment, Some(2.5));
        assert!(held[0].confirmed);
    }

    /// A property subscription and a plain one on the same object are different
    /// subscriptions: they watch different things and are cancelled separately.
    #[test]
    fn a_property_subscription_does_not_replace_the_plain_one() {
        let service = service();
        service
            .subscribe_cov(&request(Some(3600), Some(false)), Some(subscriber()))
            .expect("subscribe");
        service
            .subscribe_cov_property(
                &property_request(PropertyIdentifier::PresentValue, Some(3600), Some(false)),
                Some(subscriber()),
            )
            .expect("subscribe");

        assert_eq!(service.subscriptions().len(), 2);
    }

    #[test]
    fn cancelling_a_property_subscription_leaves_the_others() {
        let service = service();
        for property in [
            PropertyIdentifier::PresentValue,
            PropertyIdentifier::StatusFlags,
        ] {
            service
                .subscribe_cov_property(
                    &property_request(property, Some(3600), Some(false)),
                    Some(subscriber()),
                )
                .expect("subscribe");
        }
        assert_eq!(service.subscriptions().len(), 2);

        service
            .subscribe_cov_property(
                &property_request(PropertyIdentifier::PresentValue, None, None),
                Some(subscriber()),
            )
            .expect("cancel");

        let held = service.subscriptions().all();
        assert_eq!(held.len(), 1);
        assert_eq!(
            held[0].key.monitored_property,
            Some(PropertyIdentifier::StatusFlags),
            "the one that was not named survives"
        );
    }

    fn active_subscriptions(service: &ObjectService) -> Vec<CovSubscriptionValue> {
        let values = service
            .read_property(&ReadPropertyRequest::new(
                service.database().get_device_id(),
                PropertyIdentifier::ActiveCovSubscriptions,
            ))
            .expect("read Active_COV_Subscriptions")
            .property_values;

        // A list-valued property arrives as its entries: the response carries the
        // values of the property, and a list is several of them.
        values
            .iter()
            .map(|entry| match entry {
                PropertyValue::CovSubscription(subscription) => subscription.clone(),
                other => panic!("expected a subscription, got {other:?}"),
            })
            .collect()
    }

    /// What a workstation asks the device when it wants to know who is watching
    /// what -- including whether the subscription it thinks it holds is there.
    #[test]
    fn a_subscription_appears_in_active_cov_subscriptions() {
        let service = service();
        service.subscriptions().set_now(100);
        service
            .subscribe_cov(&request(Some(3600), Some(true)), Some(subscriber()))
            .expect("subscribe");

        let active = active_subscriptions(&service);

        assert_eq!(active.len(), 1);
        assert_eq!(active[0].recipient.process_identifier, 777);
        assert_eq!(
            active[0].recipient.recipient,
            Recipient::Address(BacnetAddress {
                network: 0,
                mac_address: vec![192, 168, 6, 1, 0xBA, 0xC0],
            }),
            "the address it subscribed from, as a BACnet/IP MAC"
        );
        assert!(active[0].issue_confirmed_notifications);
        assert_eq!(active[0].time_remaining, 3600);
        assert_eq!(
            active[0].monitored_property.object_identifier,
            ObjectIdentifier::new(ObjectType::AnalogValue, 1)
        );
        assert_eq!(
            active[0].monitored_property.property_identifier,
            PropertyIdentifier::PresentValue,
            "a plain SubscribeCOV names no property, but the field is not optional"
        );
    }

    /// The lifetime the subscriber has left, not the one it asked for.
    #[test]
    fn time_remaining_counts_down_with_the_engine_clock() {
        let service = service();
        service.subscriptions().set_now(100);
        service
            .subscribe_cov(&request(Some(600), Some(false)), Some(subscriber()))
            .expect("subscribe");

        service.subscriptions().set_now(400);
        assert_eq!(active_subscriptions(&service)[0].time_remaining, 300);

        service.subscriptions().set_now(700);
        assert_eq!(
            active_subscriptions(&service)[0].time_remaining,
            0,
            "past its expiry it has none left, until the engine sweeps it"
        );
    }

    /// A subscription with no lifetime lasts until it is cancelled, which the
    /// standard reports as zero remaining rather than as an absent field.
    #[test]
    fn a_subscription_that_never_expires_reports_no_time_remaining() {
        let service = service();
        service
            .subscribe_cov(&request(Some(0), Some(false)), Some(subscriber()))
            .expect("subscribe");

        assert_eq!(active_subscriptions(&service)[0].time_remaining, 0);
    }

    #[test]
    fn a_property_subscription_reports_the_property_and_its_increment() {
        let service = service();
        let mut request = property_request(PropertyIdentifier::StatusFlags, Some(60), Some(false));
        request.cov_increment = Some(2.5);
        service
            .subscribe_cov_property(&request, Some(subscriber()))
            .expect("subscribe");

        let active = active_subscriptions(&service);

        assert_eq!(
            active[0].monitored_property.property_identifier,
            PropertyIdentifier::StatusFlags
        );
        assert_eq!(active[0].cov_increment, Some(2.5));
    }

    #[test]
    fn a_cancelled_subscription_leaves_the_list() {
        let service = service();
        service
            .subscribe_cov(&request(Some(3600), Some(false)), Some(subscriber()))
            .expect("subscribe");
        service
            .subscribe_cov(&request(None, None), Some(subscriber()))
            .expect("cancel");

        assert!(
            active_subscriptions(&service).is_empty(),
            "a device with no subscribers reports an empty list, not an error"
        );
    }

    /// A HashMap iterates in whatever order it likes. A workstation polling the
    /// property would see the rows shuffle, and a diff of two reads would be
    /// noise.
    #[test]
    fn the_list_is_ordered_the_same_way_every_read() {
        let service = service();
        for process in [903, 12, 461] {
            let mut plain = request(Some(3600), Some(false));
            plain.subscriber_process_identifier = process;
            service
                .subscribe_cov(&plain, Some(subscriber()))
                .expect("subscribe");
        }

        let processes: Vec<_> = active_subscriptions(&service)
            .iter()
            .map(|subscription| subscription.recipient.process_identifier)
            .collect();

        assert_eq!(processes, vec![12, 461, 903]);
        assert_eq!(
            active_subscriptions(&service)
                .iter()
                .map(|subscription| subscription.recipient.process_identifier)
                .collect::<Vec<_>>(),
            processes,
            "and the same again on the next read"
        );
    }

    /// It is a property of the Device object alone, and a client asking for
    /// every property should be told it is there.
    #[test]
    fn the_device_lists_the_property_and_other_objects_do_not() {
        let service = service();
        let device = service.database().get_device_id();

        assert!(service
            .properties_for(device)
            .expect("device properties")
            .contains(&PropertyIdentifier::ActiveCovSubscriptions));
        assert!(!service
            .properties_for(ObjectIdentifier::new(ObjectType::AnalogValue, 1))
            .expect("object properties")
            .contains(&PropertyIdentifier::ActiveCovSubscriptions));
        assert!(
            service
                .read_property(&ReadPropertyRequest::new(
                    ObjectIdentifier::new(ObjectType::AnalogValue, 1),
                    PropertyIdentifier::ActiveCovSubscriptions,
                ))
                .is_err(),
            "an analog value has no subscription list of its own"
        );
    }

    /// Unknown object and unknown property are different mistakes, and the
    /// subscriber is told which one it made.
    #[test]
    fn subscribing_to_a_property_the_object_lacks_is_refused() {
        let service = service();
        assert!(matches!(
            service.subscribe_cov_property(
                &property_request(PropertyIdentifier::NumberOfStates, Some(60), Some(false)),
                Some(subscriber())
            ),
            Err(ObjectError::UnknownProperty)
        ));

        let mut missing = property_request(PropertyIdentifier::PresentValue, Some(60), Some(false));
        missing.monitored_object_identifier = ObjectIdentifier::new(ObjectType::AnalogValue, 99);
        assert!(matches!(
            service.subscribe_cov_property(&missing, Some(subscriber())),
            Err(ObjectError::NotFound)
        ));
        assert!(service.subscriptions().is_empty());
    }

    #[test]
    fn subscribing_to_one_element_of_an_array_is_refused() {
        let service = service();
        let mut request =
            property_request(PropertyIdentifier::PriorityArray, Some(60), Some(false));
        request.monitored_property = crate::service::PropertyReference::with_array_index(
            PropertyIdentifier::PriorityArray,
            3,
        );

        assert!(matches!(
            service.subscribe_cov_property(&request, Some(subscriber())),
            Err(ObjectError::OptionalFunctionalityNotSupported)
        ));
    }

    #[test]
    fn a_subscribe_request_round_trips_through_the_wire() {
        let original = request(Some(3600), Some(true));
        let mut encoded = Vec::new();
        original.encode(&mut encoded).expect("encode");

        let decoded = SubscribeCovRequest::decode(&encoded).expect("decode");
        assert_eq!(decoded.subscriber_process_identifier, 777);
        assert_eq!(
            decoded.monitored_object_identifier,
            original.monitored_object_identifier
        );
        assert_eq!(decoded.issue_confirmed_notifications, Some(true));
        assert_eq!(decoded.lifetime, Some(3600), "must not truncate to a byte");
        assert!(!decoded.is_cancellation());
    }

    #[test]
    fn a_cancellation_round_trips_as_one() {
        let mut encoded = Vec::new();
        request(None, None).encode(&mut encoded).expect("encode");
        assert!(SubscribeCovRequest::decode(&encoded)
            .expect("decode")
            .is_cancellation());
    }
}
