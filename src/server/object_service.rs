use std::sync::Arc;

use crate::{
    object::{
        database::ObjectDatabase, ObjectError, ObjectIdentifier, ObjectType, PropertyIdentifier,
        PropertyValue, Segmentation,
    },
    service::{IAmRequest, ReadPropertyRequest, ReadPropertyResponse, WritePropertyRequest},
};

/// Executes BACnet object services against a hosted object database.
#[derive(Clone)]
pub struct ObjectService {
    database: Arc<ObjectDatabase>,
}

impl ObjectService {
    pub fn new(database: Arc<ObjectDatabase>) -> Self {
        Self { database }
    }

    pub fn database(&self) -> &Arc<ObjectDatabase> {
        &self.database
    }

    pub fn read_property(
        &self,
        request: &ReadPropertyRequest,
    ) -> Result<ReadPropertyResponse, ObjectError> {
        let value = match request.property_identifier {
            PropertyIdentifier::ObjectList
                if request.object_identifier == self.database.get_device_id() =>
            {
                PropertyValue::Array(
                    self.database
                        .get_all_objects()
                        .into_iter()
                        .map(PropertyValue::ObjectIdentifier)
                        .collect(),
                )
            }
            PropertyIdentifier::PropertyList => {
                let mut properties = self.database.property_list(request.object_identifier)?;
                if request.object_identifier == self.database.get_device_id()
                    && !properties.contains(&PropertyIdentifier::ObjectList)
                {
                    properties.push(PropertyIdentifier::ObjectList);
                }
                if !properties.contains(&PropertyIdentifier::PropertyList) {
                    properties.push(PropertyIdentifier::PropertyList);
                }
                PropertyValue::Array(
                    properties
                        .into_iter()
                        .map(|property| PropertyValue::Enumerated(property.into()))
                        .collect(),
                )
            }
            _ => self
                .database
                .get_property(request.object_identifier, request.property_identifier)?,
        };

        let property_values = select_array_value(value, request.property_array_index)?;
        let mut response = ReadPropertyResponse::new(
            request.object_identifier,
            request.property_identifier,
            property_values,
        );
        response.property_array_index = request.property_array_index;
        Ok(response)
    }

    pub fn write_property(&self, request: &WritePropertyRequest) -> Result<(), ObjectError> {
        if request.property_array_index.is_some() {
            return Err(ObjectError::PropertyIsNotArray);
        }

        let (value, consumed) = crate::property::decode_property_value(&request.property_value)
            .map_err(|_| ObjectError::InvalidPropertyType)?;
        if consumed != request.property_value.len() {
            return Err(ObjectError::InvalidPropertyType);
        }

        self.database.set_property_with_priority(
            request.object_identifier,
            request.property_identifier.into(),
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
            .database
            .get_property(device, PropertyIdentifier::SegmentationSupported)?
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
