//! BACnet Object Database Module
//!
//! This module provides a database for storing and managing BACnet objects locally.
//! It supports CRUD operations, property access, and efficient object lookup.

#[cfg(feature = "std")]
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::Instant,
};

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, collections::BTreeMap as HashMap, string::String, sync::Arc, vec::Vec};

use super::{
    object_types_supported_bit_string, BacnetObject, Device, ObjectError, ObjectIdentifier,
    ObjectType, PropertyIdentifier, PropertyValue, Result,
};

#[cfg(feature = "std")]
type ObjectEntry = RwLock<Box<dyn BacnetObject>>;

#[cfg(feature = "std")]
fn requested_object_name(property: PropertyIdentifier, value: &PropertyValue) -> Option<String> {
    match (property, value) {
        (PropertyIdentifier::ObjectName, PropertyValue::CharacterString(name)) => {
            Some(name.clone())
        }
        _ => None,
    }
}

/// Object database for managing BACnet objects
#[cfg(feature = "std")]
pub struct ObjectDatabase {
    /// Objects stored by identifier
    objects: Arc<RwLock<HashMap<ObjectIdentifier, ObjectEntry>>>,
    /// Index by object type for fast lookup
    type_index: Arc<RwLock<HashMap<ObjectType, Vec<ObjectIdentifier>>>>,
    /// Object name index for fast lookup by name
    name_index: Arc<RwLock<HashMap<String, ObjectIdentifier>>>,
    /// Database revision (incremented on changes)
    revision: Arc<RwLock<u32>>,
    /// Last modification time
    last_modified: Arc<RwLock<Instant>>,
    /// Device object reference (must always exist)
    device_id: ObjectIdentifier,
}

#[cfg(feature = "std")]
impl ObjectDatabase {
    /// Create a new object database with a device object
    pub fn new(device: Device) -> Self {
        let device_id = device.identifier();
        let mut objects = HashMap::new();
        let mut type_index = HashMap::new();
        let mut name_index = HashMap::new();

        // Add device to indices
        type_index
            .entry(ObjectType::Device)
            .or_insert_with(Vec::new)
            .push(device_id);
        name_index.insert(device.object_name.clone(), device_id);

        // Store device object
        objects.insert(
            device_id,
            RwLock::new(Box::new(device) as Box<dyn BacnetObject>),
        );

        Self {
            objects: Arc::new(RwLock::new(objects)),
            type_index: Arc::new(RwLock::new(type_index)),
            name_index: Arc::new(RwLock::new(name_index)),
            revision: Arc::new(RwLock::new(1)),
            last_modified: Arc::new(RwLock::new(Instant::now())),
            device_id,
        }
    }

    /// Add an object to the database
    pub fn add_object(&self, object: Box<dyn BacnetObject>) -> Result<()> {
        let identifier = object.identifier();

        // Get object name for indexing
        let object_name = match object.get_property(PropertyIdentifier::ObjectName)? {
            PropertyValue::CharacterString(name) => name,
            _ => return Err(ObjectError::InvalidPropertyType),
        };

        // Update all indices and storage atomically
        {
            let mut objects = self.objects.write().unwrap();
            let mut type_index = self.type_index.write().unwrap();
            let mut name_index = self.name_index.write().unwrap();

            if objects.contains_key(&identifier) {
                return Err(ObjectError::InvalidConfiguration(format!(
                    "Object {} already exists",
                    identifier.instance
                )));
            }
            if let Some(existing) = name_index.get(&object_name) {
                return Err(ObjectError::InvalidValue(format!(
                    "Object name {object_name:?} is already used by {existing:?}"
                )));
            }

            // Add to type index
            type_index
                .entry(identifier.object_type)
                .or_default()
                .push(identifier);

            // Add to name index
            name_index.insert(object_name, identifier);

            // Store object
            objects.insert(identifier, RwLock::new(object));

            // Update database revision
            self.increment_revision();
        }

        Ok(())
    }

    /// Remove an object from the database
    pub fn remove_object(&self, identifier: ObjectIdentifier) -> Result<()> {
        // Cannot remove device object
        if identifier == self.device_id {
            return Err(ObjectError::WriteAccessDenied);
        }

        // Remove from all indices and storage
        {
            let mut objects = self.objects.write().unwrap();
            let object_name = match objects.get(&identifier) {
                Some(entry) => {
                    let object = entry.read().unwrap();
                    match object.get_property(PropertyIdentifier::ObjectName)? {
                        PropertyValue::CharacterString(name) => name,
                        _ => return Err(ObjectError::InvalidPropertyType),
                    }
                }
                None => return Err(ObjectError::NotFound),
            };
            let mut type_index = self.type_index.write().unwrap();
            let mut name_index = self.name_index.write().unwrap();

            // Remove from object storage
            objects.remove(&identifier);

            // Remove from type index
            if let Some(type_list) = type_index.get_mut(&identifier.object_type) {
                type_list.retain(|&id| id != identifier);
            }

            // Remove from name index
            name_index.remove(&object_name);

            // Update database revision
            self.increment_revision();
        }

        Ok(())
    }

    /// Get a property value from an object
    pub fn get_property(
        &self,
        identifier: ObjectIdentifier,
        property: PropertyIdentifier,
    ) -> Result<PropertyValue> {
        if identifier == self.device_id {
            match property {
                PropertyIdentifier::DatabaseRevision => {
                    return Ok(PropertyValue::Unsigned(self.revision().into()));
                }
                PropertyIdentifier::ProtocolObjectTypesSupported => {
                    let protocol_revision = match self
                        .get_stored_property(identifier, PropertyIdentifier::ProtocolRevision)?
                    {
                        PropertyValue::Unsigned(revision) => revision
                            .try_into()
                            .map_err(|_| ObjectError::InvalidPropertyType)?,
                        _ => return Err(ObjectError::InvalidPropertyType),
                    };
                    return Ok(PropertyValue::BitString(object_types_supported_bit_string(
                        &self.object_types(),
                        protocol_revision,
                    )));
                }
                _ => {}
            }
        }
        self.get_stored_property(identifier, property)
    }

    fn get_stored_property(
        &self,
        identifier: ObjectIdentifier,
        property: PropertyIdentifier,
    ) -> Result<PropertyValue> {
        let objects = self.objects.read().unwrap();
        let entry = objects.get(&identifier).ok_or(ObjectError::NotFound)?;
        let object = entry.read().unwrap();
        object.get_property(property)
    }

    /// Return the properties exposed by an object.
    pub fn property_list(&self, identifier: ObjectIdentifier) -> Result<Vec<PropertyIdentifier>> {
        let objects = self.objects.read().unwrap();
        let entry = objects.get(&identifier).ok_or(ObjectError::NotFound)?;
        let object = entry.read().unwrap();
        Ok(object.property_list())
    }

    /// Set a property value on an object
    pub fn set_property(
        &self,
        identifier: ObjectIdentifier,
        property: PropertyIdentifier,
        value: PropertyValue,
    ) -> Result<()> {
        let requested_name = requested_object_name(property, &value);
        self.update_object(identifier, property, requested_name, move |object| {
            object.set_property(property, value)
        })
    }

    /// Set a property while preserving the command priority from the BACnet
    /// request. Non-commandable objects use their normal property setter.
    pub fn set_property_with_priority(
        &self,
        identifier: ObjectIdentifier,
        property: PropertyIdentifier,
        value: PropertyValue,
        priority: Option<u8>,
    ) -> Result<()> {
        let requested_name = requested_object_name(property, &value);
        self.update_object(identifier, property, requested_name, move |object| {
            object.set_property_with_priority(property, value, priority)
        })
    }

    fn update_object<F>(
        &self,
        identifier: ObjectIdentifier,
        property: PropertyIdentifier,
        requested_name: Option<String>,
        update: F,
    ) -> Result<()>
    where
        F: FnOnce(&mut dyn BacnetObject) -> Result<()>,
    {
        let objects = self.objects.read().unwrap();
        let entry = objects.get(&identifier).ok_or(ObjectError::NotFound)?;
        let mut object = entry.write().unwrap();
        let mut name_index = if let Some(new_name) = requested_name.as_ref() {
            let name_index = self.name_index.write().unwrap();
            if name_index
                .get(new_name)
                .is_some_and(|existing| *existing != identifier)
            {
                return Err(ObjectError::InvalidValue(format!(
                    "Object name {new_name:?} is already in use"
                )));
            }
            Some(name_index)
        } else {
            None
        };
        let old_name = if requested_name.is_some() {
            match object.get_property(PropertyIdentifier::ObjectName)? {
                PropertyValue::CharacterString(name) => Some(name),
                _ => return Err(ObjectError::InvalidPropertyType),
            }
        } else {
            None
        };

        update(object.as_mut())?;

        if let Some(old_name) = old_name {
            let new_name = match object.get_property(PropertyIdentifier::ObjectName)? {
                PropertyValue::CharacterString(name) => name,
                _ => return Err(ObjectError::InvalidPropertyType),
            };
            let name_index = name_index
                .as_mut()
                .expect("ObjectName updates must hold the name index");
            name_index.remove(&old_name);
            name_index.insert(new_name, identifier);
        }

        drop(object);
        drop(objects);
        if property == PropertyIdentifier::ObjectName {
            self.increment_revision();
        }
        Ok(())
    }

    /// Get an object by name
    pub fn get_object_by_name(&self, name: &str) -> Result<ObjectIdentifier> {
        let name_index = self.name_index.read().unwrap();
        match name_index.get(name) {
            Some(&identifier) => Ok(identifier),
            None => Err(ObjectError::NotFound),
        }
    }

    /// Get all objects of a specific type
    pub fn get_objects_by_type(&self, object_type: ObjectType) -> Vec<ObjectIdentifier> {
        let type_index = self.type_index.read().unwrap();
        type_index.get(&object_type).cloned().unwrap_or_default()
    }

    /// Get all object identifiers in the database
    pub fn get_all_objects(&self) -> Vec<ObjectIdentifier> {
        let objects = self.objects.read().unwrap();
        let mut identifiers: Vec<_> = objects.keys().cloned().collect();
        identifiers
            .sort_by_key(|identifier| (u32::from(identifier.object_type), identifier.instance));
        identifiers
    }

    /// Get every object type that currently has at least one object.
    pub fn object_types(&self) -> Vec<ObjectType> {
        let type_index = self.type_index.read().unwrap();
        let mut object_types: Vec<_> = type_index
            .iter()
            .filter_map(|(object_type, identifiers)| {
                (!identifiers.is_empty()).then_some(*object_type)
            })
            .collect();
        object_types.sort_by_key(|object_type| u32::from(*object_type));
        object_types
    }

    /// Get object count
    pub fn object_count(&self) -> usize {
        let objects = self.objects.read().unwrap();
        objects.len()
    }

    /// Get object count by type
    pub fn object_count_by_type(&self, object_type: ObjectType) -> usize {
        let type_index = self.type_index.read().unwrap();
        type_index
            .get(&object_type)
            .map(|list| list.len())
            .unwrap_or(0)
    }

    /// Get the device object identifier
    pub fn get_device_id(&self) -> ObjectIdentifier {
        self.device_id
    }

    /// Get the current database revision
    pub fn revision(&self) -> u32 {
        *self.revision.read().unwrap()
    }

    /// Get the last modification time
    pub fn last_modified(&self) -> Instant {
        *self.last_modified.read().unwrap()
    }

    /// Check if an object exists
    pub fn contains(&self, identifier: ObjectIdentifier) -> bool {
        let objects = self.objects.read().unwrap();
        objects.contains_key(&identifier)
    }

    /// Check if an object name exists
    pub fn contains_name(&self, name: &str) -> bool {
        let name_index = self.name_index.read().unwrap();
        name_index.contains_key(name)
    }

    /// Find the next available instance number for an object type
    pub fn next_instance(&self, object_type: ObjectType) -> u32 {
        let type_index = self.type_index.read().unwrap();
        if let Some(objects) = type_index.get(&object_type) {
            let max_instance = objects.iter().map(|id| id.instance).max().unwrap_or(0);
            max_instance.saturating_add(1)
        } else {
            0
        }
    }

    /// Search objects by property value
    pub fn search_by_property(
        &self,
        property: PropertyIdentifier,
        value: &PropertyValue,
    ) -> Vec<ObjectIdentifier> {
        let objects = self.objects.read().unwrap();
        let mut results = Vec::new();

        for (&id, entry) in objects.iter() {
            let object = entry.read().unwrap();
            if let Ok(prop_value) = object.get_property(property) {
                if Self::property_values_equal(&prop_value, value) {
                    results.push(id);
                }
            }
        }

        results
    }

    /// Compare property values for equality
    fn property_values_equal(a: &PropertyValue, b: &PropertyValue) -> bool {
        match (a, b) {
            (PropertyValue::Null, PropertyValue::Null) => true,
            (PropertyValue::Boolean(a), PropertyValue::Boolean(b)) => a == b,
            (PropertyValue::Unsigned(a), PropertyValue::Unsigned(b)) => a == b,
            (PropertyValue::Signed(a), PropertyValue::Signed(b)) => a == b,
            (PropertyValue::Real(a), PropertyValue::Real(b)) => (a - b).abs() < f32::EPSILON,
            (PropertyValue::Double(a), PropertyValue::Double(b)) => (a - b).abs() < f64::EPSILON,
            (PropertyValue::CharacterString(a), PropertyValue::CharacterString(b)) => a == b,
            (PropertyValue::Enumerated(a), PropertyValue::Enumerated(b)) => a == b,
            (PropertyValue::ObjectIdentifier(a), PropertyValue::ObjectIdentifier(b)) => a == b,
            _ => false,
        }
    }

    /// Increment database revision
    fn increment_revision(&self) {
        let mut revision = self.revision.write().unwrap();
        *revision = revision.wrapping_add(1);

        let mut last_modified = self.last_modified.write().unwrap();
        *last_modified = Instant::now();
    }

    /// Export database statistics
    pub fn statistics(&self) -> DatabaseStatistics {
        let objects = self.objects.read().unwrap();
        let type_index = self.type_index.read().unwrap();

        let mut type_counts = HashMap::new();
        for (object_type, identifiers) in type_index.iter() {
            type_counts.insert(*object_type, identifiers.len());
        }

        DatabaseStatistics {
            total_objects: objects.len(),
            object_types: type_index.len(),
            type_counts,
            revision: self.revision(),
            last_modified: self.last_modified(),
        }
    }
}

/// Database statistics
#[cfg(feature = "std")]
#[derive(Debug, Clone)]
pub struct DatabaseStatistics {
    pub total_objects: usize,
    pub object_types: usize,
    pub type_counts: HashMap<ObjectType, usize>,
    pub revision: u32,
    pub last_modified: Instant,
}

/// Object database builder for convenient setup
#[cfg(feature = "std")]
#[derive(Default)]
pub struct DatabaseBuilder {
    device: Option<Device>,
    objects: Vec<Box<dyn BacnetObject>>,
}

#[cfg(feature = "std")]
impl DatabaseBuilder {
    /// Create a new database builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the device object
    pub fn with_device(mut self, device: Device) -> Self {
        self.device = Some(device);
        self
    }

    /// Add an object to be included in the database
    pub fn add_object(mut self, object: Box<dyn BacnetObject>) -> Self {
        self.objects.push(object);
        self
    }

    /// Build the database
    pub fn build(self) -> Result<ObjectDatabase> {
        let device = self.device.ok_or_else(|| {
            ObjectError::InvalidConfiguration("Device object is required".to_string())
        })?;

        let database = ObjectDatabase::new(device);

        // Add all objects
        for object in self.objects {
            database.add_object(object)?;
        }

        Ok(database)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        thread,
        time::Duration,
    };

    use super::*;
    use crate::object::{
        analog::{AnalogInput, AnalogValue},
        binary::BinaryInput,
    };

    struct SlowWritableObject {
        identifier: ObjectIdentifier,
        name: String,
        present_value: f32,
        active_writes: Arc<AtomicUsize>,
        maximum_active_writes: Arc<AtomicUsize>,
    }

    impl BacnetObject for SlowWritableObject {
        fn identifier(&self) -> ObjectIdentifier {
            self.identifier
        }

        fn get_property(&self, property: PropertyIdentifier) -> Result<PropertyValue> {
            match property {
                PropertyIdentifier::ObjectName => {
                    Ok(PropertyValue::CharacterString(self.name.clone()))
                }
                PropertyIdentifier::PresentValue => Ok(PropertyValue::Real(self.present_value)),
                _ => Err(ObjectError::UnknownProperty),
            }
        }

        fn set_property(
            &mut self,
            property: PropertyIdentifier,
            value: PropertyValue,
        ) -> Result<()> {
            match (property, value) {
                (PropertyIdentifier::PresentValue, PropertyValue::Real(value)) => {
                    let active = self.active_writes.fetch_add(1, Ordering::SeqCst) + 1;
                    self.maximum_active_writes
                        .fetch_max(active, Ordering::SeqCst);
                    thread::sleep(Duration::from_millis(100));
                    self.present_value = value;
                    self.active_writes.fetch_sub(1, Ordering::SeqCst);
                    Ok(())
                }
                _ => Err(ObjectError::PropertyNotWritable),
            }
        }

        fn is_property_writable(&self, property: PropertyIdentifier) -> bool {
            property == PropertyIdentifier::PresentValue
        }

        fn property_list(&self) -> Vec<PropertyIdentifier> {
            vec![
                PropertyIdentifier::ObjectName,
                PropertyIdentifier::PresentValue,
            ]
        }
    }

    #[test]
    fn test_database_creation() {
        let device = Device::new(1234, "Test Device".to_string());
        let db = ObjectDatabase::new(device);

        assert_eq!(db.object_count(), 1);
        assert_eq!(db.revision(), 1);
        assert!(db.contains(ObjectIdentifier::new(ObjectType::Device, 1234)));
    }

    #[test]
    fn test_add_remove_objects() {
        let device = Device::new(1234, "Test Device".to_string());
        let db = ObjectDatabase::new(device);

        // Add analog input
        let ai = AnalogInput::new(1, "Temperature".to_string());
        db.add_object(Box::new(ai)).unwrap();

        assert_eq!(db.object_count(), 2);
        assert_eq!(db.object_count_by_type(ObjectType::AnalogInput), 1);

        // Add binary input
        let bi = BinaryInput::new(1, "Door Sensor".to_string());
        db.add_object(Box::new(bi)).unwrap();

        assert_eq!(db.object_count(), 3);

        // Remove analog input
        let ai_id = ObjectIdentifier::new(ObjectType::AnalogInput, 1);
        db.remove_object(ai_id).unwrap();

        assert_eq!(db.object_count(), 2);
        assert_eq!(db.object_count_by_type(ObjectType::AnalogInput), 0);
    }

    #[test]
    fn test_object_lookup() {
        let device = Device::new(1234, "Test Device".to_string());
        let db = ObjectDatabase::new(device);

        let av = AnalogValue::new(100, "Setpoint".to_string());
        db.add_object(Box::new(av)).unwrap();

        // Lookup by identifier
        let av_id = ObjectIdentifier::new(ObjectType::AnalogValue, 100);
        assert!(db.contains(av_id));

        // Lookup by name
        let found_id = db.get_object_by_name("Setpoint").unwrap();
        assert_eq!(found_id, av_id);

        db.set_property(
            av_id,
            PropertyIdentifier::ObjectName,
            PropertyValue::CharacterString("Occupied setpoint".to_string()),
        )
        .unwrap();
        assert!(matches!(
            db.get_object_by_name("Setpoint"),
            Err(ObjectError::NotFound)
        ));
        assert_eq!(db.get_object_by_name("Occupied setpoint").unwrap(), av_id);

        let other_id = ObjectIdentifier::new(ObjectType::AnalogValue, 101);
        db.add_object(Box::new(AnalogValue::new(
            101,
            "Unoccupied setpoint".to_string(),
        )))
        .unwrap();
        assert!(matches!(
            db.set_property(
                other_id,
                PropertyIdentifier::ObjectName,
                PropertyValue::CharacterString("Occupied setpoint".to_string()),
            ),
            Err(ObjectError::InvalidValue(_))
        ));
        assert_eq!(db.get_object_by_name("Occupied setpoint").unwrap(), av_id);
        assert_eq!(
            db.get_object_by_name("Unoccupied setpoint").unwrap(),
            other_id
        );

        assert!(matches!(
            db.add_object(Box::new(AnalogValue::new(
                102,
                "Occupied setpoint".to_string(),
            ))),
            Err(ObjectError::InvalidValue(_))
        ));

        // Lookup by type
        let objects = db.get_objects_by_type(ObjectType::AnalogValue);
        assert_eq!(objects.len(), 2);
        assert!(objects.contains(&av_id));
        assert!(objects.contains(&other_id));
        assert_eq!(
            db.object_types(),
            vec![ObjectType::AnalogValue, ObjectType::Device]
        );
    }

    #[test]
    fn test_property_search() {
        let device = Device::new(1234, "Test Device".to_string());
        let db = ObjectDatabase::new(device);

        // Add multiple analog values
        for i in 0..5 {
            let mut av = AnalogValue::new(i, format!("AV{}", i));
            av.present_value = 20.0 + i as f32;
            db.add_object(Box::new(av)).unwrap();
        }

        // Search for specific present value
        let results =
            db.search_by_property(PropertyIdentifier::PresentValue, &PropertyValue::Real(22.0));

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].instance, 2);
    }

    #[test]
    fn test_database_builder() {
        let db = DatabaseBuilder::new()
            .with_device(Device::new(5000, "Built Device".to_string()))
            .add_object(Box::new(AnalogInput::new(1, "AI1".to_string())))
            .add_object(Box::new(AnalogInput::new(2, "AI2".to_string())))
            .add_object(Box::new(BinaryInput::new(1, "BI1".to_string())))
            .build()
            .unwrap();

        assert_eq!(db.object_count(), 4); // Device + 3 objects
        assert_eq!(db.object_count_by_type(ObjectType::AnalogInput), 2);
        assert_eq!(db.object_count_by_type(ObjectType::BinaryInput), 1);
    }

    #[test]
    fn test_next_instance() {
        let device = Device::new(1234, "Test Device".to_string());
        let db = ObjectDatabase::new(device);

        // No analog inputs yet
        assert_eq!(db.next_instance(ObjectType::AnalogInput), 0);

        // Add some analog inputs
        db.add_object(Box::new(AnalogInput::new(5, "AI5".to_string())))
            .unwrap();
        db.add_object(Box::new(AnalogInput::new(10, "AI10".to_string())))
            .unwrap();
        db.add_object(Box::new(AnalogInput::new(3, "AI3".to_string())))
            .unwrap();

        // Next instance should be max + 1
        assert_eq!(db.next_instance(ObjectType::AnalogInput), 11);
    }

    #[test]
    fn writes_to_different_objects_do_not_share_an_object_lock() {
        let database = Arc::new(ObjectDatabase::new(Device::new(
            1234,
            "Test Device".to_string(),
        )));
        let active_writes = Arc::new(AtomicUsize::new(0));
        let maximum_active_writes = Arc::new(AtomicUsize::new(0));
        for instance in 1..=2 {
            database
                .add_object(Box::new(SlowWritableObject {
                    identifier: ObjectIdentifier::new(ObjectType::AnalogValue, instance),
                    name: format!("Value {instance}"),
                    present_value: 0.0,
                    active_writes: Arc::clone(&active_writes),
                    maximum_active_writes: Arc::clone(&maximum_active_writes),
                }))
                .unwrap();
        }

        let writers: Vec<_> = (1..=2)
            .map(|instance| {
                let database = Arc::clone(&database);
                thread::spawn(move || {
                    database
                        .set_property(
                            ObjectIdentifier::new(ObjectType::AnalogValue, instance),
                            PropertyIdentifier::PresentValue,
                            PropertyValue::Real(instance as f32),
                        )
                        .unwrap();
                })
            })
            .collect();
        for writer in writers {
            writer.join().unwrap();
        }

        assert_eq!(maximum_active_writes.load(Ordering::SeqCst), 2);
        assert_eq!(database.revision(), 3);
    }
}
