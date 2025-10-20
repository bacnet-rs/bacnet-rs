//! File Object Implementation
//!
//! This module implements the File object type as defined in ASHRAE 135.
//! File objects represent files that can be accessed using the AtomicReadFile
//! and AtomicWriteFile services.

use crate::object::{
    object_name::ObjectName, BacnetObject, ObjectError, ObjectIdentifier, ObjectType,
    PropertyIdentifier, PropertyValue, Result,
};

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

/// File access method enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum FileAccessMethod {
    RecordAccess = 0,
    StreamAccess = 1,
}

/// File object implementation
#[derive(Debug, Clone)]
pub struct File<O> {
    /// Object identifier
    pub identifier: ObjectIdentifier,
    /// Object name
    pub object_name: O,
    /// File type (MIME type or file extension)
    pub file_type: String,
    /// File size in octets
    pub file_size: u32,
    /// Modification date (BACnet Date format)
    pub modification_date: crate::object::Date,
    /// Archive flag
    pub archive: bool,
    /// Read only flag
    pub read_only: bool,
    /// File access method
    pub file_access_method: FileAccessMethod,
    /// Record count (for record access method)
    pub record_count: Option<u32>,
    /// Description
    pub description: String,
    /// File contents (in-memory storage for this implementation)
    pub file_data: Vec<u8>,
}

impl<O> File<O> {
    /// Create a new File object
    pub fn new(instance: u32, object_name: O, file_type: String) -> Self {
        Self {
            identifier: ObjectIdentifier::new(ObjectType::File, instance),
            object_name,
            file_type,
            file_size: 0,
            modification_date: crate::object::Date {
                year: 2024,
                month: 1,
                day: 1,
                weekday: 1,
            },
            archive: false,
            read_only: false,
            file_access_method: FileAccessMethod::StreamAccess,
            record_count: None,
            description: String::new(),
            file_data: Vec::new(),
        }
    }

    /// Set file contents
    pub fn set_file_data(&mut self, data: Vec<u8>) {
        self.file_data = data;
        self.file_size = self.file_data.len() as u32;
        // Update modification date to current (simplified)
        // In a real implementation, this would use actual system time
    }

    /// Get file contents
    pub fn get_file_data(&self) -> &[u8] {
        &self.file_data
    }

    /// Read data from file at specified position
    pub fn read_data(&self, start_position: u32, requested_count: u32) -> Result<Vec<u8>> {
        let start = start_position as usize;
        let end = (start_position + requested_count) as usize;

        if start >= self.file_data.len() {
            return Ok(Vec::new()); // EOF
        }

        let actual_end = end.min(self.file_data.len());
        Ok(self.file_data[start..actual_end].to_vec())
    }

    /// Write data to file at specified position
    pub fn write_data(&mut self, start_position: u32, data: &[u8]) -> Result<()> {
        if self.read_only {
            return Err(ObjectError::WriteAccessDenied);
        }

        let start = start_position as usize;
        let data_len = data.len();
        let required_len = start + data_len;

        // Extend file if necessary
        if required_len > self.file_data.len() {
            self.file_data.resize(required_len, 0);
        }

        // Write the data (overwrite existing data at this position)
        self.file_data[start..start + data_len].copy_from_slice(data);
        self.file_size = self.file_data.len() as u32;

        Ok(())
    }

    /// Read records from file (for record access method)
    pub fn read_records(&self, start_record: u32, record_count: u32) -> Result<Vec<Vec<u8>>> {
        if self.file_access_method != FileAccessMethod::RecordAccess {
            return Err(ObjectError::InvalidValue(
                "File is not configured for record access".to_string(),
            ));
        }

        // This is a simplified implementation
        // In practice, records would have defined structure and separators
        let mut records = Vec::new();

        // For demonstration, treat each line as a record
        let file_str = String::from_utf8_lossy(&self.file_data);
        let lines: Vec<&str> = file_str.lines().collect();

        let start_idx = start_record as usize;
        let end_idx = (start_record + record_count) as usize;

        for line in lines.iter().take(end_idx.min(lines.len())).skip(start_idx) {
            records.push(line.as_bytes().to_vec());
        }

        Ok(records)
    }

    /// Write records to file (for record access method)
    pub fn write_records(&mut self, start_record: u32, records: &[Vec<u8>]) -> Result<()> {
        if self.read_only {
            return Err(ObjectError::WriteAccessDenied);
        }

        if self.file_access_method != FileAccessMethod::RecordAccess {
            return Err(ObjectError::InvalidValue(
                "File is not configured for record access".to_string(),
            ));
        }

        // This is a simplified implementation
        // Convert current data to lines
        let file_str = String::from_utf8_lossy(&self.file_data);
        let mut lines: Vec<String> = file_str.lines().map(|s| s.to_string()).collect();

        let start_idx = start_record as usize;

        // Extend lines vector if necessary
        while lines.len() < start_idx + records.len() {
            lines.push(String::new());
        }

        // Replace records
        for (i, record) in records.iter().enumerate() {
            let record_str = String::from_utf8_lossy(record);
            lines[start_idx + i] = record_str.to_string();
        }

        // Convert back to file data
        let new_data = lines.join("\n");
        self.file_data = new_data.into_bytes();
        self.file_size = self.file_data.len() as u32;
        self.record_count = Some(lines.len() as u32);

        Ok(())
    }
}

impl<O> BacnetObject for File<O>
where
    O: ObjectName,
{
    fn identifier(&self) -> ObjectIdentifier {
        self.identifier
    }

    fn object_name(&self) -> &dyn ObjectName {
        &self.object_name
    }

    fn get_property(&self, property: PropertyIdentifier) -> Result<PropertyValue> {
        match property {
            PropertyIdentifier::ObjectIdentifier => {
                Ok(PropertyValue::ObjectIdentifier(self.identifier))
            }
            PropertyIdentifier::ObjectName => {
                Ok(PropertyValue::CharacterString(self.object_name.to_string()))
            }
            PropertyIdentifier::ObjectType => {
                Ok(PropertyValue::Enumerated(ObjectType::File as u32))
            }
            PropertyIdentifier::Archive => Ok(PropertyValue::Boolean(self.archive)),
            _ => Err(ObjectError::UnknownProperty),
        }
    }

    fn set_property(&mut self, property: PropertyIdentifier, value: PropertyValue) -> Result<()> {
        match property {
            PropertyIdentifier::ObjectName => {
                if let PropertyValue::CharacterString(name) = value {
                    self.object_name
                        .update(&name)
                        .map_err(|_| ObjectError::InvalidValue(name))
                } else {
                    Err(ObjectError::InvalidPropertyType)
                }
            }
            PropertyIdentifier::Archive => {
                if let PropertyValue::Boolean(archive) = value {
                    self.archive = archive;
                    Ok(())
                } else {
                    Err(ObjectError::InvalidPropertyType)
                }
            }
            _ => Err(ObjectError::PropertyNotWritable),
        }
    }

    fn is_property_writable(&self, property: PropertyIdentifier) -> bool {
        matches!(
            property,
            PropertyIdentifier::ObjectName | PropertyIdentifier::Archive
        )
    }

    fn property_list(&self) -> Vec<PropertyIdentifier> {
        vec![
            PropertyIdentifier::ObjectIdentifier,
            PropertyIdentifier::ObjectName,
            PropertyIdentifier::ObjectType,
            PropertyIdentifier::Archive,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_creation() {
        let file = File::new(1, "config.txt".to_string(), "text/plain".to_string());
        assert_eq!(file.identifier.instance, 1);
        assert_eq!(file.object_name, "config.txt");
        assert_eq!(file.file_type, "text/plain");
        assert_eq!(file.file_size, 0);
    }

    #[test]
    fn test_file_data_operations() {
        let mut file = File::new(
            1,
            "test.dat".to_string(),
            "application/octet-stream".to_string(),
        );

        // Set initial data
        let data = b"Hello, BACnet File!".to_vec();
        file.set_file_data(data.clone());
        assert_eq!(file.file_size, data.len() as u32);
        assert_eq!(file.get_file_data(), data.as_slice());

        // Test reading data
        let read_data = file.read_data(0, 5).unwrap();
        assert_eq!(read_data, b"Hello");

        let read_data = file.read_data(7, 6).unwrap();
        assert_eq!(read_data, b"BACnet");

        // Test writing data (overwrite "BACnet" with "Rust  ")
        file.write_data(7, b"Rust  ").unwrap();
        let expected = b"Hello, Rust   File!";
        assert_eq!(file.get_file_data(), expected);
    }

    #[test]
    fn test_file_record_operations() {
        let mut file = File::new(1, "records.txt".to_string(), "text/plain".to_string());
        file.file_access_method = FileAccessMethod::RecordAccess;

        // Set initial records as line-separated data
        let initial_data = "Line 1\nLine 2\nLine 3\nLine 4".as_bytes().to_vec();
        file.set_file_data(initial_data);

        // Read records
        let records = file.read_records(1, 2).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0], b"Line 2");
        assert_eq!(records[1], b"Line 3");

        // Write records
        let new_records = vec![b"New Line 2".to_vec(), b"New Line 3".to_vec()];
        file.write_records(1, &new_records).unwrap();

        let updated_records = file.read_records(0, 4).unwrap();
        assert_eq!(updated_records[0], b"Line 1");
        assert_eq!(updated_records[1], b"New Line 2");
        assert_eq!(updated_records[2], b"New Line 3");
        assert_eq!(updated_records[3], b"Line 4");
    }

    #[test]
    fn test_file_properties() {
        let mut file = File::new(1, "test.txt".to_string(), "text/plain".to_string());

        // Test property access
        let name = file.get_property(PropertyIdentifier::ObjectName).unwrap();
        if let PropertyValue::CharacterString(n) = name {
            assert_eq!(n, "test.txt");
        } else {
            panic!("Expected CharacterString");
        }

        // Test property modification
        file.set_property(PropertyIdentifier::Archive, PropertyValue::Boolean(true))
            .unwrap();
        assert!(file.archive);
    }

    #[test]
    fn test_read_only_protection() {
        let mut file = File::new(1, "readonly.txt".to_string(), "text/plain".to_string());
        file.read_only = true;

        // Should fail to write data
        assert!(file.write_data(0, b"test").is_err());

        // Should fail to write records
        file.file_access_method = FileAccessMethod::RecordAccess;
        let records = vec![b"test".to_vec()];
        assert!(file.write_records(0, &records).is_err());
    }
}
