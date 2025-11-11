use core::fmt::Display;

use downcast_rs::{impl_downcast, Downcast};
use dyn_clone::{clone_trait_object, DynClone};
use dyn_eq::{eq_trait_object, DynEq};
use dyn_hash::{hash_trait_object, DynHash};

/// ISO 16484-5:2017 section 12.3.2 defines the `Object_Name` property
///
/// This property, of type CharacterString, shall represent a name for the object that is unique within the BACnet device that
/// maintains it. The minimum length of the string shall be one character. The set of characters used in the Object_Name
/// shall be restricted to printable character
pub trait ObjectName: Downcast + Send + Sync + Display + DynClone + DynHash + DynEq {
    /// Replaces the value of the Object_Name
    // takes self to remain dyn compatible
    // FIXME: should take a CharacterString type or something
    fn update(&mut self, value: &str) -> Result<(), ObjectNameParseError>;
}

impl_downcast!(ObjectName);
clone_trait_object!(ObjectName);
hash_trait_object!(ObjectName);
eq_trait_object!(ObjectName);

#[derive(Debug, thiserror::Error)]
#[error("failed to parse Object_Name: {0}")]
#[non_exhaustive]
pub enum ObjectNameParseError {
    Other(#[source] Box<dyn core::error::Error>),
}

impl ObjectName for String {
    fn update(&mut self, value: &str) -> Result<(), ObjectNameParseError> {
        *self = value.to_owned();
        Ok(())
    }
}

impl ObjectName for Box<dyn ObjectName> {
    fn update(&mut self, value: &str) -> Result<(), ObjectNameParseError> {
        self.as_mut().update(value)
    }
}

pub trait IntoBoxedObjectName {
    fn into_object_name(self) -> Box<dyn ObjectName>;
}

impl IntoBoxedObjectName for &str {
    fn into_object_name(self) -> Box<dyn ObjectName> {
        Box::new(self.to_owned())
    }
}

impl<O> IntoBoxedObjectName for O
where
    O: ObjectName,
{
    fn into_object_name(self) -> Box<dyn ObjectName> {
        Box::new(self)
    }
}
