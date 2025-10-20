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

// FIXME: remove, this is kinda unsound
#[cfg(feature = "std")]
pub mod sync {
    use std::sync::{Arc, RwLock};

    use crate::object::object_name::{ObjectName, ObjectNameParseError};
    use core::fmt::{self, Display};

    #[derive(Debug)]
    pub struct ArcRw<O>(Arc<RwLock<O>>);

    impl<O> ArcRw<O> {
        pub fn new(inner: O) -> Self {
            ArcRw(Arc::new(RwLock::new(inner)))
        }
    }

    impl<O> Clone for ArcRw<O> {
        fn clone(&self) -> Self {
            ArcRw(Arc::clone(&self.0))
        }
    }

    impl<O> From<O> for ArcRw<O> {
        fn from(o: O) -> Self {
            ArcRw::new(o)
        }
    }

    impl<O> ObjectName for ArcRw<O>
    where
        O: ObjectName,
    {
        fn update(&mut self, value: &str) -> Result<(), ObjectNameParseError> {
            // If the lock is poisoned we recover the inner value and proceed.
            let mut guard = match self.0.write() {
                Ok(g) => g,
                Err(e) => e.into_inner(),
            };
            guard.update(value)
        }
    }

    // FIXME: uhm uhm this is the case for ArcRw
    // It is also a logic error for a key to be modified in such a way that the key’s hash, as determined by the Hash trait, or its equality, as determined by the Eq trait, changes while it is in the map. This is normally only possible through Cell, RefCell, global state, I/O, or unsafe code.
    impl<O> PartialEq for ArcRw<O>
    where
        O: ObjectName,
    {
        fn eq(&self, other: &Self) -> bool {
            let guard_self = match self.0.read() {
                Ok(g) => g,
                Err(e) => e.into_inner(),
            };
            let guard_other = match other.0.read() {
                Ok(g) => g,
                Err(e) => e.into_inner(),
            };
            guard_self.dyn_eq(&*guard_other)
        }
    }

    impl<O> Eq for ArcRw<O> where O: ObjectName {}

    impl<O> std::hash::Hash for ArcRw<O>
    where
        O: ObjectName,
    {
        fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
            let guard = match self.0.read() {
                Ok(g) => g,
                Err(e) => e.into_inner(),
            };
            guard.dyn_hash(state);
        }
    }
    impl<O> Display for ArcRw<O>
    where
        O: ObjectName,
    {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let guard = match self.0.read() {
                Ok(g) => g,
                Err(e) => e.into_inner(),
            };
            write!(f, "{}", &*guard)
        }
    }
}
#[cfg(test)]
mod tests {
    use crate::object::{
        object_name::{sync::ArcRw, IntoBoxedObjectName},
        DatabaseBuilder, Device,
    };

    #[test]
    fn smoke() -> Result<(), Box<dyn core::error::Error>> {
        // damn that is ugly please send help
        let updatedable_object_name =
            ArcRw::new("This can be edited".to_string()).into_object_name();
        let device = Device::new(1, updatedable_object_name.clone());
        let database = DatabaseBuilder::new().with_device(device).build()?;
        database
            .get_object_by_name(&*updatedable_object_name)
            .expect("found");
        let moved = updatedable_object_name.clone();
        std::thread::spawn(move || {
            // this is soo weird and locks inexplicitly, this is bad
            let mut x = moved;
            // FIXME: this changes the hash of the object stored in the ObjectDatabase which is a logic error for HashMap
            x.update("changed by other thread").unwrap();
        })
        .join()
        .expect("successful");
        database
            .get_object_by_name(&"changed by other thread".into_object_name())
            .expect_err("not found because it is a different ArcRwLock instance");
        let object = database
            .get_object_by_name(&*updatedable_object_name)
            .expect("found because it is the same instance");
        assert_eq!(object.instance, 1);
        Ok(())
    }
}
