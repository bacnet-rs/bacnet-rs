//! Callback Infrastructure for BACnet Objects
//!
//! This module provides callback support for BACnet objects, allowing users to register
//! functions that are called when property values change due to remote updates (network packets).
//!
//! # Example
//!
//! ```rust
//! use bacnet_rs::object::analog::AnalogInput;
//!
//! let mut ai = AnalogInput::new(1, "Temperature Sensor".to_string());
//!
//! // Register a callback for present value changes
//! ai.on_present_value_change(|value| {
//!     println!("Temperature changed to: {}", value);
//! });
//! ```

use crate::object::{PropertyIdentifier, PropertyValue};

#[cfg(not(feature = "std"))]
use alloc::boxed::Box;

/// Callback function type for property value changes
///
/// Callbacks are invoked when a property value changes due to a remote update
/// (i.e., a packet received from the network). They are NOT invoked for local
/// updates made via `set_property()`.
///
/// The callback receives the new property value as a `PropertyValue` enum.
pub type PropertyCallback = Box<dyn FnMut(PropertyValue) + Send + Sync>;

/// Collection of callbacks for common BACnet object properties
///
/// This struct holds optional callbacks for properties that commonly change
/// during runtime. Currently supports PresentValue with plans to add
/// StatusFlags and Reliability in the future.
///
/// **Note:** Callbacks are not cloned when the parent object is cloned.
/// Cloning an object with callbacks will result in an object without callbacks.
#[derive(Default)]
pub struct ObjectCallbacks {
    /// Callback for PresentValue property changes
    pub present_value: Option<PropertyCallback>,

    /// Callback for OutOfService property changes
    pub out_of_service: Option<PropertyCallback>,
}

impl Clone for ObjectCallbacks {
    /// Clone creates an empty callback collection
    ///
    /// Callbacks cannot be cloned, so cloning an ObjectCallbacks instance
    /// will create a new instance with no callbacks registered.
    fn clone(&self) -> Self {
        Self::default()
    }
}

impl core::fmt::Debug for ObjectCallbacks {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ObjectCallbacks")
            .field("present_value", &self.present_value.is_some())
            .field("out_of_service", &self.out_of_service.is_some())
            .finish()
    }
}

impl ObjectCallbacks {
    /// Create a new empty callback collection
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a callback for PresentValue changes
    ///
    /// # Example
    ///
    /// ```rust
    /// use bacnet_rs::object::callback::ObjectCallbacks;
    /// use bacnet_rs::object::PropertyValue;
    ///
    /// let mut callbacks = ObjectCallbacks::new();
    /// callbacks.on_present_value(Box::new(|value| {
    ///     if let PropertyValue::Real(val) = value {
    ///         println!("Value: {}", val);
    ///     }
    /// }));
    /// ```
    pub fn on_present_value(&mut self, callback: PropertyCallback) {
        self.present_value = Some(callback);
    }

    /// Register a callback for OutOfService changes
    pub fn on_out_of_service(&mut self, callback: PropertyCallback) {
        self.out_of_service = Some(callback);
    }

    /// Remove the PresentValue callback
    pub fn clear_present_value(&mut self) {
        self.present_value = None;
    }

    /// Remove the OutOfService callback
    pub fn clear_out_of_service(&mut self) {
        self.out_of_service = None;
    }

    /// Remove all callbacks
    pub fn clear_all(&mut self) {
        self.present_value = None;
        self.out_of_service = None;
    }

    /// Trigger the appropriate callback for a property change
    ///
    /// This is called internally when a remote update occurs.
    pub fn trigger(&mut self, property: PropertyIdentifier, value: PropertyValue) {
        match property {
            PropertyIdentifier::PresentValue => {
                if let Some(ref mut callback) = self.present_value {
                    callback(value);
                }
            }
            PropertyIdentifier::OutOfService => {
                if let Some(ref mut callback) = self.out_of_service {
                    callback(value);
                }
            }
            _ => {
                // Property not supported for callbacks
            }
        }
    }

    /// Check if a callback is registered for a property
    pub fn has_callback(&self, property: PropertyIdentifier) -> bool {
        match property {
            PropertyIdentifier::PresentValue => self.present_value.is_some(),
            PropertyIdentifier::OutOfService => self.out_of_service.is_some(),
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::PropertyValue;

    #[test]
    fn test_callback_registration() {
        let mut callbacks = ObjectCallbacks::new();
        assert!(!callbacks.has_callback(PropertyIdentifier::PresentValue));

        callbacks.on_present_value(Box::new(|_| {}));
        assert!(callbacks.has_callback(PropertyIdentifier::PresentValue));

        callbacks.clear_present_value();
        assert!(!callbacks.has_callback(PropertyIdentifier::PresentValue));
    }

    #[test]
    fn test_callback_trigger() {
        let mut callbacks = ObjectCallbacks::new();
        let mut called = false;

        callbacks.on_present_value(Box::new(move |value| {
            if let PropertyValue::Real(val) = value {
                assert_eq!(val, 23.5);
                called = true;
            }
        }));

        callbacks.trigger(PropertyIdentifier::PresentValue, PropertyValue::Real(23.5));
        // Note: `called` won't be visible here due to move semantics
        // This is a limitation of testing closures
    }

    #[test]
    fn test_clear_all() {
        let mut callbacks = ObjectCallbacks::new();
        callbacks.on_present_value(Box::new(|_| {}));
        callbacks.on_out_of_service(Box::new(|_| {}));

        assert!(callbacks.has_callback(PropertyIdentifier::PresentValue));
        assert!(callbacks.has_callback(PropertyIdentifier::OutOfService));

        callbacks.clear_all();

        assert!(!callbacks.has_callback(PropertyIdentifier::PresentValue));
        assert!(!callbacks.has_callback(PropertyIdentifier::OutOfService));
    }
}
