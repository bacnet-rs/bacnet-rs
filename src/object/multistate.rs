//! Multi-state Object Types Implementation
//!
//! This module implements the Multi-state Input, Multi-state Output, and Multi-state Value
//! object types as defined in ASHRAE 135. These objects represent multi-position values.

use crate::object::{
    event_state::EventState,
    intrinsic::{
        intrinsic_get, intrinsic_property_list, intrinsic_set, status_flags_bits, AlarmEvaluation,
        AlarmTrigger, IntrinsicReporting,
    },
    reliability::Reliability,
    write_priority_slot, BacnetObject, ObjectError, ObjectIdentifier, ObjectType,
    PropertyIdentifier, PropertyValue, Result,
};

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec, vec::Vec};

fn commandable_unsigned(value: PropertyValue) -> Result<Option<u32>> {
    match value {
        PropertyValue::Unsigned(value) => value
            .try_into()
            .map(Some)
            .map_err(|_| ObjectError::InvalidPropertyType),
        PropertyValue::Null => Ok(None),
        _ => Err(ObjectError::InvalidPropertyType),
    }
}

/// The fields every multi-state object shares, borrowed for a property read.
struct MultistateView<'a> {
    identifier: ObjectIdentifier,
    object_type: ObjectType,
    object_name: &'a str,
    description: &'a str,
    present_value: u32,
    overridden: bool,
    event_state: EventState,
    reliability: Reliability,
    out_of_service: bool,
    number_of_states: u32,
    state_text: &'a [String],
    alarm_values: &'a [u32],
    alarm: Option<&'a IntrinsicReporting>,
}

/// Read a property common to every multi-state object type.
///
/// Returns `None` for properties belonging to a single type (priority array,
/// relinquish default, device type) so callers fall through to their own arms.
fn shared_get(
    view: MultistateView<'_>,
    property: PropertyIdentifier,
) -> Option<Result<PropertyValue>> {
    let value = match property {
        PropertyIdentifier::ObjectIdentifier => PropertyValue::ObjectIdentifier(view.identifier),
        PropertyIdentifier::ObjectName => {
            PropertyValue::CharacterString(view.object_name.to_owned())
        }
        PropertyIdentifier::ObjectType => PropertyValue::Enumerated(u32::from(view.object_type)),
        PropertyIdentifier::PresentValue => PropertyValue::Unsigned(view.present_value.into()),
        PropertyIdentifier::Description => {
            PropertyValue::CharacterString(view.description.to_owned())
        }
        PropertyIdentifier::StatusFlags => PropertyValue::BitString(status_flags_bits(
            view.event_state,
            view.reliability,
            view.out_of_service,
            view.overridden,
        )),
        PropertyIdentifier::EventState => {
            PropertyValue::Enumerated(u16::from(view.event_state).into())
        }
        PropertyIdentifier::Reliability => PropertyValue::Enumerated(view.reliability.into()),
        PropertyIdentifier::OutOfService => PropertyValue::Boolean(view.out_of_service),
        PropertyIdentifier::NumberOfStates => PropertyValue::Unsigned(view.number_of_states.into()),
        PropertyIdentifier::StateText => PropertyValue::Array(
            view.state_text
                .iter()
                .cloned()
                .map(PropertyValue::CharacterString)
                .collect(),
        ),
        // Alarm_Values only exists once intrinsic reporting is configured.
        PropertyIdentifier::AlarmValues if view.alarm.is_some() => PropertyValue::List(
            view.alarm_values
                .iter()
                .map(|&state| PropertyValue::Unsigned(state.into()))
                .collect(),
        ),
        _ => return view.alarm.and_then(|alarm| intrinsic_get(alarm, property)),
    };

    Some(Ok(value))
}

/// The writable fields shared by every multi-state object type.
struct MultistateWritable<'a> {
    object_name: &'a mut String,
    description: &'a mut String,
    out_of_service: &'a mut bool,
    reliability: &'a mut Reliability,
    alarm_values: &'a mut Vec<u32>,
    alarm: Option<&'a mut IntrinsicReporting>,
}

/// Write a property common to every multi-state object type. `None` means the
/// property is not one this helper owns.
fn shared_set(
    fields: MultistateWritable<'_>,
    property: PropertyIdentifier,
    value: PropertyValue,
) -> Option<Result<()>> {
    let MultistateWritable {
        object_name,
        description,
        out_of_service,
        reliability,
        alarm_values,
        alarm,
    } = fields;

    let result = match property {
        PropertyIdentifier::ObjectName => match value {
            PropertyValue::CharacterString(name) => {
                *object_name = name;
                Ok(())
            }
            _ => Err(ObjectError::InvalidPropertyType),
        },
        PropertyIdentifier::Description => match value {
            PropertyValue::CharacterString(text) => {
                *description = text;
                Ok(())
            }
            _ => Err(ObjectError::InvalidPropertyType),
        },
        PropertyIdentifier::OutOfService => match value {
            PropertyValue::Boolean(flag) => {
                *out_of_service = flag;
                Ok(())
            }
            _ => Err(ObjectError::InvalidPropertyType),
        },
        // Writable so a simulated device can be driven into a fault state.
        PropertyIdentifier::Reliability => match value {
            PropertyValue::Enumerated(raw) => {
                *reliability = Reliability::from(raw);
                Ok(())
            }
            _ => Err(ObjectError::InvalidPropertyType),
        },
        PropertyIdentifier::AlarmValues => match value {
            PropertyValue::List(states) | PropertyValue::Array(states) => states
                .into_iter()
                .map(|state| match state {
                    PropertyValue::Unsigned(state) => {
                        u32::try_from(state).map_err(|_| ObjectError::InvalidPropertyType)
                    }
                    _ => Err(ObjectError::InvalidPropertyType),
                })
                .collect::<Result<Vec<u32>>>()
                .map(|states| *alarm_values = states),
            _ => Err(ObjectError::InvalidPropertyType),
        },
        _ => return alarm.and_then(|alarm| intrinsic_set(alarm, property, value)),
    };

    Some(result)
}

/// Properties every multi-state object exposes, plus the alarm properties when
/// intrinsic reporting is configured.
fn shared_property_list(alarm: Option<&IntrinsicReporting>) -> Vec<PropertyIdentifier> {
    let mut properties = vec![
        PropertyIdentifier::ObjectIdentifier,
        PropertyIdentifier::ObjectName,
        PropertyIdentifier::ObjectType,
        PropertyIdentifier::PresentValue,
        PropertyIdentifier::Description,
        PropertyIdentifier::StatusFlags,
        PropertyIdentifier::EventState,
        PropertyIdentifier::Reliability,
        PropertyIdentifier::OutOfService,
        PropertyIdentifier::NumberOfStates,
        PropertyIdentifier::StateText,
    ];

    if alarm.is_some() {
        properties.push(PropertyIdentifier::AlarmValues);
        properties.extend(intrinsic_property_list());
    }

    properties
}

/// Whether a shared property accepts writes.
fn shared_writable(property: PropertyIdentifier, alarm_configured: bool) -> bool {
    match property {
        PropertyIdentifier::ObjectName
        | PropertyIdentifier::Description
        | PropertyIdentifier::OutOfService
        | PropertyIdentifier::Reliability => true,
        PropertyIdentifier::AlarmValues
        | PropertyIdentifier::NotificationClass
        | PropertyIdentifier::TimeDelay
        | PropertyIdentifier::TimeDelayNormal
        | PropertyIdentifier::EventEnable
        | PropertyIdentifier::NotifyType
        | PropertyIdentifier::EventDetectionEnable => alarm_configured,
        _ => false,
    }
}

/// Run CHANGE_OF_STATE for a multi-state object.
///
/// The object is off-normal while Present_Value is one of Alarm_Values. An
/// unreliable object goes to fault instead: every intrinsic-reporting object
/// carries Reliability, and a fault takes precedence over the primary algorithm.
fn evaluate_multistate(
    present_value: u32,
    alarm_values: &[u32],
    reliability: Reliability,
    alarm: Option<&IntrinsicReporting>,
) -> Option<AlarmEvaluation> {
    let alarm = alarm?;
    if !alarm.event_detection_enable {
        return None;
    }

    if reliability != Reliability::NoFaultDetected {
        return Some(AlarmEvaluation {
            desired_state: EventState::Fault,
            trigger: AlarmTrigger::ReliabilityChange { reliability },
        });
    }

    let desired_state = if alarm_values.contains(&present_value) {
        EventState::Offnormal
    } else {
        EventState::Normal
    };

    Some(AlarmEvaluation {
        desired_state,
        trigger: AlarmTrigger::MultistateChange {
            new_state: present_value,
        },
    })
}

/// The intrinsic reporting trait methods shared by all multi-state object types.
macro_rules! multistate_intrinsic_methods {
    () => {
        fn intrinsic(&self) -> Option<&IntrinsicReporting> {
            self.alarm.as_ref()
        }

        fn intrinsic_mut(&mut self) -> Option<&mut IntrinsicReporting> {
            self.alarm.as_mut()
        }

        fn evaluate_alarm(&self) -> Option<AlarmEvaluation> {
            evaluate_multistate(
                self.present_value,
                &self.alarm_values,
                self.reliability,
                self.alarm.as_ref(),
            )
        }

        fn apply_event_state(&mut self, state: EventState) {
            self.event_state = state;
        }

        fn is_out_of_service(&self) -> bool {
            self.out_of_service
        }
    };
}

/// Multi-state Input object
#[derive(Debug, Clone)]
pub struct MultiStateInput {
    /// Object identifier
    pub identifier: ObjectIdentifier,
    /// Object name
    pub object_name: String,
    /// Present value (state 1..N)
    pub present_value: u32,
    /// Description
    pub description: String,
    /// Device type
    pub device_type: String,
    /// Whether an operator has overridden the point. The other Status_Flags
    /// bits are derived from Event_State, Reliability and Out_Of_Service.
    pub overridden: bool,
    /// Event state
    pub event_state: EventState,
    /// Reliability
    pub reliability: Reliability,
    /// Out of service
    pub out_of_service: bool,
    /// Number of states
    pub number_of_states: u32,
    /// State text array
    pub state_text: Vec<String>,
    /// States that put the object into an off-normal event state.
    pub alarm_values: Vec<u32>,
    /// Intrinsic reporting state; `None` when event detection is not configured.
    pub alarm: Option<IntrinsicReporting>,
}

/// Multi-state Output object
#[derive(Debug, Clone)]
pub struct MultiStateOutput {
    /// Object identifier
    pub identifier: ObjectIdentifier,
    /// Object name
    pub object_name: String,
    /// Present value (state 1..N)
    pub present_value: u32,
    /// Description
    pub description: String,
    /// Device type
    pub device_type: String,
    /// Whether an operator has overridden the point. The other Status_Flags
    /// bits are derived from Event_State, Reliability and Out_Of_Service.
    pub overridden: bool,
    /// Event state
    pub event_state: EventState,
    /// Reliability
    pub reliability: Reliability,
    /// Out of service
    pub out_of_service: bool,
    /// Number of states
    pub number_of_states: u32,
    /// State text array
    pub state_text: Vec<String>,
    /// Priority array (16 levels)
    pub priority_array: [Option<u32>; 16],
    /// Relinquish default
    pub relinquish_default: u32,
    /// States that put the object into an off-normal event state.
    pub alarm_values: Vec<u32>,
    /// Intrinsic reporting state; `None` when event detection is not configured.
    pub alarm: Option<IntrinsicReporting>,
}

/// Multi-state Value object
#[derive(Debug, Clone)]
pub struct MultiStateValue {
    /// Object identifier
    pub identifier: ObjectIdentifier,
    /// Object name
    pub object_name: String,
    /// Present value (state 1..N)
    pub present_value: u32,
    /// Description
    pub description: String,
    /// Whether an operator has overridden the point. The other Status_Flags
    /// bits are derived from Event_State, Reliability and Out_Of_Service.
    pub overridden: bool,
    /// Event state
    pub event_state: EventState,
    /// Reliability
    pub reliability: Reliability,
    /// Out of service
    pub out_of_service: bool,
    /// Number of states
    pub number_of_states: u32,
    /// State text array
    pub state_text: Vec<String>,
    /// Priority array (16 levels)
    pub priority_array: [Option<u32>; 16],
    /// Relinquish default
    pub relinquish_default: u32,
    /// States that put the object into an off-normal event state.
    pub alarm_values: Vec<u32>,
    /// Intrinsic reporting state; `None` when event detection is not configured.
    pub alarm: Option<IntrinsicReporting>,
}

impl MultiStateInput {
    /// Create a new Multi-state Input object
    pub fn new(instance: u32, object_name: String, number_of_states: u32) -> Self {
        let mut state_text = Vec::with_capacity(number_of_states as usize);
        for i in 1..=number_of_states {
            state_text.push(format!("State {}", i));
        }

        Self {
            identifier: ObjectIdentifier::new(ObjectType::MultiStateInput, instance),
            object_name,
            present_value: 1,
            description: String::new(),
            device_type: String::new(),
            overridden: false,
            event_state: EventState::Normal,
            reliability: Reliability::NoFaultDetected,
            out_of_service: false,
            number_of_states,
            state_text,
            alarm_values: Vec::new(),
            alarm: None,
        }
    }

    /// Enable intrinsic reporting, alarming on `alarm_values` via `notification_class`.
    pub fn with_intrinsic_reporting(
        mut self,
        notification_class: u32,
        alarm_values: Vec<u32>,
    ) -> Self {
        self.alarm_values = alarm_values;
        self.alarm = Some(IntrinsicReporting::new(notification_class));
        self
    }

    /// Set the present value (validates range)
    pub fn set_present_value(&mut self, value: u32) -> Result<()> {
        if value < 1 || value > self.number_of_states {
            return Err(ObjectError::InvalidValue(format!(
                "Value must be between 1 and {}",
                self.number_of_states
            )));
        }
        self.present_value = value;
        Ok(())
    }

    /// Get the current state text
    pub fn get_state_text(&self) -> Option<&str> {
        if self.present_value > 0 && self.present_value <= self.state_text.len() as u32 {
            Some(&self.state_text[(self.present_value - 1) as usize])
        } else {
            None
        }
    }

    /// Set state text for a specific state
    pub fn set_state_text(&mut self, state: u32, text: String) -> Result<()> {
        if state < 1 || state > self.number_of_states {
            return Err(ObjectError::InvalidValue(format!(
                "State must be between 1 and {}",
                self.number_of_states
            )));
        }
        self.state_text[(state - 1) as usize] = text;
        Ok(())
    }

    fn view(&self) -> MultistateView<'_> {
        MultistateView {
            identifier: self.identifier,
            object_type: ObjectType::MultiStateInput,
            object_name: &self.object_name,
            description: &self.description,
            present_value: self.present_value,
            overridden: self.overridden,
            event_state: self.event_state,
            reliability: self.reliability,
            out_of_service: self.out_of_service,
            number_of_states: self.number_of_states,
            state_text: &self.state_text,
            alarm_values: &self.alarm_values,
            alarm: self.alarm.as_ref(),
        }
    }
}

impl MultiStateOutput {
    /// Create a new Multi-state Output object
    pub fn new(instance: u32, object_name: String, number_of_states: u32) -> Self {
        let mut state_text = Vec::with_capacity(number_of_states as usize);
        for i in 1..=number_of_states {
            state_text.push(format!("State {}", i));
        }

        Self {
            identifier: ObjectIdentifier::new(ObjectType::MultiStateOutput, instance),
            object_name,
            present_value: 1,
            description: String::new(),
            device_type: String::new(),
            overridden: false,
            event_state: EventState::Normal,
            reliability: Reliability::NoFaultDetected,
            out_of_service: false,
            number_of_states,
            state_text,
            priority_array: [None; 16],
            relinquish_default: 1,
            alarm_values: Vec::new(),
            alarm: None,
        }
    }

    /// Enable intrinsic reporting, alarming on `alarm_values` via `notification_class`.
    pub fn with_intrinsic_reporting(
        mut self,
        notification_class: u32,
        alarm_values: Vec<u32>,
    ) -> Self {
        self.alarm_values = alarm_values;
        self.alarm = Some(IntrinsicReporting::new(notification_class));
        self
    }

    /// Write to priority array at specified priority level (1-16)
    pub fn write_priority(&mut self, priority: u8, value: Option<u32>) -> Result<()> {
        if let Some(val) = value {
            if val < 1 || val > self.number_of_states {
                return Err(ObjectError::InvalidValue(format!(
                    "Value must be between 1 and {}",
                    self.number_of_states
                )));
            }
        }

        self.present_value = write_priority_slot(
            &mut self.priority_array,
            priority,
            value,
            self.relinquish_default,
        )?;
        Ok(())
    }

    /// Get the effective priority level for current present value
    pub fn get_effective_priority(&self) -> Option<u8> {
        for (i, priority_value) in self.priority_array.iter().enumerate() {
            if priority_value.is_some() {
                return Some((i + 1) as u8);
            }
        }
        None
    }

    fn view(&self) -> MultistateView<'_> {
        MultistateView {
            identifier: self.identifier,
            object_type: ObjectType::MultiStateOutput,
            object_name: &self.object_name,
            description: &self.description,
            present_value: self.present_value,
            overridden: self.overridden,
            event_state: self.event_state,
            reliability: self.reliability,
            out_of_service: self.out_of_service,
            number_of_states: self.number_of_states,
            state_text: &self.state_text,
            alarm_values: &self.alarm_values,
            alarm: self.alarm.as_ref(),
        }
    }
}

impl MultiStateValue {
    /// Create a new Multi-state Value object
    pub fn new(instance: u32, object_name: String, number_of_states: u32) -> Self {
        let mut state_text = Vec::with_capacity(number_of_states as usize);
        for i in 1..=number_of_states {
            state_text.push(format!("State {}", i));
        }

        Self {
            identifier: ObjectIdentifier::new(ObjectType::MultiStateValue, instance),
            object_name,
            present_value: 1,
            description: String::new(),
            overridden: false,
            event_state: EventState::Normal,
            reliability: Reliability::NoFaultDetected,
            out_of_service: false,
            number_of_states,
            state_text,
            priority_array: [None; 16],
            relinquish_default: 1,
            alarm_values: Vec::new(),
            alarm: None,
        }
    }

    /// Enable intrinsic reporting, alarming on `alarm_values` via `notification_class`.
    pub fn with_intrinsic_reporting(
        mut self,
        notification_class: u32,
        alarm_values: Vec<u32>,
    ) -> Self {
        self.alarm_values = alarm_values;
        self.alarm = Some(IntrinsicReporting::new(notification_class));
        self
    }

    /// Write to priority array at specified priority level (1-16)
    pub fn write_priority(&mut self, priority: u8, value: Option<u32>) -> Result<()> {
        if let Some(val) = value {
            if val < 1 || val > self.number_of_states {
                return Err(ObjectError::InvalidValue(format!(
                    "Value must be between 1 and {}",
                    self.number_of_states
                )));
            }
        }

        self.present_value = write_priority_slot(
            &mut self.priority_array,
            priority,
            value,
            self.relinquish_default,
        )?;
        Ok(())
    }

    fn view(&self) -> MultistateView<'_> {
        MultistateView {
            identifier: self.identifier,
            object_type: ObjectType::MultiStateValue,
            object_name: &self.object_name,
            description: &self.description,
            present_value: self.present_value,
            overridden: self.overridden,
            event_state: self.event_state,
            reliability: self.reliability,
            out_of_service: self.out_of_service,
            number_of_states: self.number_of_states,
            state_text: &self.state_text,
            alarm_values: &self.alarm_values,
            alarm: self.alarm.as_ref(),
        }
    }
}

impl BacnetObject for MultiStateInput {
    fn identifier(&self) -> ObjectIdentifier {
        self.identifier
    }

    fn get_property(&self, property: PropertyIdentifier) -> Result<PropertyValue> {
        if property == PropertyIdentifier::DeviceType {
            return Ok(PropertyValue::CharacterString(self.device_type.clone()));
        }

        shared_get(self.view(), property).unwrap_or(Err(ObjectError::UnknownProperty))
    }

    fn set_property(&mut self, property: PropertyIdentifier, value: PropertyValue) -> Result<()> {
        shared_set(
            MultistateWritable {
                object_name: &mut self.object_name,
                description: &mut self.description,
                out_of_service: &mut self.out_of_service,
                reliability: &mut self.reliability,
                alarm_values: &mut self.alarm_values,
                alarm: self.alarm.as_mut(),
            },
            property,
            value,
        )
        .unwrap_or(Err(ObjectError::PropertyNotWritable))
    }

    fn is_property_writable(&self, property: PropertyIdentifier) -> bool {
        shared_writable(property, self.alarm.is_some())
    }

    fn property_list(&self) -> Vec<PropertyIdentifier> {
        let mut properties = shared_property_list(self.alarm.as_ref());
        properties.push(PropertyIdentifier::DeviceType);
        properties
    }

    /// An input reflects a sensor, so its Present_Value has no priority array
    /// and is simply what the source last read. States are numbered from 1.
    fn set_sourced_value(&mut self, value: PropertyValue) -> Result<()> {
        let PropertyValue::Unsigned(state) = value else {
            return Err(ObjectError::InvalidPropertyType);
        };
        let state = u32::try_from(state).map_err(|_| ObjectError::InvalidPropertyType)?;
        if !(1..=self.number_of_states).contains(&state) {
            return Err(ObjectError::InvalidValue(format!(
                "State must be 1-{}",
                self.number_of_states
            )));
        }
        self.present_value = state;
        Ok(())
    }

    multistate_intrinsic_methods!();
}

impl BacnetObject for MultiStateOutput {
    fn identifier(&self) -> ObjectIdentifier {
        self.identifier
    }

    fn get_property(&self, property: PropertyIdentifier) -> Result<PropertyValue> {
        match property {
            PropertyIdentifier::DeviceType => {
                Ok(PropertyValue::CharacterString(self.device_type.clone()))
            }
            PropertyIdentifier::PriorityArray => Ok(PropertyValue::Array(
                self.priority_array
                    .iter()
                    .map(|&slot| match slot {
                        Some(state) => PropertyValue::Unsigned(state.into()),
                        None => PropertyValue::Null,
                    })
                    .collect(),
            )),
            PropertyIdentifier::RelinquishDefault => {
                Ok(PropertyValue::Unsigned(self.relinquish_default.into()))
            }
            _ => shared_get(self.view(), property).unwrap_or(Err(ObjectError::UnknownProperty)),
        }
    }

    fn set_property(&mut self, property: PropertyIdentifier, value: PropertyValue) -> Result<()> {
        if property == PropertyIdentifier::PresentValue {
            return self.set_property_with_priority(property, value, None);
        }

        shared_set(
            MultistateWritable {
                object_name: &mut self.object_name,
                description: &mut self.description,
                out_of_service: &mut self.out_of_service,
                reliability: &mut self.reliability,
                alarm_values: &mut self.alarm_values,
                alarm: self.alarm.as_mut(),
            },
            property,
            value,
        )
        .unwrap_or(Err(ObjectError::PropertyNotWritable))
    }

    fn set_property_with_priority(
        &mut self,
        property: PropertyIdentifier,
        value: PropertyValue,
        priority: Option<u8>,
    ) -> Result<()> {
        if property != PropertyIdentifier::PresentValue {
            return self.set_property(property, value);
        }

        self.write_priority(priority.unwrap_or(16), commandable_unsigned(value)?)
    }

    fn is_property_writable(&self, property: PropertyIdentifier) -> bool {
        property == PropertyIdentifier::PresentValue
            || shared_writable(property, self.alarm.is_some())
    }

    fn property_list(&self) -> Vec<PropertyIdentifier> {
        let mut properties = shared_property_list(self.alarm.as_ref());
        properties.extend([
            PropertyIdentifier::DeviceType,
            PropertyIdentifier::PriorityArray,
            PropertyIdentifier::RelinquishDefault,
        ]);
        properties
    }

    multistate_intrinsic_methods!();
}

impl BacnetObject for MultiStateValue {
    fn identifier(&self) -> ObjectIdentifier {
        self.identifier
    }

    fn get_property(&self, property: PropertyIdentifier) -> Result<PropertyValue> {
        match property {
            PropertyIdentifier::PriorityArray => Ok(PropertyValue::Array(
                self.priority_array
                    .iter()
                    .map(|&slot| match slot {
                        Some(state) => PropertyValue::Unsigned(state.into()),
                        None => PropertyValue::Null,
                    })
                    .collect(),
            )),
            PropertyIdentifier::RelinquishDefault => {
                Ok(PropertyValue::Unsigned(self.relinquish_default.into()))
            }
            _ => shared_get(self.view(), property).unwrap_or(Err(ObjectError::UnknownProperty)),
        }
    }

    fn set_property(&mut self, property: PropertyIdentifier, value: PropertyValue) -> Result<()> {
        if property == PropertyIdentifier::PresentValue {
            return self.set_property_with_priority(property, value, None);
        }

        shared_set(
            MultistateWritable {
                object_name: &mut self.object_name,
                description: &mut self.description,
                out_of_service: &mut self.out_of_service,
                reliability: &mut self.reliability,
                alarm_values: &mut self.alarm_values,
                alarm: self.alarm.as_mut(),
            },
            property,
            value,
        )
        .unwrap_or(Err(ObjectError::PropertyNotWritable))
    }

    fn set_property_with_priority(
        &mut self,
        property: PropertyIdentifier,
        value: PropertyValue,
        priority: Option<u8>,
    ) -> Result<()> {
        if property != PropertyIdentifier::PresentValue {
            return self.set_property(property, value);
        }

        self.write_priority(priority.unwrap_or(16), commandable_unsigned(value)?)
    }

    fn is_property_writable(&self, property: PropertyIdentifier) -> bool {
        property == PropertyIdentifier::PresentValue
            || shared_writable(property, self.alarm.is_some())
    }

    fn property_list(&self) -> Vec<PropertyIdentifier> {
        let mut properties = shared_property_list(self.alarm.as_ref());
        properties.extend([
            PropertyIdentifier::PriorityArray,
            PropertyIdentifier::RelinquishDefault,
        ]);
        properties
    }

    multistate_intrinsic_methods!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multistate_input_creation() {
        let msi = MultiStateInput::new(1, "Mode Selector".to_string(), 5);
        assert_eq!(msi.identifier.instance, 1);
        assert_eq!(msi.object_name, "Mode Selector");
        assert_eq!(msi.number_of_states, 5);
        assert_eq!(msi.present_value, 1);
        assert_eq!(msi.state_text.len(), 5);
    }

    #[test]
    fn test_multistate_state_text() {
        let mut msi = MultiStateInput::new(1, "Mode".to_string(), 3);

        // Set custom state text
        msi.set_state_text(1, "OFF".to_string()).unwrap();
        msi.set_state_text(2, "AUTO".to_string()).unwrap();
        msi.set_state_text(3, "MANUAL".to_string()).unwrap();

        assert_eq!(msi.get_state_text(), Some("OFF"));

        msi.set_present_value(2).unwrap();
        assert_eq!(msi.get_state_text(), Some("AUTO"));

        // Test invalid state
        assert!(msi.set_present_value(4).is_err());
    }

    #[test]
    fn test_multistate_output_priority() {
        let mut mso = MultiStateOutput::new(1, "Sequence Control".to_string(), 4);

        // Write to priority 8
        mso.write_priority(8, Some(3)).unwrap();
        assert_eq!(mso.present_value, 3);
        assert_eq!(mso.get_effective_priority(), Some(8));

        // Write to higher priority 3
        mso.write_priority(3, Some(2)).unwrap();
        assert_eq!(mso.present_value, 2);
        assert_eq!(mso.get_effective_priority(), Some(3));

        // Test invalid value
        assert!(mso.write_priority(3, Some(5)).is_err());

        // Release priority 3
        mso.write_priority(3, None).unwrap();
        assert_eq!(mso.present_value, 3); // Back to priority 8 value
    }

    #[test]
    fn multistate_property_writes_preserve_priority_and_relinquish() {
        let mut output = MultiStateOutput::new(1, "Sequence Control".to_string(), 4);
        output
            .set_property_with_priority(
                PropertyIdentifier::PresentValue,
                PropertyValue::Unsigned(3),
                Some(2),
            )
            .unwrap();
        assert_eq!(output.priority_array[1], Some(3));
        output
            .set_property_with_priority(
                PropertyIdentifier::PresentValue,
                PropertyValue::Null,
                Some(2),
            )
            .unwrap();
        assert_eq!(output.priority_array[1], None);

        let mut value = MultiStateValue::new(2, "Operating Mode".to_string(), 4);
        value
            .set_property_with_priority(
                PropertyIdentifier::PresentValue,
                PropertyValue::Unsigned(4),
                Some(5),
            )
            .unwrap();
        assert_eq!(value.priority_array[4], Some(4));
        value
            .set_property_with_priority(
                PropertyIdentifier::PresentValue,
                PropertyValue::Null,
                Some(5),
            )
            .unwrap();
        assert_eq!(value.priority_array[4], None);
    }

    #[test]
    fn test_multistate_properties() {
        let mut msv = MultiStateValue::new(1, "Operating Mode".to_string(), 4);

        // Test property access
        let name = msv.get_property(PropertyIdentifier::ObjectName).unwrap();
        if let PropertyValue::CharacterString(n) = name {
            assert_eq!(n, "Operating Mode");
        } else {
            panic!("Expected CharacterString");
        }

        // Test property modification
        msv.set_property(PropertyIdentifier::PresentValue, PropertyValue::Unsigned(3))
            .unwrap();
        assert_eq!(msv.present_value, 3);
    }

    #[test]
    fn a_source_drives_an_input_and_its_state_is_range_checked() {
        let mut input = MultiStateInput::new(1, "Mode".to_string(), 4);

        input.set_sourced_value(PropertyValue::Unsigned(3)).unwrap();
        assert_eq!(input.present_value, 3);

        for out_of_range in [0, 5] {
            assert!(
                matches!(
                    input.set_sourced_value(PropertyValue::Unsigned(out_of_range)),
                    Err(ObjectError::InvalidValue(_))
                ),
                "state {out_of_range} is outside 1-4"
            );
        }
        assert_eq!(input.present_value, 3, "a rejected state changes nothing");
    }
}
