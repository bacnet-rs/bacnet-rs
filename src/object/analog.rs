//! Analog Object Types Implementation
//!
//! This module implements the Analog Input, Analog Output, and Analog Value object types
//! as defined in ASHRAE 135. These objects represent analog (continuous) values in BACnet.

use crate::object::{
    engineering_units::EngineeringUnits,
    event_state::EventState,
    intrinsic::{
        intrinsic_get, intrinsic_property_list, intrinsic_set, status_flags_for, AlarmEvaluation,
        AlarmTrigger, IntrinsicReporting,
    },
    reliability::Reliability,
    write_priority_slot, BacnetObject, ObjectError, ObjectIdentifier, ObjectType,
    PropertyIdentifier, PropertyValue, Result,
};

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec, vec::Vec};

fn commandable_real(value: PropertyValue) -> Result<Option<f32>> {
    match value {
        PropertyValue::Real(value) => Ok(Some(value)),
        PropertyValue::Null => Ok(None),
        _ => Err(ObjectError::InvalidPropertyType),
    }
}

/// Read an alarm property from an analog object.
///
/// Returns `None` when the object has no intrinsic reporting configured, or when
/// `property` is not an alarm property. An analog object with reporting but no
/// limits runs CHANGE_OF_RELIABILITY, so its limit properties do not exist.
fn analog_alarm_get(
    high_limit: Option<f32>,
    low_limit: Option<f32>,
    deadband: f32,
    alarm: Option<&IntrinsicReporting>,
    property: PropertyIdentifier,
) -> Option<Result<PropertyValue>> {
    let alarm = alarm?;

    let value = match property {
        PropertyIdentifier::HighLimit => match high_limit {
            Some(limit) => PropertyValue::Real(limit),
            None => return Some(Err(ObjectError::UnknownProperty)),
        },
        PropertyIdentifier::LowLimit => match low_limit {
            Some(limit) => PropertyValue::Real(limit),
            None => return Some(Err(ObjectError::UnknownProperty)),
        },
        PropertyIdentifier::Deadband => PropertyValue::Real(deadband),
        // Limit_Enable is ordered low-limit-enable, high-limit-enable.
        PropertyIdentifier::LimitEnable => {
            PropertyValue::BitString(vec![low_limit.is_some(), high_limit.is_some()])
        }
        _ => return intrinsic_get(alarm, property),
    };

    Some(Ok(value))
}

/// Write an alarm property on an analog object. `None` follows the same
/// convention as [`analog_alarm_get`].
fn analog_alarm_set(
    high_limit: &mut Option<f32>,
    low_limit: &mut Option<f32>,
    deadband: &mut f32,
    alarm: Option<&mut IntrinsicReporting>,
    property: PropertyIdentifier,
    value: PropertyValue,
) -> Option<Result<()>> {
    let alarm = alarm?;

    let result = match property {
        PropertyIdentifier::HighLimit => match value {
            PropertyValue::Real(limit) => {
                *high_limit = Some(limit);
                Ok(())
            }
            PropertyValue::Null => {
                *high_limit = None;
                Ok(())
            }
            _ => Err(ObjectError::InvalidPropertyType),
        },
        PropertyIdentifier::LowLimit => match value {
            PropertyValue::Real(limit) => {
                *low_limit = Some(limit);
                Ok(())
            }
            PropertyValue::Null => {
                *low_limit = None;
                Ok(())
            }
            _ => Err(ObjectError::InvalidPropertyType),
        },
        PropertyIdentifier::Deadband => match value {
            PropertyValue::Real(band) => {
                *deadband = band;
                Ok(())
            }
            _ => Err(ObjectError::InvalidPropertyType),
        },
        _ => return intrinsic_set(alarm, property, value),
    };

    Some(result)
}

/// Alarm properties an analog object exposes, given its configuration.
fn analog_alarm_property_list(
    high_limit: Option<f32>,
    low_limit: Option<f32>,
    alarm: Option<&IntrinsicReporting>,
) -> Vec<PropertyIdentifier> {
    if alarm.is_none() {
        return Vec::new();
    }

    let mut properties = intrinsic_property_list();
    if high_limit.is_some() || low_limit.is_some() {
        properties.extend([
            PropertyIdentifier::Deadband,
            PropertyIdentifier::LimitEnable,
        ]);
        if high_limit.is_some() {
            properties.push(PropertyIdentifier::HighLimit);
        }
        if low_limit.is_some() {
            properties.push(PropertyIdentifier::LowLimit);
        }
    }
    properties
}

/// Whether an analog alarm property accepts writes.
fn analog_alarm_writable(property: PropertyIdentifier, alarm_configured: bool) -> bool {
    alarm_configured
        && matches!(
            property,
            PropertyIdentifier::HighLimit
                | PropertyIdentifier::LowLimit
                | PropertyIdentifier::Deadband
                | PropertyIdentifier::NotificationClass
                | PropertyIdentifier::TimeDelay
                | PropertyIdentifier::TimeDelayNormal
                | PropertyIdentifier::EventEnable
                | PropertyIdentifier::NotifyType
                | PropertyIdentifier::EventDetectionEnable
        )
}

/// Run OUT_OF_RANGE, or CHANGE_OF_RELIABILITY when no limits are configured.
///
/// The deadband is hysteresis on the way back: once high-limit has tripped, the
/// value must fall below `high_limit - deadband` before the object returns to
/// normal (and symmetrically for low-limit). Without that, a value hovering on a
/// limit would emit a notification per evaluation.
fn evaluate_analog(
    present_value: f32,
    high_limit: Option<f32>,
    low_limit: Option<f32>,
    deadband: f32,
    reliability: Reliability,
    current_state: EventState,
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

    // No limits means this object only reports reliability changes.
    if high_limit.is_none() && low_limit.is_none() {
        return Some(AlarmEvaluation {
            desired_state: EventState::Normal,
            trigger: AlarmTrigger::ReliabilityChange { reliability },
        });
    }

    if let Some(limit) = high_limit {
        let tripped = if current_state == EventState::HighLimit {
            present_value > limit - deadband
        } else {
            present_value > limit
        };
        if tripped {
            return Some(AlarmEvaluation {
                desired_state: EventState::HighLimit,
                trigger: AlarmTrigger::OutOfRange {
                    exceeding_value: present_value,
                    exceeded_limit: limit,
                    deadband,
                },
            });
        }
    }

    if let Some(limit) = low_limit {
        let tripped = if current_state == EventState::LowLimit {
            present_value < limit + deadband
        } else {
            present_value < limit
        };
        if tripped {
            return Some(AlarmEvaluation {
                desired_state: EventState::LowLimit,
                trigger: AlarmTrigger::OutOfRange {
                    exceeding_value: present_value,
                    exceeded_limit: limit,
                    deadband,
                },
            });
        }
    }

    // Back in range: report the limit that was breached, which is the one the
    // object is returning from. Reporting the other limit would tell the
    // recipient a low-limit recovery cleared the high limit.
    let breached = if current_state == EventState::LowLimit {
        low_limit.or(high_limit)
    } else {
        high_limit.or(low_limit)
    };
    Some(AlarmEvaluation {
        desired_state: EventState::Normal,
        trigger: AlarmTrigger::OutOfRange {
            exceeding_value: present_value,
            exceeded_limit: breached.unwrap_or(present_value),
            deadband,
        },
    })
}

/// The intrinsic reporting trait methods shared by all analog object types.
macro_rules! analog_intrinsic_methods {
    () => {
        fn intrinsic(&self) -> Option<&IntrinsicReporting> {
            self.alarm.as_ref()
        }

        fn intrinsic_mut(&mut self) -> Option<&mut IntrinsicReporting> {
            self.alarm.as_mut()
        }

        fn evaluate_alarm(&self) -> Option<AlarmEvaluation> {
            evaluate_analog(
                self.present_value,
                self.high_limit,
                self.low_limit,
                self.deadband,
                self.reliability,
                self.event_state,
                self.alarm.as_ref(),
            )
        }

        fn apply_event_state(&mut self, state: EventState) {
            self.event_state = state;
            self.status_flags = status_flags_for(state, self.out_of_service);
        }

        fn is_out_of_service(&self) -> bool {
            self.out_of_service
        }
    };
}

/// Analog Input object
#[derive(Debug, Clone)]
pub struct AnalogInput {
    /// Object identifier
    pub identifier: ObjectIdentifier,
    /// Object name
    pub object_name: String,
    /// Present value
    pub present_value: f32,
    /// Description
    pub description: String,
    /// Device type
    pub device_type: String,
    /// Status flags (4 bits: in_alarm, fault, overridden, out_of_service)
    pub status_flags: u8,
    /// Event state
    pub event_state: EventState,
    /// Reliability
    pub reliability: Reliability,
    /// Out of service
    pub out_of_service: bool,
    /// Units
    pub units: EngineeringUnits,
    /// Minimum present value
    pub min_pres_value: Option<f32>,
    /// Maximum present value
    pub max_pres_value: Option<f32>,
    /// Resolution
    pub resolution: Option<f32>,
    /// COV increment
    pub cov_increment: Option<f32>,
    /// OUT_OF_RANGE high limit; `None` disables the high-limit check.
    pub high_limit: Option<f32>,
    /// OUT_OF_RANGE low limit; `None` disables the low-limit check.
    pub low_limit: Option<f32>,
    /// Hysteresis applied before returning to normal.
    pub deadband: f32,
    /// Intrinsic reporting state; `None` when event detection is not configured.
    pub alarm: Option<IntrinsicReporting>,
}

/// Analog Output object
#[derive(Debug, Clone)]
pub struct AnalogOutput {
    /// Object identifier
    pub identifier: ObjectIdentifier,
    /// Object name
    pub object_name: String,
    /// Present value
    pub present_value: f32,
    /// Description
    pub description: String,
    /// Device type
    pub device_type: String,
    /// Status flags
    pub status_flags: u8,
    /// Event state
    pub event_state: EventState,
    /// Reliability
    pub reliability: Reliability,
    /// Out of service
    pub out_of_service: bool,
    /// Units
    pub units: EngineeringUnits,
    /// Minimum present value
    pub min_pres_value: Option<f32>,
    /// Maximum present value
    pub max_pres_value: Option<f32>,
    /// Resolution
    pub resolution: Option<f32>,
    /// Priority array (16 levels)
    pub priority_array: [Option<f32>; 16],
    /// Relinquish default
    pub relinquish_default: f32,
    /// COV increment
    pub cov_increment: Option<f32>,
    /// OUT_OF_RANGE high limit; `None` disables the high-limit check.
    pub high_limit: Option<f32>,
    /// OUT_OF_RANGE low limit; `None` disables the low-limit check.
    pub low_limit: Option<f32>,
    /// Hysteresis applied before returning to normal.
    pub deadband: f32,
    /// Intrinsic reporting state; `None` when event detection is not configured.
    pub alarm: Option<IntrinsicReporting>,
}

/// Analog Value object
#[derive(Debug, Clone)]
pub struct AnalogValue {
    /// Object identifier
    pub identifier: ObjectIdentifier,
    /// Object name
    pub object_name: String,
    /// Present value
    pub present_value: f32,
    /// Description
    pub description: String,
    /// Status flags
    pub status_flags: u8,
    /// Event state
    pub event_state: EventState,
    /// Reliability
    pub reliability: Reliability,
    /// Out of service
    pub out_of_service: bool,
    /// Units
    pub units: EngineeringUnits,
    /// Priority array (16 levels)
    pub priority_array: [Option<f32>; 16],
    /// Relinquish default
    pub relinquish_default: f32,
    /// COV increment
    pub cov_increment: Option<f32>,
    /// OUT_OF_RANGE high limit; `None` disables the high-limit check.
    pub high_limit: Option<f32>,
    /// OUT_OF_RANGE low limit; `None` disables the low-limit check.
    pub low_limit: Option<f32>,
    /// Hysteresis applied before returning to normal.
    pub deadband: f32,
    /// Intrinsic reporting state; `None` when event detection is not configured.
    pub alarm: Option<IntrinsicReporting>,
}

// EngineeringUnits enum moved to src/object/engineering_units.rs for complete implementation

impl AnalogInput {
    /// Create a new Analog Input object
    pub fn new(instance: u32, object_name: String) -> Self {
        Self {
            identifier: ObjectIdentifier::new(ObjectType::AnalogInput, instance),
            object_name,
            present_value: 0.0,
            description: String::new(),
            device_type: String::new(),
            status_flags: 0,
            event_state: EventState::Normal,
            reliability: Reliability::NoFaultDetected,
            out_of_service: false,
            units: EngineeringUnits::NoUnits,
            min_pres_value: None,
            max_pres_value: None,
            resolution: None,
            cov_increment: None,
            high_limit: None,
            low_limit: None,
            deadband: 0.0,
            alarm: None,
        }
    }

    /// Enable CHANGE_OF_RELIABILITY reporting through `notification_class`.
    pub fn with_intrinsic_reporting(mut self, notification_class: u32) -> Self {
        self.alarm = Some(IntrinsicReporting::new(notification_class));
        self
    }

    /// Enable OUT_OF_RANGE reporting through `notification_class`.
    pub fn with_out_of_range_reporting(
        mut self,
        notification_class: u32,
        low_limit: Option<f32>,
        high_limit: Option<f32>,
        deadband: f32,
    ) -> Self {
        self.low_limit = low_limit;
        self.high_limit = high_limit;
        self.deadband = deadband;
        self.alarm = Some(IntrinsicReporting::new(notification_class));
        self
    }

    /// Set the present value
    pub fn set_present_value(&mut self, value: f32) {
        self.present_value = value;
    }

    /// Get status flags as individual booleans
    pub fn get_status_flags(&self) -> (bool, bool, bool, bool) {
        (
            (self.status_flags & 0x08) != 0, // in_alarm
            (self.status_flags & 0x04) != 0, // fault
            (self.status_flags & 0x02) != 0, // overridden
            (self.status_flags & 0x01) != 0, // out_of_service
        )
    }

    /// Set status flags from individual booleans
    pub fn set_status_flags(
        &mut self,
        in_alarm: bool,
        fault: bool,
        overridden: bool,
        out_of_service: bool,
    ) {
        self.status_flags = 0;
        if in_alarm {
            self.status_flags |= 0x08;
        }
        if fault {
            self.status_flags |= 0x04;
        }
        if overridden {
            self.status_flags |= 0x02;
        }
        if out_of_service {
            self.status_flags |= 0x01;
        }
    }
}

impl AnalogOutput {
    /// Create a new Analog Output object
    pub fn new(instance: u32, object_name: String) -> Self {
        Self {
            identifier: ObjectIdentifier::new(ObjectType::AnalogOutput, instance),
            object_name,
            present_value: 0.0,
            description: String::new(),
            device_type: String::new(),
            status_flags: 0,
            event_state: EventState::Normal,
            reliability: Reliability::NoFaultDetected,
            out_of_service: false,
            units: EngineeringUnits::NoUnits,
            min_pres_value: None,
            max_pres_value: None,
            resolution: None,
            priority_array: [None; 16],
            relinquish_default: 0.0,
            cov_increment: None,
            high_limit: None,
            low_limit: None,
            deadband: 0.0,
            alarm: None,
        }
    }

    /// Enable CHANGE_OF_RELIABILITY reporting through `notification_class`.
    pub fn with_intrinsic_reporting(mut self, notification_class: u32) -> Self {
        self.alarm = Some(IntrinsicReporting::new(notification_class));
        self
    }

    /// Enable OUT_OF_RANGE reporting through `notification_class`.
    pub fn with_out_of_range_reporting(
        mut self,
        notification_class: u32,
        low_limit: Option<f32>,
        high_limit: Option<f32>,
        deadband: f32,
    ) -> Self {
        self.low_limit = low_limit;
        self.high_limit = high_limit;
        self.deadband = deadband;
        self.alarm = Some(IntrinsicReporting::new(notification_class));
        self
    }

    /// Write to priority array at specified priority level (1-16)
    pub fn write_priority(&mut self, priority: u8, value: Option<f32>) -> Result<()> {
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
}

impl AnalogValue {
    /// Create a new Analog Value object
    pub fn new(instance: u32, object_name: String) -> Self {
        Self {
            identifier: ObjectIdentifier::new(ObjectType::AnalogValue, instance),
            object_name,
            present_value: 0.0,
            description: String::new(),
            status_flags: 0,
            event_state: EventState::Normal,
            reliability: Reliability::NoFaultDetected,
            out_of_service: false,
            units: EngineeringUnits::NoUnits,
            priority_array: [None; 16],
            relinquish_default: 0.0,
            cov_increment: None,
            high_limit: None,
            low_limit: None,
            deadband: 0.0,
            alarm: None,
        }
    }

    /// Enable CHANGE_OF_RELIABILITY reporting through `notification_class`.
    pub fn with_intrinsic_reporting(mut self, notification_class: u32) -> Self {
        self.alarm = Some(IntrinsicReporting::new(notification_class));
        self
    }

    /// Enable OUT_OF_RANGE reporting through `notification_class`.
    pub fn with_out_of_range_reporting(
        mut self,
        notification_class: u32,
        low_limit: Option<f32>,
        high_limit: Option<f32>,
        deadband: f32,
    ) -> Self {
        self.low_limit = low_limit;
        self.high_limit = high_limit;
        self.deadband = deadband;
        self.alarm = Some(IntrinsicReporting::new(notification_class));
        self
    }

    /// Write to priority array at specified priority level (1-16)
    pub fn write_priority(&mut self, priority: u8, value: Option<f32>) -> Result<()> {
        self.present_value = write_priority_slot(
            &mut self.priority_array,
            priority,
            value,
            self.relinquish_default,
        )?;
        Ok(())
    }
}

impl BacnetObject for AnalogInput {
    fn identifier(&self) -> ObjectIdentifier {
        self.identifier
    }

    fn get_property(&self, property: PropertyIdentifier) -> Result<PropertyValue> {
        match property {
            PropertyIdentifier::ObjectIdentifier => {
                Ok(PropertyValue::ObjectIdentifier(self.identifier))
            }
            PropertyIdentifier::ObjectName => {
                Ok(PropertyValue::CharacterString(self.object_name.clone()))
            }
            PropertyIdentifier::ObjectType => Ok(PropertyValue::Enumerated(u32::from(
                ObjectType::AnalogInput,
            ))),
            PropertyIdentifier::PresentValue => Ok(PropertyValue::Real(self.present_value)),
            PropertyIdentifier::Description => {
                Ok(PropertyValue::CharacterString(self.description.clone()))
            }
            PropertyIdentifier::DeviceType => {
                Ok(PropertyValue::CharacterString(self.device_type.clone()))
            }
            PropertyIdentifier::StatusFlags => Ok(PropertyValue::BitString(vec![
                self.status_flags & 0x08 != 0,
                self.status_flags & 0x04 != 0,
                self.status_flags & 0x02 != 0,
                self.status_flags & 0x01 != 0,
            ])),
            PropertyIdentifier::EventState => Ok(PropertyValue::Enumerated(
                u16::from(self.event_state).into(),
            )),
            PropertyIdentifier::Reliability => {
                Ok(PropertyValue::Enumerated(self.reliability.into()))
            }
            PropertyIdentifier::OutOfService => Ok(PropertyValue::Boolean(self.out_of_service)),
            PropertyIdentifier::Units => Ok(PropertyValue::Enumerated(self.units.into())),
            _ => analog_alarm_get(
                self.high_limit,
                self.low_limit,
                self.deadband,
                self.alarm.as_ref(),
                property,
            )
            .unwrap_or(Err(ObjectError::UnknownProperty)),
        }
    }

    fn set_property(&mut self, property: PropertyIdentifier, value: PropertyValue) -> Result<()> {
        match property {
            PropertyIdentifier::ObjectName => {
                if let PropertyValue::CharacterString(name) = value {
                    self.object_name = name;
                    Ok(())
                } else {
                    Err(ObjectError::InvalidPropertyType)
                }
            }
            PropertyIdentifier::Description => {
                if let PropertyValue::CharacterString(text) = value {
                    self.description = text;
                    Ok(())
                } else {
                    Err(ObjectError::InvalidPropertyType)
                }
            }
            // Writable so a simulated device can be driven into a fault state.
            PropertyIdentifier::Reliability => {
                if let PropertyValue::Enumerated(raw) = value {
                    self.reliability = Reliability::from(raw);
                    Ok(())
                } else {
                    Err(ObjectError::InvalidPropertyType)
                }
            }
            PropertyIdentifier::OutOfService => {
                if let PropertyValue::Boolean(oos) = value {
                    self.out_of_service = oos;
                    Ok(())
                } else {
                    Err(ObjectError::InvalidPropertyType)
                }
            }
            _ => analog_alarm_set(
                &mut self.high_limit,
                &mut self.low_limit,
                &mut self.deadband,
                self.alarm.as_mut(),
                property,
                value,
            )
            .unwrap_or(Err(ObjectError::PropertyNotWritable)),
        }
    }

    fn is_property_writable(&self, property: PropertyIdentifier) -> bool {
        matches!(
            property,
            PropertyIdentifier::ObjectName
                | PropertyIdentifier::Description
                | PropertyIdentifier::OutOfService
                | PropertyIdentifier::Reliability
        ) || analog_alarm_writable(property, self.alarm.is_some())
    }

    fn property_list(&self) -> Vec<PropertyIdentifier> {
        let mut properties = vec![
            PropertyIdentifier::ObjectIdentifier,
            PropertyIdentifier::ObjectName,
            PropertyIdentifier::ObjectType,
            PropertyIdentifier::PresentValue,
            PropertyIdentifier::Description,
            PropertyIdentifier::DeviceType,
            PropertyIdentifier::StatusFlags,
            PropertyIdentifier::EventState,
            PropertyIdentifier::Reliability,
            PropertyIdentifier::OutOfService,
            PropertyIdentifier::Units,
        ];
        properties.extend(analog_alarm_property_list(
            self.high_limit,
            self.low_limit,
            self.alarm.as_ref(),
        ));
        properties
    }

    /// An input reflects a sensor, so its Present_Value has no priority array
    /// and is simply what the source last read.
    fn set_sourced_value(&mut self, value: PropertyValue) -> Result<()> {
        match value {
            PropertyValue::Real(value) => {
                self.present_value = value;
                Ok(())
            }
            _ => Err(ObjectError::InvalidPropertyType),
        }
    }

    analog_intrinsic_methods!();
}

impl BacnetObject for AnalogOutput {
    fn identifier(&self) -> ObjectIdentifier {
        self.identifier
    }

    fn get_property(&self, property: PropertyIdentifier) -> Result<PropertyValue> {
        match property {
            PropertyIdentifier::ObjectIdentifier => {
                Ok(PropertyValue::ObjectIdentifier(self.identifier))
            }
            PropertyIdentifier::ObjectName => {
                Ok(PropertyValue::CharacterString(self.object_name.clone()))
            }
            PropertyIdentifier::ObjectType => Ok(PropertyValue::Enumerated(u32::from(
                ObjectType::AnalogOutput,
            ))),
            PropertyIdentifier::PresentValue => Ok(PropertyValue::Real(self.present_value)),
            PropertyIdentifier::Description => {
                Ok(PropertyValue::CharacterString(self.description.clone()))
            }
            PropertyIdentifier::DeviceType => {
                Ok(PropertyValue::CharacterString(self.device_type.clone()))
            }
            PropertyIdentifier::StatusFlags => Ok(PropertyValue::BitString(vec![
                self.status_flags & 0x08 != 0,
                self.status_flags & 0x04 != 0,
                self.status_flags & 0x02 != 0,
                self.status_flags & 0x01 != 0,
            ])),
            PropertyIdentifier::EventState => Ok(PropertyValue::Enumerated(
                u16::from(self.event_state).into(),
            )),
            PropertyIdentifier::Reliability => {
                Ok(PropertyValue::Enumerated(self.reliability.into()))
            }
            PropertyIdentifier::OutOfService => Ok(PropertyValue::Boolean(self.out_of_service)),
            PropertyIdentifier::Units => Ok(PropertyValue::Enumerated(self.units.into())),
            PropertyIdentifier::PriorityArray => {
                let array: Vec<PropertyValue> = self
                    .priority_array
                    .iter()
                    .map(|&v| match v {
                        Some(val) => PropertyValue::Real(val),
                        None => PropertyValue::Null,
                    })
                    .collect();
                Ok(PropertyValue::Array(array))
            }
            PropertyIdentifier::RelinquishDefault => {
                Ok(PropertyValue::Real(self.relinquish_default))
            }
            _ => analog_alarm_get(
                self.high_limit,
                self.low_limit,
                self.deadband,
                self.alarm.as_ref(),
                property,
            )
            .unwrap_or(Err(ObjectError::UnknownProperty)),
        }
    }

    fn set_property(&mut self, property: PropertyIdentifier, value: PropertyValue) -> Result<()> {
        match property {
            PropertyIdentifier::ObjectName => {
                if let PropertyValue::CharacterString(name) = value {
                    self.object_name = name;
                    Ok(())
                } else {
                    Err(ObjectError::InvalidPropertyType)
                }
            }
            PropertyIdentifier::Description => {
                if let PropertyValue::CharacterString(text) = value {
                    self.description = text;
                    Ok(())
                } else {
                    Err(ObjectError::InvalidPropertyType)
                }
            }
            // Writable so a simulated device can be driven into a fault state.
            PropertyIdentifier::Reliability => {
                if let PropertyValue::Enumerated(raw) = value {
                    self.reliability = Reliability::from(raw);
                    Ok(())
                } else {
                    Err(ObjectError::InvalidPropertyType)
                }
            }
            PropertyIdentifier::PresentValue => {
                self.set_property_with_priority(property, value, None)
            }
            PropertyIdentifier::OutOfService => {
                if let PropertyValue::Boolean(oos) = value {
                    self.out_of_service = oos;
                    Ok(())
                } else {
                    Err(ObjectError::InvalidPropertyType)
                }
            }
            _ => analog_alarm_set(
                &mut self.high_limit,
                &mut self.low_limit,
                &mut self.deadband,
                self.alarm.as_mut(),
                property,
                value,
            )
            .unwrap_or(Err(ObjectError::PropertyNotWritable)),
        }
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

        self.write_priority(priority.unwrap_or(16), commandable_real(value)?)
    }

    fn is_property_writable(&self, property: PropertyIdentifier) -> bool {
        matches!(
            property,
            PropertyIdentifier::ObjectName
                | PropertyIdentifier::Description
                | PropertyIdentifier::PresentValue
                | PropertyIdentifier::OutOfService
                | PropertyIdentifier::Reliability
        ) || analog_alarm_writable(property, self.alarm.is_some())
    }

    fn property_list(&self) -> Vec<PropertyIdentifier> {
        let mut properties = vec![
            PropertyIdentifier::ObjectIdentifier,
            PropertyIdentifier::ObjectName,
            PropertyIdentifier::ObjectType,
            PropertyIdentifier::PresentValue,
            PropertyIdentifier::Description,
            PropertyIdentifier::DeviceType,
            PropertyIdentifier::StatusFlags,
            PropertyIdentifier::EventState,
            PropertyIdentifier::Reliability,
            PropertyIdentifier::OutOfService,
            PropertyIdentifier::Units,
            PropertyIdentifier::PriorityArray,
            PropertyIdentifier::RelinquishDefault,
        ];
        properties.extend(analog_alarm_property_list(
            self.high_limit,
            self.low_limit,
            self.alarm.as_ref(),
        ));
        properties
    }

    analog_intrinsic_methods!();
}

impl BacnetObject for AnalogValue {
    fn identifier(&self) -> ObjectIdentifier {
        self.identifier
    }

    fn get_property(&self, property: PropertyIdentifier) -> Result<PropertyValue> {
        match property {
            PropertyIdentifier::ObjectIdentifier => {
                Ok(PropertyValue::ObjectIdentifier(self.identifier))
            }
            PropertyIdentifier::ObjectName => {
                Ok(PropertyValue::CharacterString(self.object_name.clone()))
            }
            PropertyIdentifier::ObjectType => Ok(PropertyValue::Enumerated(u32::from(
                ObjectType::AnalogValue,
            ))),
            PropertyIdentifier::PresentValue => Ok(PropertyValue::Real(self.present_value)),
            PropertyIdentifier::Description => {
                Ok(PropertyValue::CharacterString(self.description.clone()))
            }
            PropertyIdentifier::StatusFlags => Ok(PropertyValue::BitString(vec![
                self.status_flags & 0x08 != 0,
                self.status_flags & 0x04 != 0,
                self.status_flags & 0x02 != 0,
                self.status_flags & 0x01 != 0,
            ])),
            PropertyIdentifier::EventState => Ok(PropertyValue::Enumerated(
                u16::from(self.event_state).into(),
            )),
            PropertyIdentifier::Reliability => {
                Ok(PropertyValue::Enumerated(self.reliability.into()))
            }
            PropertyIdentifier::OutOfService => Ok(PropertyValue::Boolean(self.out_of_service)),
            PropertyIdentifier::Units => Ok(PropertyValue::Enumerated(self.units.into())),
            PropertyIdentifier::PriorityArray => {
                let array: Vec<PropertyValue> = self
                    .priority_array
                    .iter()
                    .map(|&v| match v {
                        Some(val) => PropertyValue::Real(val),
                        None => PropertyValue::Null,
                    })
                    .collect();
                Ok(PropertyValue::Array(array))
            }
            PropertyIdentifier::RelinquishDefault => {
                Ok(PropertyValue::Real(self.relinquish_default))
            }
            PropertyIdentifier::CovIncrement => self
                .cov_increment
                .map(PropertyValue::Real)
                .ok_or(ObjectError::UnknownProperty),
            _ => analog_alarm_get(
                self.high_limit,
                self.low_limit,
                self.deadband,
                self.alarm.as_ref(),
                property,
            )
            .unwrap_or(Err(ObjectError::UnknownProperty)),
        }
    }

    fn set_property(&mut self, property: PropertyIdentifier, value: PropertyValue) -> Result<()> {
        match property {
            PropertyIdentifier::ObjectName => {
                if let PropertyValue::CharacterString(name) = value {
                    self.object_name = name;
                    Ok(())
                } else {
                    Err(ObjectError::InvalidPropertyType)
                }
            }
            PropertyIdentifier::Description => {
                if let PropertyValue::CharacterString(text) = value {
                    self.description = text;
                    Ok(())
                } else {
                    Err(ObjectError::InvalidPropertyType)
                }
            }
            // Writable so a simulated device can be driven into a fault state.
            PropertyIdentifier::Reliability => {
                if let PropertyValue::Enumerated(raw) = value {
                    self.reliability = Reliability::from(raw);
                    Ok(())
                } else {
                    Err(ObjectError::InvalidPropertyType)
                }
            }
            PropertyIdentifier::PresentValue => {
                self.set_property_with_priority(property, value, None)
            }
            PropertyIdentifier::OutOfService => {
                if let PropertyValue::Boolean(oos) = value {
                    self.out_of_service = oos;
                    Ok(())
                } else {
                    Err(ObjectError::InvalidPropertyType)
                }
            }
            _ => analog_alarm_set(
                &mut self.high_limit,
                &mut self.low_limit,
                &mut self.deadband,
                self.alarm.as_mut(),
                property,
                value,
            )
            .unwrap_or(Err(ObjectError::PropertyNotWritable)),
        }
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

        self.write_priority(priority.unwrap_or(16), commandable_real(value)?)
    }

    fn is_property_writable(&self, property: PropertyIdentifier) -> bool {
        matches!(
            property,
            PropertyIdentifier::ObjectName
                | PropertyIdentifier::Description
                | PropertyIdentifier::PresentValue
                | PropertyIdentifier::OutOfService
                | PropertyIdentifier::Reliability
        ) || analog_alarm_writable(property, self.alarm.is_some())
    }

    fn property_list(&self) -> Vec<PropertyIdentifier> {
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
            PropertyIdentifier::Units,
            PropertyIdentifier::PriorityArray,
            PropertyIdentifier::RelinquishDefault,
        ];
        if self.cov_increment.is_some() {
            properties.push(PropertyIdentifier::CovIncrement);
        }
        properties.extend(analog_alarm_property_list(
            self.high_limit,
            self.low_limit,
            self.alarm.as_ref(),
        ));
        properties
    }

    analog_intrinsic_methods!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analog_input_creation() {
        let ai = AnalogInput::new(1, "Temperature Sensor".to_string());
        assert_eq!(ai.identifier.instance, 1);
        assert_eq!(ai.object_name, "Temperature Sensor");
        assert_eq!(ai.present_value, 0.0);
        assert!(!ai.out_of_service);
    }

    #[test]
    fn test_analog_output_priority() {
        let mut ao = AnalogOutput::new(1, "Damper Position".to_string());

        // Write to priority 8
        ao.write_priority(8, Some(75.0)).unwrap();
        assert_eq!(ao.present_value, 75.0);
        assert_eq!(ao.get_effective_priority(), Some(8));

        // Write to higher priority 3
        ao.write_priority(3, Some(50.0)).unwrap();
        assert_eq!(ao.present_value, 50.0);
        assert_eq!(ao.get_effective_priority(), Some(3));

        // Release priority 3
        ao.write_priority(3, None).unwrap();
        assert_eq!(ao.present_value, 75.0);
        assert_eq!(ao.get_effective_priority(), Some(8));

        // Release all priorities
        ao.write_priority(8, None).unwrap();
        assert_eq!(ao.present_value, ao.relinquish_default);
        assert_eq!(ao.get_effective_priority(), None);
    }

    #[test]
    fn analog_output_property_write_preserves_priority_and_relinquishes() {
        let mut output = AnalogOutput::new(1, "Damper Position".to_string());

        output
            .set_property_with_priority(
                PropertyIdentifier::PresentValue,
                PropertyValue::Real(50.0),
                Some(3),
            )
            .unwrap();
        assert_eq!(output.priority_array[2], Some(50.0));

        output
            .set_property_with_priority(
                PropertyIdentifier::PresentValue,
                PropertyValue::Null,
                Some(3),
            )
            .unwrap();
        assert_eq!(output.priority_array[2], None);
    }

    #[test]
    fn test_analog_object_properties() {
        let mut av = AnalogValue::new(1, "Test Value".to_string());

        // Test property access
        let name = av.get_property(PropertyIdentifier::ObjectName).unwrap();
        if let PropertyValue::CharacterString(n) = name {
            assert_eq!(n, "Test Value");
        } else {
            panic!("Expected CharacterString");
        }

        // Test property modification
        av.set_property(PropertyIdentifier::PresentValue, PropertyValue::Real(42.5))
            .unwrap();
        assert_eq!(av.present_value, 42.5);

        // Test writable properties
        assert!(av.is_property_writable(PropertyIdentifier::PresentValue));
        assert!(!av.is_property_writable(PropertyIdentifier::ObjectIdentifier));
    }

    #[test]
    fn test_status_flags() {
        let mut ai = AnalogInput::new(1, "Test".to_string());

        ai.set_status_flags(true, false, true, false);
        let (in_alarm, fault, overridden, out_of_service) = ai.get_status_flags();
        assert!(in_alarm);
        assert!(!fault);
        assert!(overridden);
        assert!(!out_of_service);
        assert_eq!(ai.status_flags, 0x0A); // 1010 in binary
    }

    /// The point of the hook: a host can drive an input whose Present_Value no
    /// network client is allowed to write.
    #[test]
    fn a_source_can_drive_an_input_that_clients_cannot_write() {
        let mut input = AnalogInput::new(1, "Outdoor temperature".to_string());

        assert!(!input.is_property_writable(PropertyIdentifier::PresentValue));
        assert!(matches!(
            input.set_property(PropertyIdentifier::PresentValue, PropertyValue::Real(5.0)),
            Err(ObjectError::PropertyNotWritable)
        ));

        input.set_sourced_value(PropertyValue::Real(5.0)).unwrap();

        assert_eq!(
            input
                .get_property(PropertyIdentifier::PresentValue)
                .unwrap(),
            PropertyValue::Real(5.0)
        );
        assert!(matches!(
            input.set_sourced_value(PropertyValue::Boolean(true)),
            Err(ObjectError::InvalidPropertyType)
        ));
    }

    /// A commandable object has a priority array, so a source driving it must go
    /// through the command path rather than around it.
    #[test]
    fn a_commandable_object_reports_the_hook_as_unsupported() {
        let mut value = AnalogValue::new(1, "Setpoint".to_string());

        assert!(matches!(
            value.set_sourced_value(PropertyValue::Real(5.0)),
            Err(ObjectError::OptionalFunctionalityNotSupported)
        ));
    }
}
