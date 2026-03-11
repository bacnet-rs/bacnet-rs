use crate::generate_custom_enum;

generate_custom_enum!(
    /// Event state enumeration
    EventState {
        Normal = 0,
        Fault = 1,
        Offnormal = 2,
        HighLimit = 3,
        LowLimit = 4,
        LifeSafetyAlarm = 5,
    },
    u16,
    64..=65535
);
