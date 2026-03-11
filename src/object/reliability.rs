use crate::generate_custom_enum;

generate_custom_enum!(
    /// Reliability enumeration
    Reliability {
        NoFaultDetected = 0,
        NoSensor = 1,
        OverRange = 2,
        UnderRange = 3,
        OpenLoop = 4,
        ShortedLoop = 5,
        NoOutput = 6,
        UnreliableOther = 7,
        ProcessError = 8,
        MultiStateFault = 9,
        ConfigurationError = 10,
    },
    u32,
    64..=65535
);
