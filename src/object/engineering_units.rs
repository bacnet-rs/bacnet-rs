//! BACnet Engineering Units
//!
//! This module defines the complete set of engineering units as specified in
//! ISO 16484-5:2017 page 791 (ASHRAE Standard 135-2020).
//!
//! The enum includes all standard BACnet engineering units with their exact
//! numeric values for protocol compatibility.

macro_rules! generate_engineering_units {
    ($(#[$doc:meta])* $name:ident { $($variant:ident = $value:expr => $bacnet_name:literal $unit_symbol:literal,)+ }) => {
        pastey::paste! {
            $(#[$doc])*
            #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
            pub enum $name {
                $($variant,)*
                Reserved([<$name Value>]),
                Custom([<$name Value>]),
            }

            // Default should be NoUnits
            impl Default for $name {
                fn default() -> Self {
                    $name::NoUnits
                }
            }

            #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
            pub struct [<$name Value>] { value: u32 }

            impl [<$name Value>] {
                fn new(value: u32) -> Self {
                    Self { value }
                }

                pub fn value(&self) -> u32 {
                    self.value
                }
            }

            impl From<$name> for u32 {
                fn from(value: $name) -> Self {
                    match value {
                        $($name::$variant => $value,)*
                        $name::Reserved(value) => value.value(),
                        $name::Custom(value) => value.value(),
                    }
                }
            }

            impl From<u32> for $name {
                fn from(value: u32) -> Self {
                    match value {
                        $($value => $name::$variant,)*
                        value if (0..=255).contains(&value) || (47808..=49999).contains(&value) || (65536..).contains(&value) => {
                            $name::Reserved([<$name Value>]::new(value))
                        }
                        value if (256..=47807).contains(&value) || (50000..=65535).contains(&value) => {
                            $name::Custom([<$name Value>]::new(value))
                        }
                        _ => unreachable!(),
                    }
                }
            }

            impl $name {
                pub fn bacnet_name(&self) -> String {
                    match self {
                        $($name::$variant => $bacnet_name.to_string(),)*
                        $name::Reserved(v) => format!("Reserved({})", v.value()),
                        $name::Custom(v) => format!("Custom({})", v.value()),
                    }
                }

                pub fn unit_symbol(&self) -> &str {
                    match self {
                        $($name::$variant => $unit_symbol,)*
                        _ => "",
                    }
                }
            }
        }
    };
}

generate_engineering_units! {
    /// BACnet Engineering Units enumeration
    ///
    /// Represents all engineering units defined in the BACnet standard.
    /// Values 0-255 and 47808-49999 are reserved for definition by ASHRAE.
    /// Values 256-47807 and 50000-65535 may be used by others and are represented
    /// by the `Custom(EngineeringUnitsValue)` variant.
    EngineeringUnits {
        MetersPerSecondPerSecond = 166 => "meters-per-second-per-second" "m/s²",
        SquareMeters = 0 => "square-meters" "m²",
        SquareCentimeters = 116 => "square-centimeters" "cm²",
        SquareFeet = 1 => "square-feet" "ft²",
        SquareInches = 115 => "square-inches" "in²",
        Currency1 = 105 => "currency1" "",
        Currency2 = 106 => "currency2" "",
        Currency3 = 107 => "currency3" "",
        Currency4 = 108 => "currency4" "",
        Currency5 = 109 => "currency5" "",
        Currency6 = 110 => "currency6" "",
        Currency7 = 111 => "currency7" "",
        Currency8 = 112 => "currency8" "",
        Currency9 = 113 => "currency9" "",
        Currency10 = 114 => "currency10" "",
        BtuPerHourPerWatt = 47898 => "btu-per-hour-per-watt" "",
        BtuPerWattHourSeasonal = 47899 => "btu-per-watt-hour-seasonal" "",
        CoefficientOfPerformance = 47900 => "coefficient-of-performance" "",
        CoefficientOfPerformanceSeasonal = 47901 => "coefficient-of-performance-seasonal" "",
        KilowattPerTonRefrigeration = 47902 => "kilowatt-per-ton-refrigeration" "",
        LumensPerWatt = 47903 => "lumens-per-watt" "",
        Milliamperes = 2 => "milliamperes" "mA",
        Amperes = 3 => "amperes" "A",
        AmperesPerMeter = 167 => "amperes-per-meter" "A/m",
        AmperesPerSquareMeter = 168 => "amperes-per-square-meter" "A/m²",
        AmpereSquareMeters = 169 => "ampere-square-meters" "A·m²",
        Decibels = 199 => "decibels" "dB",
        DecibelsMillivolt = 200 => "decibels-millivolt" "dBmV",
        DecibelsVolt = 201 => "decibels-volt" "dBV",
        Farads = 170 => "farads" "F",
        Henrys = 171 => "henrys" "H",
        Ohms = 4 => "ohms" "Ω",
        OhmMeterSquaredPerMeter = 237 => "ohm-meter-squared-per-meter" "Ω·m²/m",
        OhmMeters = 172 => "ohm-meters" "Ω·m",
        Milliohms = 145 => "milliohms" "mΩ",
        Kiloohms = 122 => "kiloohms" "kΩ",
        Megaohms = 123 => "megohms" "MΩ",
        Microsiemens = 190 => "microsiemens" "µS",
        Millisiemens = 202 => "millisiemens" "mS",
        Siemens = 173 => "siemens" "S",
        SiemensPerMeter = 174 => "siemens-per-meter" "S/m",
        MicrosiemensPerCentimeter = 47909 => "microsiemens-per-centimeter" "",
        MillisiemensPerCentimeter = 47910 => "millisiemens-per-centimeter" "",
        MillisiemensPerMeter = 47911 => "millisiemens-per-meter" "",
        Teslas = 175 => "teslas" "T",
        Volts = 5 => "volts" "V",
        Millivolts = 124 => "millivolts" "mV",
        Kilovolts = 6 => "kilovolts" "kV",
        Megavolts = 7 => "megavolts" "MV",
        VoltAmperes = 8 => "volt-amperes" "VA",
        KilovoltAmperes = 9 => "kilovolt-amperes" "kVA",
        MegavoltAmperes = 10 => "megavolt-amperes" "MVA",
        VoltAmperesReactive = 11 => "volt-amperes-reactive" "var",
        KilovoltAmperesReactive = 12 => "kilovolt-amperes-reactive" "kvar",
        MegavoltAmperesReactive = 13 => "megavolt-amperes-reactive" "Mvar",
        VoltsPerKelvin = 176 => "volts-per-kelvin" "V/K",
        VoltsPerMeter = 177 => "volts-per-meter" "V/m",
        DegreesPhase = 14 => "degrees-phase" "°",
        PowerFactor = 15 => "power-factor" "cos φ",
        Webers = 178 => "webers" "Wb",
        AmpereSeconds = 238 => "ampere-seconds" "A·s",
        VoltAmpereHours = 239 => "volt-ampere-hours" "VAh",
        KilovoltAmpereHours = 240 => "kilovolt-ampere-hours" "kVAh",
        MegavoltAmpereHours = 241 => "megavolt-ampere-hours" "MVAh",
        VoltAmpereHoursReactive = 242 => "volt-ampere-hours-reactive" "varh",
        KilovoltAmpereHoursReactive = 243 => "kilovolt-ampere-hours-reactive" "kvarh",
        MegavoltAmpereHoursReactive = 244 => "megavolt-ampere-hours-reactive" "Mvarh",
        VoltSquareHours = 245 => "volt-square-hours" "V²·h",
        AmpereSquareHours = 246 => "ampere-square-hours" "A²·h",
        Joules = 16 => "joules" "J",
        Kilojoules = 17 => "kilojoules" "kJ",
        KilojoulesPerKilogram = 125 => "kilojoules-per-kilogram" "kJ/kg",
        Megajoules = 126 => "megajoules" "MJ",
        WattHours = 18 => "watt-hours" "W·h",
        KilowattHours = 19 => "kilowatt-hours" "kW·h",
        MegawattHours = 146 => "megawatt-hours" "MW·h",
        WattHoursReactive = 203 => "watt-hours-reactive" "var·h",
        KilowattHoursReactive = 204 => "kilowatt-hours-reactive" "kvar·h",
        MegawattHoursReactive = 205 => "megawatt-hours-reactive" "Mvar·h",
        Btus = 20 => "btus" "Btu",
        KiloBtus = 147 => "kilo-btus" "kBtu",
        MegaBtus = 148 => "mega-btus" "MBtu",
        Therms = 21 => "therms" "thm",
        TonHours = 22 => "ton-hours" "ton·h",
        ActiveEnergyPulseValue = 47918 => "active-energy-pulse-value" "",
        ReactiveEnergyPulseValue = 47919 => "reactive-energy-pulse-value" "",
        ApparentEnergyPulseValue = 47920 => "apparent-energy-pulse-value" "",
        VoltSquaredHourPulseValue = 47921 => "volt-squared-hour-pulse-value" "",
        AmpereSquaredHourPulseValue = 47922 => "ampere-squared-hour-pulse-value" "",
        JoulesPerKilogramDryAir = 23 => "joules-per-kilogram-dry-air" "J/kg dry air",
        KilojoulesPerKilogramDryAir = 149 => "kilojoules-per-kilogram-dry-air" "kJ/kg dry air",
        MegajoulesPerKilogramDryAir = 150 => "megajoules-per-kilogram-dry-air" "MJ/kg dry air",
        BtusPerPoundDryAir = 24 => "btus-per-pound-dry-air" "Btu/lb dry air",
        BtusPerPound = 117 => "btus-per-pound" "Btu/lb",
        JoulesPerKelvin = 127 => "joules-per-kelvin" "J/K",
        KilojoulesPerKelvin = 151 => "kilojoules-per-kelvin" "kJ/K",
        MegajoulesPerKelvin = 152 => "megajoules-per-kelvin" "MJ/K",
        JoulesPerKilogramKelvin = 128 => "joules-per-kilogram-kelvin" "J/(kg·K)",
        Newton = 153 => "newton" "N",
        CyclesPerHour = 25 => "cycles-per-hour" "cph",
        CyclesPerMinute = 26 => "cycles-per-minute" "cpm",
        Hertz = 27 => "hertz" "Hz",
        Kilohertz = 129 => "kilohertz" "kHz",
        Megahertz = 130 => "megahertz" "MHz",
        PerDay = 47823 => "per-day" "",
        PerHour = 131 => "per-hour" "/h",
        PerMillisecond = 47824 => "per-millisecond" "",
        GramsOfWaterPerKilogramDryAir = 28 => "grams-of-water-per-kilogram-dry-air" "g/kg dry air",
        GrainsOfWaterPerPoundDryAir = 47972 => "grains-of-water-per-pound-dry-air" "",
        PercentRelativeHumidity = 29 => "percent-relative-humidity" "% RH",
        Micrometers = 194 => "micrometers" "µm",
        Millimeters = 30 => "millimeters" "mm",
        Centimeters = 118 => "centimeters" "cm",
        Kilometers = 193 => "kilometers" "km",
        Meters = 31 => "meters" "m",
        Inches = 32 => "inches" "in",
        Feet = 33 => "feet" "ft",
        Yards = 47825 => "yards" "",
        Miles = 47826 => "miles" "",
        NauticalMiles = 47827 => "nautical-miles" "",
        Candelas = 179 => "candelas" "cd",
        CandelasPerSquareMeter = 180 => "candelas-per-square-meter" "cd/m²",
        WattsPerSquareFoot = 34 => "watts-per-square-foot" "W/ft²",
        WattsPerSquareMeter = 35 => "watts-per-square-meter" "W/m²",
        Lumens = 36 => "lumens" "lm",
        Luxes = 37 => "luxes" "lx",
        FootCandles = 38 => "foot-candles" "fc",
        Milligrams = 196 => "milligrams" "mg",
        Grams = 195 => "grams" "g",
        Kilograms = 39 => "kilograms" "kg",
        PoundsMass = 40 => "pounds-mass" "lbm",
        Tons = 41 => "tons" "ton",
        MetricTonnes = 47830 => "metric-tonnes" "",
        ShortTons = 47831 => "short-tons" "",
        LongTons = 47832 => "long-tons" "",
        GramsPerSecond = 154 => "grams-per-second" "g/s",
        GramsPerMinute = 155 => "grams-per-minute" "g/min",
        GramsPerHour = 47833 => "grams-per-hour" "",
        GramsPerDay = 47834 => "grams-per-day" "",
        KilogramsPerSecond = 42 => "kilograms-per-second" "kg/s",
        KilogramsPerMinute = 43 => "kilograms-per-minute" "kg/min",
        KilogramsPerHour = 44 => "kilograms-per-hour" "kg/h",
        KilogramsPerDay = 47835 => "kilograms-per-day" "",
        PoundsMassPerSecond = 119 => "pounds-mass-per-second" "lbm/s",
        PoundsMassPerMinute = 45 => "pounds-mass-per-minute" "lbm/min",
        PoundsMassPerHour = 46 => "pounds-mass-per-hour" "lbm/h",
        TonsPerHour = 156 => "tons-per-hour" "ton/h",
        ShortTonsPerSecond = 47836 => "short-tons-per-second" "",
        ShortTonsPerMinute = 47837 => "short-tons-per-minute" "",
        ShortTonsPerHour = 47838 => "short-tons-per-hour" "",
        ShortTonsPerDay = 47839 => "short-tons-per-day" "",
        MetricTonnesPerSecond = 47840 => "metric-tonnes-per-second" "",
        MetricTonnesPerMinute = 47841 => "metric-tonnes-per-minute" "",
        MetricTonnesPerHour = 47842 => "metric-tonnes-per-hour" "",
        MetricTonnesPerDay = 47843 => "metric-tonnes-per-day" "",
        LongTonsPerSecond = 47844 => "long-tons-per-second" "",
        LongTonsPerMinute = 47845 => "long-tons-per-minute" "",
        LongTonsPerHour = 47846 => "long-tons-per-hour" "",
        LongTonsPerDay = 47847 => "long-tons-per-day" "",
        Milliwatts = 132 => "milliwatts" "mW",
        Watts = 47 => "watts" "W",
        Kilowatts = 48 => "kilowatts" "kW",
        Megawatts = 49 => "megawatts" "MW",
        Gigawatts = 47924 => "gigawatts" "",
        BtusPerSecond = 47848 => "btus-per-second" "",
        BtusPerMinute = 47849 => "btus-per-minute" "",
        BtusPerHour = 50 => "btus-per-hour" "Btu/h",
        BtusPerDay = 47850 => "btus-per-day" "",
        KiloBtusPerSecond = 47851 => "kilo-btus-per-second" "",
        KiloBtusPerMinute = 47852 => "kilo-btus-per-minute" "",
        KiloBtusPerHour = 157 => "kilo-btus-per-hour" "kBtu/h",
        KiloBtusPerDay = 47853 => "kilo-btus-per-day" "",
        MegaBtusPerSecond = 47854 => "mega-btus-per-second" "",
        MegaBtusPerMinute = 47855 => "mega-btus-per-minute" "",
        MegaBtusPerHour = 47856 => "mega-btus-per-hour" "",
        MegaBtusPerDay = 47857 => "mega-btus-per-day" "",
        JoulesPerSecond = 47858 => "joules-per-second" "",
        JoulesPerMinute = 47859 => "joules-per-minute" "",
        JoulesPerHour = 247 => "joules-per-hour" "J/h",
        JoulesPerDay = 47860 => "joules-per-day" "",
        KilojoulesPerSecond = 47861 => "kilojoules-per-second" "",
        KilojoulesPerMinute = 47862 => "kilojoules-per-minute" "",
        KilojoulesPerHour = 47863 => "kilojoules-per-hour" "",
        KilojoulesPerDay = 47864 => "kilojoules-per-day" "",
        MegajoulesPerSecond = 47865 => "megajoules-per-second" "",
        MegajoulesPerMinute = 47866 => "megajoules-per-minute" "",
        MegajoulesPerHour = 47867 => "megajoules-per-hour" "",
        MegajoulesPerDay = 47868 => "megajoules-per-day" "",
        Horsepower = 51 => "horsepower" "hp",
        TonsRefrigeration = 52 => "tons-refrigeration" "ton ref",
        Pascals = 53 => "pascals" "Pa",
        Hectopascals = 133 => "hectopascals" "hPa",
        Kilopascals = 54 => "kilopascals" "kPa",
        Millibars = 134 => "millibars" "mbar",
        Bars = 55 => "bars" "bar",
        PoundsForcePerSquareInch = 56 => "pounds-force-per-square-inch" "psi",
        PoundsForcePerSquareInchAbsolute = 47907 => "pounds-force-per-square-inch-absolute" "",
        PoundsForcePerSquareInchGauge = 47908 => "pounds-force-per-square-inch-gauge" "",
        MillimetersOfWater = 206 => "millimeters-of-water" "mmH₂O",
        CentimetersOfWater = 57 => "centimeters-of-water" "cmH₂O",
        InchesOfWater = 58 => "inches-of-water" "inH₂O",
        MillimetersOfMercury = 59 => "millimeters-of-mercury" "mmHg",
        CentimetersOfMercury = 60 => "centimeters-of-mercury" "cmHg",
        InchesOfMercury = 61 => "inches-of-mercury" "inHg",
        DegreesCelsius = 62 => "degrees-celsius" "°C",
        DegreesCelsiusPerDay = 47869 => "degrees-celsius-per-day" "",
        DegreesCelsiusPerHour = 91 => "degrees-celsius-per-hour" "°C/h",
        DegreesCelsiusPerMinute = 92 => "degrees-celsius-per-minute" "°C/min",
        Kelvin = 63 => "kelvin" "K",
        KelvinPerHour = 181 => "kelvin-per-hour" "K/h",
        KelvinPerMinute = 182 => "kelvin-per-minute" "K/min",
        DegreesFahrenheit = 64 => "degrees-fahrenheit" "°F",
        DegreesFahrenheitPerDay = 47871 => "degrees-fahrenheit-per-day" "",
        DegreesFahrenheitPerHour = 93 => "degrees-fahrenheit-per-hour" "°F/h",
        DegreesFahrenheitPerMinute = 94 => "degrees-fahrenheit-per-minute" "°F/min",
        DegreeDaysCelsius = 65 => "degree-days-celsius" "°C·day",
        DegreeDaysFahrenheit = 66 => "degree-days-fahrenheit" "°F·day",
        DeltaDegreesCelsius = 47872 => "delta-degrees-celsius" "",
        DeltaDegreesFahrenheit = 120 => "delta-degrees-fahrenheit" "Δ°F",
        DeltaKelvin = 121 => "delta-kelvin" "ΔK",
        Years = 67 => "years" "yr",
        Months = 68 => "months" "mo",
        Weeks = 69 => "weeks" "wk",
        Days = 70 => "days" "day",
        Hours = 71 => "hours" "h",
        Minutes = 72 => "minutes" "min",
        Seconds = 73 => "seconds" "s",
        HundredthsSeconds = 158 => "hundredths-seconds" "cs",
        Milliseconds = 159 => "milliseconds" "ms",
        Microseconds = 47979 => "microseconds" "",
        Nanoseconds = 47980 => "nanoseconds" "",
        Picoseconds = 47981 => "picoseconds" "",
        NewtonMeters = 160 => "newton-meters" "N·m",
        PoundForceFeet = 47904 => "pound-force-feet" "",
        PoundForceInches = 47905 => "pound-force-inches" "",
        OunceForceInches = 47906 => "ounce-force-inches" "",
        MillimetersPerSecond = 161 => "millimeters-per-second" "mm/s",
        MillimetersPerMinute = 162 => "millimeters-per-minute" "mm/min",
        MetersPerSecond = 74 => "meters-per-second" "m/s",
        MetersPerMinute = 163 => "meters-per-minute" "m/min",
        MetersPerHour = 164 => "meters-per-hour" "m/h",
        KilometersPerHour = 75 => "kilometers-per-hour" "km/h",
        FeetPerSecond = 76 => "feet-per-second" "ft/s",
        FeetPerMinute = 77 => "feet-per-minute" "ft/min",
        MilesPerHour = 78 => "miles-per-hour" "mph",
        CubicFeet = 79 => "cubic-feet" "ft³",
        CubicMeters = 80 => "cubic-meters" "m³",
        ImperialGallons = 81 => "imperial-gallons" "gal (UK)",
        Milliliters = 197 => "milliliters" "mL",
        Liters = 82 => "liters" "L",
        UsGallons = 83 => "us-gallons" "gal (US)",
        MillionsOfUsGallons = 47912 => "millions-of-us-gallons" "",
        MillionsOfImperialGallons = 47913 => "millions-of-imperial-gallons" "",
        Volume1 = 47937 => "volume1" "",
        Volume2 = 47938 => "volume2" "",
        Volume3 = 47939 => "volume3" "",
        Volume4 = 47940 => "volume4" "",
        Volume5 = 47941 => "volume5" "",
        Volume6 = 47942 => "volume6" "",
        Volume7 = 47943 => "volume7" "",
        Volume8 = 47944 => "volume8" "",
        Volume9 = 47945 => "volume9" "",
        Volume10 = 47946 => "volume10" "",
        CubicFeetPerSecond = 142 => "cubic-feet-per-second" "ft³/s",
        CubicFeetPerMinute = 84 => "cubic-feet-per-minute" "cfm",
        MillionStandardCubicFeetPerMinute = 254 => "million-standard-cubic-feet-per-minute" "MMscfm",
        CubicFeetPerHour = 191 => "cubic-feet-per-hour" "cfh",
        CubicFeetPerDay = 248 => "cubic-feet-per-day" "cfd",
        StandardCubicFeetPerDay = 47808 => "standard-cubic-feet-per-day" "scfd",
        MillionStandardCubicFeetPerDay = 47809 => "million-standard-cubic-feet-per-day" "MMscfd",
        ThousandCubicFeetPerDay = 47810 => "thousand-cubic-feet-per-day" "kcfd",
        ThousandStandardCubicFeetPerDay = 47811 => "thousand-standard-cubic-feet-per-day" "kscfd",
        MillionCubicFeetPerMinute = 47873 => "million-cubic-feet-per-minute" "",
        MillionCubicFeetPerDay = 47874 => "million-cubic-feet-per-day" "",
        PoundsMassPerDay = 47812 => "pounds-mass-per-day" "lbm/day",
        CubicMetersPerSecond = 85 => "cubic-meters-per-second" "m³/s",
        CubicMetersPerMinute = 165 => "cubic-meters-per-minute" "m³/min",
        CubicMetersPerHour = 135 => "cubic-meters-per-hour" "m³/h",
        CubicMetersPerDay = 249 => "cubic-meters-per-day" "m³/day",
        ImperialGallonsPerSecond = 47875 => "imperial-gallons-per-second" "",
        ImperialGallonsPerMinute = 86 => "imperial-gallons-per-minute" "gpm (UK)",
        MillilitersPerSecond = 198 => "milliliters-per-second" "mL/s",
        MillilitersPerMinute = 47914 => "milliliters-per-minute" "",
        LitersPerSecond = 87 => "liters-per-second" "L/s",
        LitersPerMinute = 88 => "liters-per-minute" "L/min",
        LitersPerHour = 136 => "liters-per-hour" "L/h",
        LitersPerDay = 47878 => "liters-per-day" "",
        UsGallonsPerSecond = 47879 => "us-gallons-per-second" "",
        UsGallonsPerMinute = 89 => "us-gallons-per-minute" "gpm (US)",
        UsGallonsPerHour = 192 => "us-gallons-per-hour" "gph (US)",
        UsGallonsPerDay = 47880 => "us-gallons-per-day" "",
        CubicMeterPulseValue = 47923 => "cubic-meter-pulse-value" "",
        VolumetricFlow1 = 47947 => "volumetric-flow1" "",
        VolumetricFlow2 = 47948 => "volumetric-flow2" "",
        VolumetricFlow3 = 47949 => "volumetric-flow3" "",
        VolumetricFlow4 = 47950 => "volumetric-flow4" "",
        VolumetricFlow5 = 47951 => "volumetric-flow5" "",
        VolumetricFlow6 = 47952 => "volumetric-flow6" "",
        VolumetricFlow7 = 47953 => "volumetric-flow7" "",
        VolumetricFlow8 = 47954 => "volumetric-flow8" "",
        VolumetricFlow9 = 47955 => "volumetric-flow9" "",
        VolumetricFlow10 = 47956 => "volumetric-flow10" "",
        DegreesAngular = 90 => "degrees-angular" "°",
        JouleSeconds = 183 => "joule-seconds" "J·s",
        KilogramsPerCubicMeter = 186 => "kilograms-per-cubic-meter" "kg/m³",
        KilowattHoursPerSquareMeter = 137 => "kilowatt-hours-per-square-meter" "kWh/m²",
        KilowattHoursPerSquareFoot = 138 => "kilowatt-hours-per-square-foot" "kWh/ft²",
        WattHoursPerCubicMeter = 250 => "watt-hours-per-cubic-meter" "Wh/m³",
        JoulesPerCubicMeter = 251 => "joules-per-cubic-meter" "J/m³",
        MegajoulesPerSquareMeter = 139 => "megajoules-per-square-meter" "MJ/m²",
        MegajoulesPerSquareFoot = 140 => "megajoules-per-square-foot" "MJ/ft²",
        MolePercent = 252 => "mole-percent" "mol%",
        NoUnits = 95 => "no-units" "",
        NewtonSeconds = 187 => "newton-seconds" "N·s",
        NewtonsPerMeter = 188 => "newtons-per-meter" "N/m",
        PartsPerMillion = 96 => "parts-per-million" "ppm",
        PartsPerBillion = 97 => "parts-per-billion" "ppb",
        PascalSeconds = 253 => "pascal-seconds" "Pa·s",
        Percent = 98 => "percent" "%",
        PercentObscurationPerFoot = 143 => "percent-obscuration-per-foot" "%/ft",
        PercentObscurationPerMeter = 144 => "percent-obscuration-per-meter" "%/m",
        PercentPerSecond = 99 => "percent-per-second" "%/s",
        PercentPerMinute = 47881 => "percent-per-minute" "",
        PercentPerHour = 47882 => "percent-per-hour" "",
        PercentPerDay = 47883 => "percent-per-day" "",
        PsiPerDegreeFahrenheit = 102 => "psi-per-degree-fahrenheit" "psi/°F",
        Radians = 103 => "radians" "rad",
        RadiansPerSecond = 184 => "radians-per-second" "rad/s",
        RevolutionsPerMinute = 104 => "revolutions-per-minute" "rpm",
        SquareMetersPerNewton = 185 => "square-meters-per-newton" "m²/N",
        WattsPerMeterPerKelvin = 189 => "watts-per-meter-per-kelvin" "W/(m·K)",
        WattsPerSquareMeterPerKelvin = 141 => "watts-per-square-meter-per-kelvin" "W/(m²·K)",
        PerMille = 207 => "per-mille" "‰",
        PerMillion = 47884 => "per-million" "",
        PerBillion = 47885 => "per-billion" "",
        GramsPerGram = 208 => "grams-per-gram" "g/g",
        MilligramsPerGram = 211 => "milligrams-per-gram" "mg/g",
        KilogramsPerKilogram = 209 => "kilograms-per-kilogram" "kg/kg",
        GramsPerKilogram = 210 => "grams-per-kilogram" "g/kg",
        MilligramsPerKilogram = 212 => "milligrams-per-kilogram" "mg/kg",
        MicrogramsPerKilogram = 47888 => "micrograms-per-kilogram" "",
        NanogramsPerKilogram = 47889 => "nanograms-per-kilogram" "",
        GramsPerMilliliter = 213 => "grams-per-milliliter" "g/mL",
        MilligramsPerMilliliter = 47890 => "milligrams-per-milliliter" "",
        MicrogramsPerMilliliter = 47891 => "micrograms-per-milliliter" "",
        NanogramsPerMilliliter = 47892 => "nanograms-per-milliliter" "",
        KilogramsPerLiter = 47893 => "kilograms-per-liter" "",
        GramsPerLiter = 214 => "grams-per-liter" "g/L",
        MilligramsPerLiter = 215 => "milligrams-per-liter" "mg/L",
        MicrogramsPerLiter = 216 => "micrograms-per-liter" "µg/L",
        NanogramsPerLiter = 47894 => "nanograms-per-liter" "",
        GramsPerCubicMeter = 217 => "grams-per-cubic-meter" "g/m³",
        MilligramsPerCubicMeter = 218 => "milligrams-per-cubic-meter" "mg/m³",
        MicrogramsPerCubicMeter = 219 => "micrograms-per-cubic-meter" "µg/m³",
        NanogramsPerCubicMeter = 220 => "nanograms-per-cubic-meter" "ng/m³",
        GramsPerCubicCentimeter = 221 => "grams-per-cubic-centimeter" "g/cm³",
        MilligramsPerCubicCentimeter = 47895 => "milligrams-per-cubic-centimeter" "",
        MicrogramsPerCubicCentimeter = 47896 => "micrograms-per-cubic-centimeter" "",
        NanogramsPerCubicCentimeter = 47897 => "nanograms-per-cubic-centimeter" "",
        ParticlesPerCubicFoot = 47968 => "particles-per-cubic-foot" "",
        ParticlesPerCubicMeter = 47969 => "particles-per-cubic-meter" "",
        PicocuriesPerLiter = 47970 => "picocuries-per-liter" "",
        BecquerelsPerCubicMeter = 47971 => "becquerels-per-cubic-meter" "",
        Becquerels = 222 => "becquerels" "Bq",
        Kilobecquerels = 223 => "kilobecquerels" "kBq",
        Megabecquerels = 224 => "megabecquerels" "MBq",
        Gray = 225 => "gray" "Gy",
        Milligray = 226 => "milligray" "mGy",
        Microgray = 227 => "microgray" "µGy",
        Sieverts = 228 => "sieverts" "Sv",
        Millisieverts = 229 => "millisieverts" "mSv",
        Microsieverts = 230 => "microsieverts" "µSv",
        MicrosievertsPerHour = 231 => "microsieverts-per-hour" "µSv/h",
        Millirems = 47814 => "millirems" "mrem",
        MilliremsPerHour = 47815 => "millirems-per-hour" "mrem/h",
        DecibelsA = 232 => "decibels-a" "dBA",
        NephelometricTurbidityUnit = 233 => "nephelometric-turbidity-unit" "NTU",
        Ph = 234 => "ph" "pH",
        GramsPerSquareMeter = 235 => "grams-per-square-meter" "g/m²",
        MinutesPerKelvin = 236 => "minutes-per-kelvin" "min/K",
        DegreesLovibond = 47816 => "degrees-lovibond" "",
        AlcoholByVolume = 47817 => "alcohol-by-volume" "",
        InternationalBitteringUnits = 47818 => "international-bittering-units" "",
        EuropeanBitternessUnits = 47819 => "european-bitterness-units" "",
        DegreesPlato = 47820 => "degrees-plato" "",
        SpecificGravity = 47821 => "specific-gravity" "",
        EuropeanBrewingConvention = 47822 => "european-brewing-convention" "",
        MilsPerYear = 47915 => "mils-per-year" "",
        MillimetersPerYear = 47916 => "millimeters-per-year" "",
        PulsesPerMinute = 47917 => "pulses-per-minute" "",
        BitsPerSecond = 47929 => "bits-per-second" "",
        KilobitsPerSecond = 47930 => "kilobits-per-second" "",
        MegabitsPerSecond = 47931 => "megabits-per-second" "",
        GigabitsPerSecond = 47932 => "gigabits-per-second" "",
        BytesPerSecond = 47933 => "bytes-per-second" "",
        KilobytesPerSecond = 47934 => "kilobytes-per-second" "",
        MegabytesPerSecond = 47935 => "megabytes-per-second" "",
        GigabytesPerSecond = 47936 => "gigabytes-per-second" "",
        SiteUnit1 = 47958 => "site-unit1" "",
        SiteUnit2 = 47959 => "site-unit2" "",
        SiteUnit3 = 47960 => "site-unit3" "",
        SiteUnit4 = 47961 => "site-unit4" "",
        SiteUnit5 = 47962 => "site-unit5" "",
        SiteUnit6 = 47963 => "site-unit6" "",
        SiteUnit7 = 47964 => "site-unit7" "",
        SiteUnit8 = 47965 => "site-unit8" "",
        SiteUnit9 = 47966 => "site-unit9" "",
        SiteUnit10 = 47967 => "site-unit10" "",
        DegreeHoursCelsius = 47973 => "degree-hours-celsius" "",
        DegreeHoursFahrenheit = 47974 => "degree-hours-fahrenheit" "",
        DegreeMinutesCelsius = 47975 => "degree-minutes-celsius" "",
        DegreeMinutesFahrenheit = 47976 => "degree-minutes-fahrenheit" "",
        DegreeSecondsCelsius = 47977 => "degree-seconds-celsius" "",
        DegreeSecondsFahrenheit = 47978 => "degree-seconds-fahrenheit" "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_u32() {
        // Test standard ASHRAE units
        assert_eq!(EngineeringUnits::from(95), EngineeringUnits::NoUnits);
        assert_eq!(EngineeringUnits::from(62), EngineeringUnits::DegreesCelsius);
        assert_eq!(
            EngineeringUnits::from(64),
            EngineeringUnits::DegreesFahrenheit
        );

        // Test custom units (256-47807)
        let custom1 = EngineeringUnits::from(1000);
        assert!(matches!(custom1, EngineeringUnits::Custom(_)));
        assert_eq!(u32::from(custom1), 1000);

        // Test reserved units
        let reserved1 = EngineeringUnits::from(100);
        assert!(matches!(reserved1, EngineeringUnits::Reserved(_)));
        assert_eq!(u32::from(reserved1), 100);
    }

    #[test]
    fn test_to_u32() {
        assert_eq!(u32::from(EngineeringUnits::NoUnits), 95);
        assert_eq!(u32::from(EngineeringUnits::DegreesCelsius), 62);
        assert_eq!(
            u32::from(EngineeringUnits::Custom(EngineeringUnitsValue::new(1000))),
            1000
        );
    }

    #[test]
    fn test_roundtrip() {
        // Standard units should roundtrip
        let celsius = EngineeringUnits::DegreesCelsius;
        assert_eq!(EngineeringUnits::from(u32::from(celsius)), celsius);

        // Custom units should roundtrip
        let custom = EngineeringUnits::from(12345);
        assert_eq!(EngineeringUnits::from(u32::from(custom)), custom);
    }

    #[test]
    fn test_default() {
        assert_eq!(EngineeringUnits::default(), EngineeringUnits::NoUnits);
    }

    #[test]
    fn test_bacnet_name() {
        assert_eq!(
            EngineeringUnits::DegreesCelsius.bacnet_name(),
            "degrees-celsius"
        );
        assert_eq!(EngineeringUnits::NoUnits.bacnet_name(), "no-units");
        assert_eq!(EngineeringUnits::from(1000).bacnet_name(), "Custom(1000)");
    }

    #[test]
    fn test_unit_symbol() {
        assert_eq!(EngineeringUnits::DegreesCelsius.unit_symbol(), "°C");
        assert_eq!(EngineeringUnits::NoUnits.unit_symbol(), "");
        assert_eq!(EngineeringUnits::from(1000).unit_symbol(), "");
    }
}
