//! BACnet Engineering Units
//!
//! This module defines the complete set of engineering units as specified in
//! ANSI/ASHRAE Standard 135-2024.
//!
//! The enum includes all standard BACnet engineering units with their exact
//! numeric values for protocol compatibility. Units are ordered by ID.

#[cfg(not(feature = "std"))]
use alloc::{
    format,
    string::{String, ToString},
};

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
    /// Represents all engineering units defined in the BACnet standard
    /// (ANSI/ASHRAE Standard 135-2024).
    /// Values 0-255 and 47808-49999 are reserved for definition by ASHRAE.
    /// Values 256-47807 and 50000-65535 may be used by others and are represented
    /// by the `Custom(EngineeringUnitsValue)` variant.
    EngineeringUnits {
        // 0-9: Area and electrical
        SquareMeters = 0 => "square-meters" "m²",
        SquareFeet = 1 => "square-feet" "ft²",
        Milliamperes = 2 => "milliamperes" "mA",
        Amperes = 3 => "amperes" "A",
        Ohms = 4 => "ohms" "Ω",
        Volts = 5 => "volts" "V",
        Kilovolts = 6 => "kilovolts" "kV",
        Megavolts = 7 => "megavolts" "MV",
        VoltAmperes = 8 => "volt-amperes" "VA",
        KilovoltAmperes = 9 => "kilovolt-amperes" "kVA",

        // 10-19: Power and energy
        MegavoltAmperes = 10 => "megavolt-amperes" "MVA",
        VoltAmperesReactive = 11 => "volt-amperes-reactive" "var",
        KilovoltAmperesReactive = 12 => "kilovolt-amperes-reactive" "kvar",
        MegavoltAmperesReactive = 13 => "megavolt-amperes-reactive" "Mvar",
        DegreesPhase = 14 => "degrees-phase" "°",
        PowerFactor = 15 => "power-factor" "cos φ",
        Joules = 16 => "joules" "J",
        Kilojoules = 17 => "kilojoules" "kJ",
        WattHours = 18 => "watt-hours" "W·h",
        KilowattHours = 19 => "kilowatt-hours" "kW·h",

        // 20-29: Energy and humidity
        Btus = 20 => "btus" "Btu",
        Therms = 21 => "therms" "thm",
        TonHours = 22 => "ton-hours" "ton·h",
        JoulesPerKilogramDryAir = 23 => "joules-per-kilogram-dry-air" "J/kg dry air",
        BtusPerPoundDryAir = 24 => "btus-per-pound-dry-air" "Btu/lb dry air",
        CyclesPerHour = 25 => "cycles-per-hour" "cph",
        CyclesPerMinute = 26 => "cycles-per-minute" "cpm",
        Hertz = 27 => "hertz" "Hz",
        GramsOfWaterPerKilogramDryAir = 28 => "grams-of-water-per-kilogram-dry-air" "g/kg dry air",
        PercentRelativeHumidity = 29 => "percent-relative-humidity" "% RH",

        // 30-39: Length, illumination, mass
        Millimeters = 30 => "millimeters" "mm",
        Meters = 31 => "meters" "m",
        Inches = 32 => "inches" "in",
        Feet = 33 => "feet" "ft",
        WattsPerSquareFoot = 34 => "watts-per-square-foot" "W/ft²",
        WattsPerSquareMeter = 35 => "watts-per-square-meter" "W/m²",
        Lumens = 36 => "lumens" "lm",
        Luxes = 37 => "luxes" "lx",
        FootCandles = 38 => "foot-candles" "fc",
        Kilograms = 39 => "kilograms" "kg",

        // 40-49: Mass and power
        PoundsMass = 40 => "pounds-mass" "lbm",
        Tons = 41 => "tons" "ton",
        KilogramsPerSecond = 42 => "kilograms-per-second" "kg/s",
        KilogramsPerMinute = 43 => "kilograms-per-minute" "kg/min",
        KilogramsPerHour = 44 => "kilograms-per-hour" "kg/h",
        PoundsMassPerMinute = 45 => "pounds-mass-per-minute" "lbm/min",
        PoundsMassPerHour = 46 => "pounds-mass-per-hour" "lbm/h",
        Watts = 47 => "watts" "W",
        Kilowatts = 48 => "kilowatts" "kW",
        Megawatts = 49 => "megawatts" "MW",

        // 50-59: Power and pressure
        BtusPerHour = 50 => "btus-per-hour" "Btu/h",
        Horsepower = 51 => "horsepower" "hp",
        TonsRefrigeration = 52 => "tons-refrigeration" "ton ref",
        Pascals = 53 => "pascals" "Pa",
        Kilopascals = 54 => "kilopascals" "kPa",
        Bars = 55 => "bars" "bar",
        PoundsForcePerSquareInch = 56 => "pounds-force-per-square-inch" "psi",
        CentimetersOfWater = 57 => "centimeters-of-water" "cmH₂O",
        InchesOfWater = 58 => "inches-of-water" "inH₂O",
        MillimetersOfMercury = 59 => "millimeters-of-mercury" "mmHg",

        // 60-69: Pressure and temperature
        CentimetersOfMercury = 60 => "centimeters-of-mercury" "cmHg",
        InchesOfMercury = 61 => "inches-of-mercury" "inHg",
        DegreesCelsius = 62 => "degrees-celsius" "°C",
        Kelvin = 63 => "kelvin" "K",
        DegreesFahrenheit = 64 => "degrees-fahrenheit" "°F",
        DegreeDaysCelsius = 65 => "degree-days-celsius" "°C·day",
        DegreeDaysFahrenheit = 66 => "degree-days-fahrenheit" "°F·day",
        Years = 67 => "years" "yr",
        Months = 68 => "months" "mo",
        Weeks = 69 => "weeks" "wk",

        // 70-79: Time and velocity
        Days = 70 => "days" "day",
        Hours = 71 => "hours" "h",
        Minutes = 72 => "minutes" "min",
        Seconds = 73 => "seconds" "s",
        MetersPerSecond = 74 => "meters-per-second" "m/s",
        KilometersPerHour = 75 => "kilometers-per-hour" "km/h",
        FeetPerSecond = 76 => "feet-per-second" "ft/s",
        FeetPerMinute = 77 => "feet-per-minute" "ft/min",
        MilesPerHour = 78 => "miles-per-hour" "mph",
        CubicFeet = 79 => "cubic-feet" "ft³",

        // 80-89: Volume and flow
        CubicMeters = 80 => "cubic-meters" "m³",
        ImperialGallons = 81 => "imperial-gallons" "gal (UK)",
        Liters = 82 => "liters" "L",
        UsGallons = 83 => "us-gallons" "gal (US)",
        CubicFeetPerMinute = 84 => "cubic-feet-per-minute" "cfm",
        CubicMetersPerSecond = 85 => "cubic-meters-per-second" "m³/s",
        ImperialGallonsPerMinute = 86 => "imperial-gallons-per-minute" "gpm (UK)",
        LitersPerSecond = 87 => "liters-per-second" "L/s",
        LitersPerMinute = 88 => "liters-per-minute" "L/min",
        UsGallonsPerMinute = 89 => "us-gallons-per-minute" "gpm (US)",

        // 90-99: Angular, temperature rates, misc
        DegreesAngular = 90 => "degrees-angular" "°",
        DegreesCelsiusPerHour = 91 => "degrees-celsius-per-hour" "°C/h",
        DegreesCelsiusPerMinute = 92 => "degrees-celsius-per-minute" "°C/min",
        DegreesFahrenheitPerHour = 93 => "degrees-fahrenheit-per-hour" "°F/h",
        DegreesFahrenheitPerMinute = 94 => "degrees-fahrenheit-per-minute" "°F/min",
        NoUnits = 95 => "no-units" "",
        PartsPerMillion = 96 => "parts-per-million" "ppm",
        PartsPerBillion = 97 => "parts-per-billion" "ppb",
        Percent = 98 => "percent" "%",
        PercentPerSecond = 99 => "percent-per-second" "%/s",

        // 100-109: Rates and currency
        PerMinute = 100 => "per-minute" "/min",
        PerSecond = 101 => "per-second" "/s",
        PsiPerDegreeFahrenheit = 102 => "psi-per-degree-fahrenheit" "psi/°F",
        Radians = 103 => "radians" "rad",
        RevolutionsPerMinute = 104 => "revolutions-per-minute" "rpm",
        Currency1 = 105 => "currency1" "",
        Currency2 = 106 => "currency2" "",
        Currency3 = 107 => "currency3" "",
        Currency4 = 108 => "currency4" "",
        Currency5 = 109 => "currency5" "",

        // 110-119: Currency, area, misc
        Currency6 = 110 => "currency6" "",
        Currency7 = 111 => "currency7" "",
        Currency8 = 112 => "currency8" "",
        Currency9 = 113 => "currency9" "",
        Currency10 = 114 => "currency10" "",
        SquareInches = 115 => "square-inches" "in²",
        SquareCentimeters = 116 => "square-centimeters" "cm²",
        BtusPerPound = 117 => "btus-per-pound" "Btu/lb",
        Centimeters = 118 => "centimeters" "cm",
        PoundsMassPerSecond = 119 => "pounds-mass-per-second" "lbm/s",

        // 120-129: Delta temps, resistance, voltage, energy
        DeltaDegreesFahrenheit = 120 => "delta-degrees-fahrenheit" "Δ°F",
        DeltaKelvin = 121 => "delta-kelvin" "ΔK",
        Kiloohms = 122 => "kilohms" "kΩ",
        Megaohms = 123 => "megohms" "MΩ",
        Millivolts = 124 => "millivolts" "mV",
        KilojoulesPerKilogram = 125 => "kilojoules-per-kilogram" "kJ/kg",
        Megajoules = 126 => "megajoules" "MJ",
        JoulesPerKelvin = 127 => "joules-per-kelvin" "J/K",
        JoulesPerKilogramKelvin = 128 => "joules-per-kilogram-per-kelvin" "J/(kg·K)",
        Kilohertz = 129 => "kilohertz" "kHz",

        // 130-139: Frequency, rates, pressure, flow, energy density
        Megahertz = 130 => "megahertz" "MHz",
        PerHour = 131 => "per-hour" "/h",
        Milliwatts = 132 => "milliwatts" "mW",
        Hectopascals = 133 => "hectopascals" "hPa",
        Millibars = 134 => "millibars" "mbar",
        CubicMetersPerHour = 135 => "cubic-meters-per-hour" "m³/h",
        LitersPerHour = 136 => "liters-per-hour" "L/h",
        KilowattHoursPerSquareMeter = 137 => "kilowatt-hours-per-square-meter" "kWh/m²",
        KilowattHoursPerSquareFoot = 138 => "kilowatt-hours-per-square-foot" "kWh/ft²",
        MegajoulesPerSquareMeter = 139 => "megajoules-per-square-meter" "MJ/m²",

        // 140-149: Energy density, flow, obscuration, resistance, energy
        MegajoulesPerSquareFoot = 140 => "megajoules-per-square-foot" "MJ/ft²",
        WattsPerSquareMeterPerKelvin = 141 => "watts-per-square-meter-per-kelvin" "W/(m²·K)",
        CubicFeetPerSecond = 142 => "cubic-feet-per-second" "ft³/s",
        PercentObscurationPerFoot = 143 => "percent-obscuration-per-foot" "%/ft",
        PercentObscurationPerMeter = 144 => "percent-obscuration-per-meter" "%/m",
        Milliohms = 145 => "milliohms" "mΩ",
        MegawattHours = 146 => "megawatt-hours" "MW·h",
        KiloBtus = 147 => "kilo-btus" "kBtu",
        MegaBtus = 148 => "mega-btus" "MBtu",
        KilojoulesPerKilogramDryAir = 149 => "kilojoules-per-kilogram-dry-air" "kJ/kg dry air",

        // 150-159: Energy, force, mass flow, time
        MegajoulesPerKilogramDryAir = 150 => "megajoules-per-kilogram-dry-air" "MJ/kg dry air",
        KilojoulesPerKelvin = 151 => "kilojoules-per-kelvin" "kJ/K",
        MegajoulesPerKelvin = 152 => "megajoules-per-kelvin" "MJ/K",
        Newton = 153 => "newton" "N",
        GramsPerSecond = 154 => "grams-per-second" "g/s",
        GramsPerMinute = 155 => "grams-per-minute" "g/min",
        TonsPerHour = 156 => "tons-per-hour" "ton/h",
        KiloBtusPerHour = 157 => "kilo-btus-per-hour" "kBtu/h",
        HundredthsSeconds = 158 => "hundredths-seconds" "cs",
        Milliseconds = 159 => "milliseconds" "ms",

        // 160-169: Torque, velocity, flow, acceleration, electromagnetic
        NewtonMeters = 160 => "newton-meters" "N·m",
        MillimetersPerSecond = 161 => "millimeters-per-second" "mm/s",
        MillimetersPerMinute = 162 => "millimeters-per-minute" "mm/min",
        MetersPerMinute = 163 => "meters-per-minute" "m/min",
        MetersPerHour = 164 => "meters-per-hour" "m/h",
        CubicMetersPerMinute = 165 => "cubic-meters-per-minute" "m³/min",
        MetersPerSecondPerSecond = 166 => "meters-per-second-per-second" "m/s²",
        AmperesPerMeter = 167 => "amperes-per-meter" "A/m",
        AmperesPerSquareMeter = 168 => "amperes-per-square-meter" "A/m²",
        AmpereSquareMeters = 169 => "ampere-square-meters" "A·m²",

        // 170-179: Electromagnetic
        Farads = 170 => "farads" "F",
        Henrys = 171 => "henrys" "H",
        OhmMeters = 172 => "ohm-meters" "Ω·m",
        Siemens = 173 => "siemens" "S",
        SiemensPerMeter = 174 => "siemens-per-meter" "S/m",
        Teslas = 175 => "teslas" "T",
        VoltsPerKelvin = 176 => "volts-per-kelvin" "V/K",
        VoltsPerMeter = 177 => "volts-per-meter" "V/m",
        Webers = 178 => "webers" "Wb",
        Candelas = 179 => "candelas" "cd",

        // 180-189: Photometric, thermal, mechanical
        CandelasPerSquareMeter = 180 => "candelas-per-square-meter" "cd/m²",
        KelvinPerHour = 181 => "kelvin-per-hour" "K/h",
        KelvinPerMinute = 182 => "kelvin-per-minute" "K/min",
        JouleSeconds = 183 => "joule-seconds" "J·s",
        RadiansPerSecond = 184 => "radians-per-second" "rad/s",
        SquareMetersPerNewton = 185 => "square-meters-per-newton" "m²/N",
        KilogramsPerCubicMeter = 186 => "kilograms-per-cubic-meter" "kg/m³",
        NewtonSeconds = 187 => "newton-seconds" "N·s",
        NewtonsPerMeter = 188 => "newtons-per-meter" "N/m",
        WattsPerMeterPerKelvin = 189 => "watts-per-meter-per-kelvin" "W/(m·K)",

        // 190-199: Conductance, flow, length, mass, volume, acoustics
        Microsiemens = 190 => "microsiemens" "µS",
        CubicFeetPerHour = 191 => "cubic-feet-per-hour" "cfh",
        UsGallonsPerHour = 192 => "us-gallons-per-hour" "gph (US)",
        Kilometers = 193 => "kilometers" "km",
        Micrometers = 194 => "micrometers" "µm",
        Grams = 195 => "grams" "g",
        Milligrams = 196 => "milligrams" "mg",
        Milliliters = 197 => "milliliters" "mL",
        MillilitersPerSecond = 198 => "milliliters-per-second" "mL/s",
        Decibels = 199 => "decibels" "dB",

        // 200-209: Acoustics, reactive energy, water, concentration
        DecibelsMillivolt = 200 => "decibels-millivolt" "dBmV",
        DecibelsVolt = 201 => "decibels-volt" "dBV",
        Millisiemens = 202 => "millisiemens" "mS",
        WattHoursReactive = 203 => "watt-reactive-hours" "var·h",
        KilowattHoursReactive = 204 => "kilowatt-reactive-hours" "kvar·h",
        MegawattHoursReactive = 205 => "megawatt-reactive-hours" "Mvar·h",
        MillimetersOfWater = 206 => "millimeters-of-water" "mmH₂O",
        PerMille = 207 => "per-mille" "‰",
        GramsPerGram = 208 => "grams-per-gram" "g/g",
        KilogramsPerKilogram = 209 => "kilograms-per-kilogram" "kg/kg",

        // 210-219: Concentration
        GramsPerKilogram = 210 => "grams-per-kilogram" "g/kg",
        MilligramsPerGram = 211 => "milligrams-per-gram" "mg/g",
        MilligramsPerKilogram = 212 => "milligrams-per-kilogram" "mg/kg",
        GramsPerMilliliter = 213 => "grams-per-milliliter" "g/mL",
        GramsPerLiter = 214 => "grams-per-liter" "g/L",
        MilligramsPerLiter = 215 => "milligrams-per-liter" "mg/L",
        MicrogramsPerLiter = 216 => "micrograms-per-liter" "µg/L",
        GramsPerCubicMeter = 217 => "grams-per-cubic-meter" "g/m³",
        MilligramsPerCubicMeter = 218 => "milligrams-per-cubic-meter" "mg/m³",
        MicrogramsPerCubicMeter = 219 => "micrograms-per-cubic-meter" "µg/m³",

        // 220-229: Concentration, radiation
        NanogramsPerCubicMeter = 220 => "nanograms-per-cubic-meter" "ng/m³",
        GramsPerCubicCentimeter = 221 => "grams-per-cubic-centimeter" "g/cm³",
        Becquerels = 222 => "becquerels" "Bq",
        Kilobecquerels = 223 => "kilobecquerels" "kBq",
        Megabecquerels = 224 => "megabecquerels" "MBq",
        Gray = 225 => "gray" "Gy",
        Milligray = 226 => "milligray" "mGy",
        Microgray = 227 => "microgray" "µGy",
        Sieverts = 228 => "sieverts" "Sv",
        Millisieverts = 229 => "millisieverts" "mSv",

        // 230-239: Radiation, environmental, misc
        Microsieverts = 230 => "microsieverts" "µSv",
        MicrosievertsPerHour = 231 => "microsieverts-per-hour" "µSv/h",
        DecibelsA = 232 => "decibels-a" "dBA",
        NephelometricTurbidityUnit = 233 => "nephelometric-turbidity-unit" "NTU",
        Ph = 234 => "pH" "pH",
        GramsPerSquareMeter = 235 => "grams-per-square-meter" "g/m²",
        MinutesPerKelvin = 236 => "minutes-per-kelvin" "min/K",
        OhmMeterSquaredPerMeter = 237 => "ohm-meter-squared-per-meter" "Ω·m²/m",
        AmpereSeconds = 238 => "ampere-seconds" "A·s",
        VoltAmpereHours = 239 => "volt-ampere-hours" "VAh",

        // 240-254: Electrical energy, flow, misc
        KilovoltAmpereHours = 240 => "kilovolt-ampere-hours" "kVAh",
        MegavoltAmpereHours = 241 => "megavolt-ampere-hours" "MVAh",
        VoltAmpereHoursReactive = 242 => "volt-ampere-hours-reactive" "varh",
        KilovoltAmpereHoursReactive = 243 => "kilovolt-ampere-hours-reactive" "kvarh",
        MegavoltAmpereHoursReactive = 244 => "megavolt-ampere-hours-reactive" "Mvarh",
        VoltSquareHours = 245 => "volt-square-hours" "V²·h",
        AmpereSquareHours = 246 => "ampere-square-hours" "A²·h",
        JoulesPerHour = 247 => "joules-per-hour" "J/h",
        CubicFeetPerDay = 248 => "cubic-feet-per-day" "cfd",
        CubicMetersPerDay = 249 => "cubic-meters-per-day" "m³/day",
        WattHoursPerCubicMeter = 250 => "watt-hours-per-cubic-meter" "Wh/m³",
        JoulesPerCubicMeter = 251 => "joules-per-cubic-meter" "J/m³",
        MolePercent = 252 => "mole-percent" "mol%",
        PascalSeconds = 253 => "pascal-seconds" "Pa·s",
        MillionStandardCubicFeetPerMinute = 254 => "million-standard-cubic-feet-per-minute" "MMscfm",

        // 47808-47812: Extended flow and mass
        StandardCubicFeetPerDay = 47808 => "standard-cubic-feet-per-day" "scfd",
        MillionStandardCubicFeetPerDay = 47809 => "million-standard-cubic-feet-per-day" "MMscfd",
        ThousandCubicFeetPerDay = 47810 => "thousand-cubic-feet-per-day" "kcfd",
        ThousandStandardCubicFeetPerDay = 47811 => "thousand-standard-cubic-feet-per-day" "kscfd",
        PoundsMassPerDay = 47812 => "pounds-mass-per-day" "lbm/day",

        // 47814-47824: Radiation, brewing, rates
        Millirems = 47814 => "millirems" "mrem",
        MilliremsPerHour = 47815 => "millirems-per-hour" "mrem/h",
        DegreesLovibond = 47816 => "degrees-lovibond" "",
        AlcoholByVolume = 47817 => "alcohol-by-volume" "",
        InternationalBitteringUnits = 47818 => "international-bittering-units" "",
        EuropeanBitternessUnits = 47819 => "european-bitterness-units" "",
        DegreesPlato = 47820 => "degrees-plato" "",
        SpecificGravity = 47821 => "specific-gravity" "",
        EuropeanBrewingConvention = 47822 => "european-brewing-convention" "",
        PerDay = 47823 => "per-day" "",
        PerMillisecond = 47824 => "per-millisecond" "",

        // 47825-47835: Distance, mass
        Yards = 47825 => "yards" "",
        Miles = 47826 => "miles" "",
        NauticalMiles = 47827 => "nautical-miles" "",
        Nanograms = 47828 => "nanograms" "ng",
        Micrograms = 47829 => "micrograms" "µg",
        MetricTonnes = 47830 => "metric-tonnes" "",
        ShortTons = 47831 => "short-tons" "",
        LongTons = 47832 => "long-tons" "",
        GramsPerHour = 47833 => "grams-per-hour" "",
        GramsPerDay = 47834 => "grams-per-day" "",
        KilogramsPerDay = 47835 => "kilograms-per-day" "",

        // 47836-47847: Mass flow rates (tons)
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

        // 47848-47868: Energy rates (BTU, joule, kilojoule, megajoule)
        BtusPerSecond = 47848 => "btus-per-second" "",
        BtusPerMinute = 47849 => "btus-per-minute" "",
        BtusPerDay = 47850 => "btus-per-day" "",
        KiloBtusPerSecond = 47851 => "kilo-btus-per-second" "",
        KiloBtusPerMinute = 47852 => "kilo-btus-per-minute" "",
        KiloBtusPerDay = 47853 => "kilo-btus-per-day" "",
        MegaBtusPerSecond = 47854 => "mega-btus-per-second" "",
        MegaBtusPerMinute = 47855 => "mega-btus-per-minute" "",
        MegaBtusPerHour = 47856 => "mega-btus-per-hour" "",
        MegaBtusPerDay = 47857 => "mega-btus-per-day" "",
        JoulesPerSecond = 47858 => "joules-per-second" "",
        JoulesPerMinute = 47859 => "joules-per-minute" "",
        JoulesPerDay = 47860 => "joules-per-day" "",
        KilojoulesPerSecond = 47861 => "kilojoules-per-second" "",
        KilojoulesPerMinute = 47862 => "kilojoules-per-minute" "",
        KilojoulesPerHour = 47863 => "kilojoules-per-hour" "",
        KilojoulesPerDay = 47864 => "kilojoules-per-day" "",
        MegajoulesPerSecond = 47865 => "megajoules-per-second" "",
        MegajoulesPerMinute = 47866 => "megajoules-per-minute" "",
        MegajoulesPerHour = 47867 => "megajoules-per-hour" "",
        MegajoulesPerDay = 47868 => "megajoules-per-day" "",

        // 47869-47880: Temperature rates, flow rates
        DegreesCelsiusPerDay = 47869 => "degrees-celsius-per-day" "",
        KelvinPerDay = 47870 => "kelvin-per-day" "",
        DegreesFahrenheitPerDay = 47871 => "degrees-fahrenheit-per-day" "",
        DeltaDegreesCelsius = 47872 => "delta-degrees-celsius" "",
        MillionCubicFeetPerMinute = 47873 => "million-cubic-feet-per-minute" "",
        MillionCubicFeetPerDay = 47874 => "million-cubic-feet-per-day" "",
        ImperialGallonsPerSecond = 47875 => "imperial-gallons-per-second" "",
        ImperialGallonsPerHour = 47876 => "imperial-gallons-per-hour" "",
        ImperialGallonsPerDay = 47877 => "imperial-gallons-per-day" "",
        LitersPerDay = 47878 => "liters-per-day" "",
        UsGallonsPerSecond = 47879 => "us-gallons-per-second" "",
        UsGallonsPerDay = 47880 => "us-gallons-per-day" "",

        // 47881-47897: Percent rates, concentration
        PercentPerMinute = 47881 => "percent-per-minute" "",
        PercentPerHour = 47882 => "percent-per-hour" "",
        PercentPerDay = 47883 => "percent-per-day" "",
        PerMillion = 47884 => "per-million" "",
        PerBillion = 47885 => "per-billion" "",
        MicrogramsPerGram = 47886 => "micrograms-per-gram" "",
        NanogramsPerGram = 47887 => "nanograms-per-gram" "",
        MicrogramsPerKilogram = 47888 => "micrograms-per-kilogram" "",
        NanogramsPerKilogram = 47889 => "nanograms-per-kilogram" "",
        MilligramsPerMilliliter = 47890 => "milligrams-per-milliliter" "",
        MicrogramsPerMilliliter = 47891 => "micrograms-per-milliliter" "",
        NanogramsPerMilliliter = 47892 => "nanograms-per-milliliter" "",
        KilogramsPerLiter = 47893 => "kilograms-per-liter" "",
        NanogramsPerLiter = 47894 => "nanograms-per-liter" "",
        MilligramsPerCubicCentimeter = 47895 => "milligrams-per-cubic-centimeter" "",
        MicrogramsPerCubicCentimeter = 47896 => "micrograms-per-cubic-centimeter" "",
        NanogramsPerCubicCentimeter = 47897 => "nanograms-per-cubic-centimeter" "",

        // 47898-47911: Efficiency, force, conductance
        BtuPerHourPerWatt = 47898 => "btu-per-hour-per-watt" "",
        BtuPerWattHourSeasonal = 47899 => "btu-per-watt-hour-seasonal" "",
        CoefficientOfPerformance = 47900 => "coefficient-of-performance" "",
        CoefficientOfPerformanceSeasonal = 47901 => "coefficient-of-performance-seasonal" "",
        KilowattPerTonRefrigeration = 47902 => "kilowatt-per-ton-refrigeration" "",
        LumensPerWatt = 47903 => "lumens-per-watt" "",
        PoundForceFeet = 47904 => "pound-force-feet" "",
        PoundForceInches = 47905 => "pound-force-inches" "",
        OunceForceInches = 47906 => "ounce-force-inches" "",
        PoundsForcePerSquareInchAbsolute = 47907 => "pounds-force-per-square-inch-absolute" "",
        PoundsForcePerSquareInchGauge = 47908 => "pounds-force-per-square-inch-gauge" "",
        MicrosiemensPerCentimeter = 47909 => "microsiemens-per-centimeter" "",
        MillisiemensPerCentimeter = 47910 => "millisiemens-per-centimeter" "",
        MillisiemensPerMeter = 47911 => "millisiemens-per-meter" "",

        // 47912-47923: Volume, corrosion, pulses
        MillionsOfUsGallons = 47912 => "millions-of-us-gallons" "",
        MillionsOfImperialGallons = 47913 => "millions-of-imperial-gallons" "",
        MillilitersPerMinute = 47914 => "milliliters-per-minute" "",
        MilsPerYear = 47915 => "mils-per-year" "",
        MillimetersPerYear = 47916 => "millimeters-per-year" "",
        PulsesPerMinute = 47917 => "pulses-per-minute" "",
        ActiveEnergyPulseValue = 47918 => "active-energy-pulse-value" "",
        ReactiveEnergyPulseValue = 47919 => "reactive-energy-pulse-value" "",
        ApparentEnergyPulseValue = 47920 => "apparent-energy-pulse-value" "",
        VoltSquaredHourPulseValue = 47921 => "volt-squared-hour-pulse-value" "",
        AmpereSquaredHourPulseValue = 47922 => "ampere-squared-hour-pulse-value" "",
        CubicMeterPulseValue = 47923 => "cubic-meter-pulse-value" "",

        // 47924-47936: Large power/energy, data rates
        Gigawatts = 47924 => "gigawatts" "",
        Gigajoules = 47925 => "gigajoules" "GJ",
        Terajoules = 47926 => "terajoules" "TJ",
        GigawattHours = 47927 => "gigawatt-hours" "GW·h",
        GigawattReactiveHours = 47928 => "gigawatt-reactive-hours" "Gvar·h",
        BitsPerSecond = 47929 => "bits-per-second" "",
        KilobitsPerSecond = 47930 => "kilobits-per-second" "",
        MegabitsPerSecond = 47931 => "megabits-per-second" "",
        GigabitsPerSecond = 47932 => "gigabits-per-second" "",
        BytesPerSecond = 47933 => "bytes-per-second" "",
        KilobytesPerSecond = 47934 => "kilobytes-per-second" "",
        MegabytesPerSecond = 47935 => "megabytes-per-second" "",
        GigabytesPerSecond = 47936 => "gigabytes-per-second" "",

        // 47937-47956: Custom volume and flow
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

        // 47958-47981: Site units, particles, radiation, degree-time, sub-second time
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
        ParticlesPerCubicFoot = 47968 => "particles-per-cubic-foot" "",
        ParticlesPerCubicMeter = 47969 => "particles-per-cubic-meter" "",
        PicocuriesPerLiter = 47970 => "picocuries-per-liter" "",
        BecquerelsPerCubicMeter = 47971 => "becquerels-per-cubic-meter" "",
        GrainsOfWaterPerPoundDryAir = 47972 => "grains-of-water-per-pound-dry-air" "",
        DegreeHoursCelsius = 47973 => "degree-hours-celsius" "",
        DegreeHoursFahrenheit = 47974 => "degree-hours-fahrenheit" "",
        DegreeMinutesCelsius = 47975 => "degree-minutes-celsius" "",
        DegreeMinutesFahrenheit = 47976 => "degree-minutes-fahrenheit" "",
        DegreeSecondsCelsius = 47977 => "degree-seconds-celsius" "",
        DegreeSecondsFahrenheit = 47978 => "degree-seconds-fahrenheit" "",
        Microseconds = 47979 => "microseconds" "",
        Nanoseconds = 47980 => "nanoseconds" "",
        Picoseconds = 47981 => "picoseconds" "",
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

        // Test concrete unit by ID
        let per_minute = EngineeringUnits::from(100);
        assert!(matches!(per_minute, EngineeringUnits::PerMinute));
        assert_eq!(u32::from(per_minute), 100);
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

    #[test]
    fn test_newly_added_units() {
        // Verify the 13 previously missing units
        assert_eq!(u32::from(EngineeringUnits::PerMinute), 100);
        assert_eq!(u32::from(EngineeringUnits::PerSecond), 101);
        assert_eq!(u32::from(EngineeringUnits::Nanograms), 47828);
        assert_eq!(u32::from(EngineeringUnits::Micrograms), 47829);
        assert_eq!(u32::from(EngineeringUnits::KelvinPerDay), 47870);
        assert_eq!(u32::from(EngineeringUnits::ImperialGallonsPerHour), 47876);
        assert_eq!(u32::from(EngineeringUnits::ImperialGallonsPerDay), 47877);
        assert_eq!(u32::from(EngineeringUnits::MicrogramsPerGram), 47886);
        assert_eq!(u32::from(EngineeringUnits::NanogramsPerGram), 47887);
        assert_eq!(u32::from(EngineeringUnits::Gigajoules), 47925);
        assert_eq!(u32::from(EngineeringUnits::Terajoules), 47926);
        assert_eq!(u32::from(EngineeringUnits::GigawattHours), 47927);
        assert_eq!(u32::from(EngineeringUnits::GigawattReactiveHours), 47928);
    }

    #[test]
    fn test_corrected_names() {
        // Verify name corrections match ASHRAE 135-2024
        assert_eq!(EngineeringUnits::Kiloohms.bacnet_name(), "kilohms");
        assert_eq!(
            EngineeringUnits::JoulesPerKilogramKelvin.bacnet_name(),
            "joules-per-kilogram-per-kelvin"
        );
        assert_eq!(EngineeringUnits::Microsiemens.bacnet_name(), "microsiemens");
        assert_eq!(
            EngineeringUnits::WattHoursReactive.bacnet_name(),
            "watt-reactive-hours"
        );
        assert_eq!(
            EngineeringUnits::KilowattHoursReactive.bacnet_name(),
            "kilowatt-reactive-hours"
        );
        assert_eq!(
            EngineeringUnits::MegawattHoursReactive.bacnet_name(),
            "megawatt-reactive-hours"
        );
        assert_eq!(EngineeringUnits::Ph.bacnet_name(), "pH");
    }
}
