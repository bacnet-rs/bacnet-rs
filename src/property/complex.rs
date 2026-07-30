//! Constructed BACnet property value types.

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, vec::Vec};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{
    encoding::{
        advanced::bitstring::encode_bit_string,
        advanced::context::{encode_closing_tag, encode_opening_tag},
        decode_context_object_id, decode_context_tag, decode_context_unsigned, decode_date,
        encode_boolean, encode_context_enumerated, encode_context_object_id, encode_context_tag,
        encode_context_unsigned, encode_date, encode_object_identifier, encode_octet_string,
        encode_time, encode_unsigned, EncodingError, Result as EncodingResult,
    },
    object::{ObjectIdentifier, PropertyIdentifier},
    property::{decode_property_value, PropertyValue},
};

/// Wildcard for any octet-sized field of a BACnet date or WeekNDay.
pub const ANY: u8 = 255;
/// Unspecified year, encoded as the same 255 octet as [`ANY`].
pub const UNSPECIFIED_YEAR: u16 = 255;
/// Date or WeekNDay month matching every odd-numbered month.
pub const ODD_MONTHS: u8 = 13;
/// Date or WeekNDay month matching every even-numbered month.
pub const EVEN_MONTHS: u8 = 14;
/// Date day matching whichever day ends the month.
pub const LAST_DAY_OF_MONTH: u8 = 32;
/// Date day matching every odd-numbered day.
pub const ODD_DAYS: u8 = 33;
/// Date day matching every even-numbered day.
pub const EVEN_DAYS: u8 = 34;
/// WeekNDay week matching the final seven days of the month.
pub const LAST_WEEK_OF_MONTH: u8 = 6;

/// BACnet address used by constructed application values.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BacnetAddress {
    pub network: u16,
    pub mac_address: Vec<u8>,
}

/// One BACnetAddressBinding entry from Device_Address_Binding.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressBindingValue {
    pub device_identifier: ObjectIdentifier,
    pub address: BacnetAddress,
}

impl AddressBindingValue {
    pub fn encode(&self, buffer: &mut Vec<u8>) -> EncodingResult<()> {
        encode_object_identifier(buffer, self.device_identifier)?;
        encode_unsigned(buffer, self.address.network.into())?;
        encode_octet_string(buffer, &self.address.mac_address)?;
        Ok(())
    }
}

/// Recipient choice used by BACnetRecipientProcess.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recipient {
    Device(ObjectIdentifier),
    Address(BacnetAddress),
}

/// Destination and process identifier for notifications.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientProcess {
    pub recipient: Recipient,
    pub process_identifier: u32,
}

/// One entry in a Notification Class Recipient_List.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestinationValue {
    pub valid_days: Vec<bool>,
    pub from_time: (u8, u8, u8, u8),
    pub to_time: (u8, u8, u8, u8),
    pub recipient: Recipient,
    pub process_identifier: u32,
    pub issue_confirmed_notifications: bool,
    pub transitions: Vec<bool>,
}

/// A scheduled application value at a particular time.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq)]
pub struct TimeValueValue {
    pub time: (u8, u8, u8, u8),
    pub value: Box<PropertyValue>,
}

/// One BACnetDailySchedule entry in Weekly_Schedule.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq)]
pub struct DailyScheduleValue {
    pub time_values: Vec<TimeValueValue>,
}

/// BACnetDateRange: an inclusive span between two dates.
///
/// An endpoint with an unspecified year leaves that side open, which is how
/// Effective_Period says "always in effect".
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DateRangeValue {
    pub start: (u16, u8, u8, u8),
    pub end: (u16, u8, u8, u8),
}

/// BACnetWeekNDay: a recurring month, week-of-month and weekday pattern.
///
/// `month` is 1-12, [`ODD_MONTHS`] or [`EVEN_MONTHS`]; `week_of_month` is 1-5
/// for the successive seven-day blocks or [`LAST_WEEK_OF_MONTH`];
/// `day_of_week` is 1 (Monday) through 7 (Sunday). [`ANY`] wildcards a field.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WeekNDayValue {
    pub month: u8,
    pub week_of_month: u8,
    pub day_of_week: u8,
}

/// BACnetCalendarEntry choice.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CalendarEntryValue {
    /// `date [0]`, honouring the BACnet date wildcards.
    Date(u16, u8, u8, u8),
    /// `dateRange [1]`.
    DateRange(DateRangeValue),
    /// `weekNDay [2]`.
    WeekNDay(WeekNDayValue),
}

/// The period a BACnetSpecialEvent applies to.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpecialEventPeriod {
    /// `calendarEntry [0]`, written inline in the schedule.
    CalendarEntry(CalendarEntryValue),
    /// `calendarReference [1]`, naming a Calendar object to consult instead.
    CalendarReference(ObjectIdentifier),
}

/// One BACnetSpecialEvent in an Exception_Schedule.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq)]
pub struct SpecialEventValue {
    pub period: SpecialEventPeriod,
    pub time_values: Vec<TimeValueValue>,
    /// 1-16; the lowest number wins when two events cover the same day.
    pub priority: u32,
}

/// BACnetValueSource choice. Unknown future choices remain raw values.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueSourceValue {
    None,
}

impl ValueSourceValue {
    pub fn encode(&self, out: &mut Vec<u8>) -> EncodingResult<()> {
        match self {
            Self::None => encode_context_tag(out, 0, 0),
        }
    }

    pub fn decode(data: &[u8]) -> EncodingResult<(Self, usize)> {
        let (tag, length, consumed) = decode_context_tag(data)?;
        if tag == 0 && length == 0 {
            Ok((Self::None, consumed))
        } else {
            Err(EncodingError::InvalidTag)
        }
    }
}

impl DailyScheduleValue {
    pub fn encode(&self, out: &mut Vec<u8>) -> EncodingResult<()> {
        encode_opening_tag(out, 0)?;
        encode_time_values(out, &self.time_values)?;
        encode_closing_tag(out, 0)?;
        Ok(())
    }

    pub fn decode(data: &[u8]) -> EncodingResult<(Self, usize)> {
        let mut consumed = expect_constructed_tag(data, 0, 6)?;
        let (time_values, length) = decode_time_values(&data[consumed..], 0)?;
        consumed += length;
        consumed += expect_constructed_tag(&data[consumed..], 0, 7)?;
        Ok((Self { time_values }, consumed))
    }
}

impl DateRangeValue {
    pub fn encode(&self, out: &mut Vec<u8>) -> EncodingResult<()> {
        encode_date(out, self.start.0, self.start.1, self.start.2, self.start.3)?;
        encode_date(out, self.end.0, self.end.1, self.end.2, self.end.3)
    }

    pub fn decode(data: &[u8]) -> EncodingResult<(Self, usize)> {
        let (start, mut consumed) = decode_date(data)?;
        let (end, length) = decode_date(&data[consumed..])?;
        consumed += length;
        Ok((Self { start, end }, consumed))
    }

    /// Whether `date` falls inside the range. An endpoint whose year, month or
    /// day is unspecified leaves that side of the range open.
    pub fn contains(&self, date: (u16, u8, u8, u8)) -> bool {
        let Some(day) = calendar_ordinal(date) else {
            return false;
        };
        calendar_ordinal(self.start).is_none_or(|start| start <= day)
            && calendar_ordinal(self.end).is_none_or(|end| day <= end)
    }
}

impl CalendarEntryValue {
    pub fn encode(&self, out: &mut Vec<u8>) -> EncodingResult<()> {
        match self {
            Self::Date(year, month, day, weekday) => {
                encode_context_date(out, 0, (*year, *month, *day, *weekday))
            }
            Self::DateRange(range) => {
                encode_opening_tag(out, 1)?;
                range.encode(out)?;
                encode_closing_tag(out, 1)
            }
            Self::WeekNDay(week) => {
                encode_context_tag(out, 2, 3)?;
                out.extend_from_slice(&[week.month, week.week_of_month, week.day_of_week]);
                Ok(())
            }
        }
    }

    pub fn decode(data: &[u8]) -> EncodingResult<(Self, usize)> {
        let (tag, kind, header) = decode_context_tag(data)?;
        match (tag, kind) {
            (0, 4) => {
                let ((year, month, day, weekday), consumed) = decode_context_date(data, 0)?;
                Ok((Self::Date(year, month, day, weekday), consumed))
            }
            (1, 6) => {
                let (range, length) = DateRangeValue::decode(&data[header..])?;
                let mut consumed = header + length;
                consumed += expect_constructed_tag(&data[consumed..], 1, 7)?;
                Ok((Self::DateRange(range), consumed))
            }
            (2, 3) => {
                let week = data
                    .get(header..header + 3)
                    .ok_or(EncodingError::BufferUnderflow)?;
                Ok((
                    Self::WeekNDay(WeekNDayValue {
                        month: week[0],
                        week_of_month: week[1],
                        day_of_week: week[2],
                    }),
                    header + 3,
                ))
            }
            _ => Err(EncodingError::InvalidTag),
        }
    }

    /// Whether this entry covers `date`, given as (year, month, day, weekday)
    /// with weekday 1 for Monday.
    pub fn matches(&self, date: (u16, u8, u8, u8)) -> bool {
        match self {
            Self::Date(year, month, day, weekday) => {
                date_pattern_matches((*year, *month, *day, *weekday), date)
            }
            Self::DateRange(range) => range.contains(date),
            Self::WeekNDay(week) => week_n_day_matches(week, date),
        }
    }
}

impl SpecialEventValue {
    pub fn encode(&self, out: &mut Vec<u8>) -> EncodingResult<()> {
        match &self.period {
            SpecialEventPeriod::CalendarEntry(entry) => {
                encode_opening_tag(out, 0)?;
                entry.encode(out)?;
                encode_closing_tag(out, 0)?;
            }
            // A primitive context tag, not a constructed one: this alternative
            // of the CHOICE is a bare object identifier.
            SpecialEventPeriod::CalendarReference(calendar) => {
                out.extend_from_slice(&encode_context_object_id(*calendar, 1)?);
            }
        }
        encode_opening_tag(out, 2)?;
        encode_time_values(out, &self.time_values)?;
        encode_closing_tag(out, 2)?;
        out.extend_from_slice(&encode_context_unsigned(self.priority, 3)?);
        Ok(())
    }

    pub fn decode(data: &[u8]) -> EncodingResult<(Self, usize)> {
        let (tag, kind, header) = decode_context_tag(data)?;
        let (period, mut consumed) = match (tag, kind) {
            (0, 6) => {
                let (entry, length) = CalendarEntryValue::decode(&data[header..])?;
                let mut consumed = header + length;
                consumed += expect_constructed_tag(&data[consumed..], 0, 7)?;
                (SpecialEventPeriod::CalendarEntry(entry), consumed)
            }
            (1, 4) => {
                let (calendar, consumed) = decode_context_object_id(data, 1)?;
                (SpecialEventPeriod::CalendarReference(calendar), consumed)
            }
            _ => return Err(EncodingError::InvalidTag),
        };

        consumed += expect_constructed_tag(&data[consumed..], 2, 6)?;
        let (time_values, length) = decode_time_values(&data[consumed..], 2)?;
        consumed += length;
        consumed += expect_constructed_tag(&data[consumed..], 2, 7)?;

        let (priority, length) = decode_context_unsigned(&data[consumed..], 3)?;
        consumed += length;

        Ok((
            Self {
                period,
                time_values,
                priority,
            },
            consumed,
        ))
    }
}

impl DestinationValue {
    pub fn encode(&self, out: &mut Vec<u8>) -> EncodingResult<()> {
        encode_bit_string(out, &self.valid_days)?;
        encode_time(
            out,
            self.from_time.0,
            self.from_time.1,
            self.from_time.2,
            self.from_time.3,
        )?;
        encode_time(
            out,
            self.to_time.0,
            self.to_time.1,
            self.to_time.2,
            self.to_time.3,
        )?;
        encode_recipient(out, &self.recipient)?;
        encode_unsigned(out, self.process_identifier)?;
        encode_boolean(out, self.issue_confirmed_notifications)?;
        encode_bit_string(out, &self.transitions)?;
        Ok(())
    }

    pub fn decode(data: &[u8]) -> EncodingResult<(Self, usize)> {
        let mut p = 0;
        let (days, n) = decode_property_value(&data[p..])?;
        p += n;
        let PropertyValue::BitString(valid_days) = days else {
            return Err(EncodingError::InvalidTag);
        };
        let (from, n) = decode_property_value(&data[p..])?;
        p += n;
        let PropertyValue::Time(fh, fm, fs, ff) = from else {
            return Err(EncodingError::InvalidTag);
        };
        let (to, n) = decode_property_value(&data[p..])?;
        p += n;
        let PropertyValue::Time(th, tm, ts, tf) = to else {
            return Err(EncodingError::InvalidTag);
        };
        let (recipient, n) = decode_recipient(&data[p..])?;
        p += n;
        let (process, n) = decode_property_value(&data[p..])?;
        p += n;
        let PropertyValue::Unsigned(process) = process else {
            return Err(EncodingError::InvalidTag);
        };
        let process_identifier =
            u32::try_from(process).map_err(|_| EncodingError::ValueOutOfRange)?;
        let (confirmed, n) = decode_property_value(&data[p..])?;
        p += n;
        let PropertyValue::Boolean(issue_confirmed_notifications) = confirmed else {
            return Err(EncodingError::InvalidTag);
        };
        let (trans, n) = decode_property_value(&data[p..])?;
        p += n;
        let PropertyValue::BitString(transitions) = trans else {
            return Err(EncodingError::InvalidTag);
        };
        Ok((
            Self {
                valid_days,
                from_time: (fh, fm, fs, ff),
                to_time: (th, tm, ts, tf),
                recipient,
                process_identifier,
                issue_confirmed_notifications,
                transitions,
            },
            p,
        ))
    }
}

/// Reference to a property on a BACnet object.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectPropertyReference {
    pub object_identifier: ObjectIdentifier,
    pub property_identifier: PropertyIdentifier,
    pub array_index: Option<u32>,
}

impl ObjectPropertyReference {
    pub fn encode(&self, buffer: &mut Vec<u8>) -> EncodingResult<()> {
        buffer.extend_from_slice(&encode_context_object_id(self.object_identifier, 0)?);
        buffer.extend_from_slice(&encode_context_enumerated(
            self.property_identifier.into(),
            1,
        )?);
        if let Some(index) = self.array_index {
            buffer.extend_from_slice(&encode_context_unsigned(index, 2)?);
        }
        Ok(())
    }

    pub fn decode(data: &[u8]) -> EncodingResult<(Self, usize)> {
        let (object_identifier, mut consumed) = decode_context_object_id(data, 0)?;
        let (property_identifier, length) = decode_context_unsigned(&data[consumed..], 1)?;
        consumed += length;
        let array_index = if context_tag_matches(&data[consumed..], 2, None) {
            let (index, length) = decode_context_unsigned(&data[consumed..], 2)?;
            consumed += length;
            Some(index)
        } else {
            None
        };
        Ok((
            Self {
                object_identifier,
                property_identifier: property_identifier.into(),
                array_index,
            },
            consumed,
        ))
    }
}

/// BACnetTimeStamp choice.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimestampValue {
    Time(u8, u8, u8, u8),
    SequenceNumber(u32),
    DateTime {
        date: (u16, u8, u8, u8),
        time: (u8, u8, u8, u8),
    },
}

impl TimestampValue {
    pub fn encode(&self, buffer: &mut Vec<u8>) -> EncodingResult<()> {
        match self {
            Self::Time(hour, minute, second, hundredths) => {
                encode_context_tag(buffer, 0, 4)?;
                buffer.extend_from_slice(&[*hour, *minute, *second, *hundredths]);
            }
            Self::SequenceNumber(sequence) => {
                buffer.extend_from_slice(&encode_context_unsigned(*sequence, 1)?);
            }
            Self::DateTime { date, time } => {
                encode_opening_tag(buffer, 2)?;
                encode_date(buffer, date.0, date.1, date.2, date.3)?;
                encode_time(buffer, time.0, time.1, time.2, time.3)?;
                encode_closing_tag(buffer, 2)?;
            }
        }
        Ok(())
    }

    pub fn decode(data: &[u8]) -> EncodingResult<(Self, usize)> {
        let (tag, kind, header) = decode_context_tag(data)?;
        match (tag, kind) {
            (0, 4) if data.len() >= header + 4 => Ok((
                Self::Time(
                    data[header],
                    data[header + 1],
                    data[header + 2],
                    data[header + 3],
                ),
                header + 4,
            )),
            (1, _) => {
                let (sequence, consumed) = decode_context_unsigned(data, 1)?;
                Ok((Self::SequenceNumber(sequence), consumed))
            }
            (2, 6) => {
                let mut consumed = header;
                let (date, length) = decode_property_value(&data[consumed..])?;
                consumed += length;
                let PropertyValue::Date(year, month, day, weekday) = date else {
                    return Err(EncodingError::InvalidTag);
                };
                let (time, length) = decode_property_value(&data[consumed..])?;
                consumed += length;
                let PropertyValue::Time(hour, minute, second, hundredths) = time else {
                    return Err(EncodingError::InvalidTag);
                };
                consumed += expect_constructed_tag(&data[consumed..], 2, 7)?;
                Ok((
                    Self::DateTime {
                        date: (year, month, day, weekday),
                        time: (hour, minute, second, hundredths),
                    },
                    consumed,
                ))
            }
            _ => Err(EncodingError::InvalidTag),
        }
    }
}

/// One entry in the Device object's Active_COV_Subscriptions property.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq)]
pub struct CovSubscriptionValue {
    pub recipient: RecipientProcess,
    pub monitored_property: ObjectPropertyReference,
    pub issue_confirmed_notifications: bool,
    pub time_remaining: u32,
    pub cov_increment: Option<f32>,
}

impl CovSubscriptionValue {
    pub fn encode(&self, buffer: &mut Vec<u8>) -> EncodingResult<()> {
        encode_recipient_process(buffer, 0, &self.recipient)?;
        encode_object_property_reference(buffer, 1, &self.monitored_property)?;
        encode_context_boolean(buffer, 2, self.issue_confirmed_notifications)?;
        buffer.extend_from_slice(&encode_context_unsigned(self.time_remaining, 3)?);
        if let Some(increment) = self.cov_increment {
            encode_context_real(buffer, 4, increment)?;
        }
        Ok(())
    }

    pub fn decode(data: &[u8]) -> EncodingResult<(Self, usize)> {
        let (recipient, mut consumed) = decode_recipient_process(data, 0)?;
        let (monitored_property, length) = decode_object_property_reference(&data[consumed..], 1)?;
        consumed += length;
        let (issue_confirmed_notifications, length) = decode_context_boolean(&data[consumed..], 2)?;
        consumed += length;
        let (time_remaining, length) = decode_context_unsigned(&data[consumed..], 3)?;
        consumed += length;

        let cov_increment = if context_tag_matches(&data[consumed..], 4, Some(4)) {
            let (increment, length) = decode_context_real(&data[consumed..], 4)?;
            consumed += length;
            Some(increment)
        } else {
            None
        };

        Ok((
            Self {
                recipient,
                monitored_property,
                issue_confirmed_notifications,
                time_remaining,
                cov_increment,
            },
            consumed,
        ))
    }
}

pub(crate) fn decode_cov_subscriptions(data: &[u8]) -> EncodingResult<Vec<PropertyValue>> {
    let mut subscriptions = Vec::new();
    let mut consumed = 0;
    while consumed < data.len() {
        let (subscription, length) = CovSubscriptionValue::decode(&data[consumed..])?;
        if length == 0 {
            return Err(EncodingError::InvalidLength);
        }
        consumed += length;
        subscriptions.push(PropertyValue::CovSubscription(subscription));
    }
    Ok(subscriptions)
}

pub(crate) fn decode_address_bindings(data: &[u8]) -> EncodingResult<Vec<PropertyValue>> {
    let mut bindings = Vec::new();
    let mut consumed = 0;
    while consumed < data.len() {
        let (device_identifier, length) = decode_property_value(&data[consumed..])?;
        consumed += length;
        let PropertyValue::ObjectIdentifier(device_identifier) = device_identifier else {
            return Err(EncodingError::InvalidFormat(
                "address binding device is not an object identifier".into(),
            ));
        };
        let (network, length) = decode_property_value(&data[consumed..])?;
        consumed += length;
        let PropertyValue::Unsigned(network) = network else {
            return Err(EncodingError::InvalidFormat(
                "address binding network is not unsigned".into(),
            ));
        };
        let network = u16::try_from(network).map_err(|_| EncodingError::ValueOutOfRange)?;
        let (mac_address, length) = decode_property_value(&data[consumed..])?;
        consumed += length;
        let PropertyValue::OctetString(mac_address) = mac_address else {
            return Err(EncodingError::InvalidFormat(
                "address binding MAC is not an octet string".into(),
            ));
        };
        bindings.push(PropertyValue::AddressBinding(AddressBindingValue {
            device_identifier,
            address: BacnetAddress {
                network,
                mac_address,
            },
        }));
    }
    Ok(bindings)
}

pub(crate) fn decode_timestamps(data: &[u8]) -> EncodingResult<Vec<PropertyValue>> {
    let mut values = Vec::new();
    let mut consumed = 0;
    while consumed < data.len() {
        let (value, length) = TimestampValue::decode(&data[consumed..])?;
        consumed += length;
        values.push(PropertyValue::Timestamp(value));
    }
    Ok(values)
}

pub(crate) fn decode_destinations(data: &[u8]) -> EncodingResult<Vec<PropertyValue>> {
    let mut values = Vec::new();
    let mut consumed = 0;
    while consumed < data.len() {
        let (value, length) = DestinationValue::decode(&data[consumed..])?;
        consumed += length;
        values.push(PropertyValue::Destination(value));
    }
    Ok(values)
}

pub(crate) fn decode_weekly_schedule(data: &[u8]) -> EncodingResult<Vec<PropertyValue>> {
    let mut values = Vec::new();
    let mut consumed = 0;
    while consumed < data.len() {
        let (value, length) = DailyScheduleValue::decode(&data[consumed..])?;
        consumed += length;
        values.push(PropertyValue::DailySchedule(value));
    }
    Ok(values)
}

pub(crate) fn decode_date_list(data: &[u8]) -> EncodingResult<Vec<PropertyValue>> {
    let mut values = Vec::new();
    let mut consumed = 0;
    while consumed < data.len() {
        let (value, length) = CalendarEntryValue::decode(&data[consumed..])?;
        consumed += length;
        values.push(PropertyValue::CalendarEntry(value));
    }
    Ok(values)
}

pub(crate) fn decode_exception_schedule(data: &[u8]) -> EncodingResult<Vec<PropertyValue>> {
    let mut values = Vec::new();
    let mut consumed = 0;
    while consumed < data.len() {
        let (value, length) = SpecialEventValue::decode(&data[consumed..])?;
        consumed += length;
        values.push(PropertyValue::SpecialEvent(value));
    }
    Ok(values)
}

pub(crate) fn decode_date_range(data: &[u8]) -> EncodingResult<Vec<PropertyValue>> {
    let (value, _) = DateRangeValue::decode(data)?;
    Ok(vec![PropertyValue::DateRange(value)])
}

pub(crate) fn decode_value_sources(data: &[u8]) -> EncodingResult<Vec<PropertyValue>> {
    let mut values = Vec::new();
    let mut consumed = 0;
    while consumed < data.len() {
        let (value, length) = ValueSourceValue::decode(&data[consumed..])?;
        consumed += length;
        values.push(PropertyValue::ValueSource(value));
    }
    Ok(values)
}

pub(crate) fn decode_object_property_references(data: &[u8]) -> EncodingResult<Vec<PropertyValue>> {
    let mut values = Vec::new();
    let mut consumed = 0;
    while consumed < data.len() {
        let (value, length) = ObjectPropertyReference::decode(&data[consumed..])?;
        consumed += length;
        values.push(PropertyValue::ObjectPropertyReference(value));
    }
    Ok(values)
}

fn encode_recipient_process(
    buffer: &mut Vec<u8>,
    tag: u8,
    value: &RecipientProcess,
) -> EncodingResult<()> {
    encode_opening_tag(buffer, tag)?;
    encode_opening_tag(buffer, 0)?;
    match &value.recipient {
        Recipient::Device(device) => {
            buffer.extend_from_slice(&encode_context_object_id(*device, 0)?)
        }
        Recipient::Address(address) => {
            encode_opening_tag(buffer, 1)?;
            encode_unsigned(buffer, address.network.into())?;
            encode_octet_string(buffer, &address.mac_address)?;
            encode_closing_tag(buffer, 1)?;
        }
    }
    encode_closing_tag(buffer, 0)?;
    buffer.extend_from_slice(&encode_context_unsigned(value.process_identifier, 1)?);
    encode_closing_tag(buffer, tag)?;
    Ok(())
}

fn encode_recipient(out: &mut Vec<u8>, value: &Recipient) -> EncodingResult<()> {
    match value {
        Recipient::Device(device) => out.extend_from_slice(&encode_context_object_id(*device, 0)?),
        Recipient::Address(address) => {
            encode_opening_tag(out, 1)?;
            encode_unsigned(out, address.network.into())?;
            encode_octet_string(out, &address.mac_address)?;
            encode_closing_tag(out, 1)?;
        }
    }
    Ok(())
}

fn decode_recipient(data: &[u8]) -> EncodingResult<(Recipient, usize)> {
    if context_tag_matches(data, 0, Some(4)) {
        let (device, consumed) = decode_context_object_id(data, 0)?;
        return Ok((Recipient::Device(device), consumed));
    }
    let mut p = expect_constructed_tag(data, 1, 6)?;
    let (network, n) = decode_property_value(&data[p..])?;
    p += n;
    let PropertyValue::Unsigned(network) = network else {
        return Err(EncodingError::InvalidTag);
    };
    let network = u16::try_from(network).map_err(|_| EncodingError::ValueOutOfRange)?;
    let (mac, n) = decode_property_value(&data[p..])?;
    p += n;
    let PropertyValue::OctetString(mac_address) = mac else {
        return Err(EncodingError::InvalidTag);
    };
    p += expect_constructed_tag(&data[p..], 1, 7)?;
    Ok((
        Recipient::Address(BacnetAddress {
            network,
            mac_address,
        }),
        p,
    ))
}

fn decode_recipient_process(data: &[u8], tag: u8) -> EncodingResult<(RecipientProcess, usize)> {
    let mut consumed = expect_constructed_tag(data, tag, 6)?;
    consumed += expect_constructed_tag(&data[consumed..], 0, 6)?;

    let recipient = if context_tag_matches(&data[consumed..], 0, Some(4)) {
        let (device, length) = decode_context_object_id(&data[consumed..], 0)?;
        consumed += length;
        Recipient::Device(device)
    } else {
        consumed += expect_constructed_tag(&data[consumed..], 1, 6)?;
        let (network, length) = decode_property_value(&data[consumed..])?;
        consumed += length;
        let PropertyValue::Unsigned(network) = network else {
            return Err(EncodingError::InvalidFormat(
                "BACnetAddress network is not unsigned".into(),
            ));
        };
        let network = u16::try_from(network).map_err(|_| EncodingError::ValueOutOfRange)?;
        let (mac_address, length) = decode_property_value(&data[consumed..])?;
        consumed += length;
        let PropertyValue::OctetString(mac_address) = mac_address else {
            return Err(EncodingError::InvalidFormat(
                "BACnetAddress MAC is not an octet string".into(),
            ));
        };
        consumed += expect_constructed_tag(&data[consumed..], 1, 7)?;
        Recipient::Address(BacnetAddress {
            network,
            mac_address,
        })
    };

    consumed += expect_constructed_tag(&data[consumed..], 0, 7)?;
    let (process_identifier, length) = decode_context_unsigned(&data[consumed..], 1)?;
    consumed += length;
    consumed += expect_constructed_tag(&data[consumed..], tag, 7)?;

    Ok((
        RecipientProcess {
            recipient,
            process_identifier,
        },
        consumed,
    ))
}

fn encode_object_property_reference(
    buffer: &mut Vec<u8>,
    tag: u8,
    value: &ObjectPropertyReference,
) -> EncodingResult<()> {
    encode_opening_tag(buffer, tag)?;
    value.encode(buffer)?;
    encode_closing_tag(buffer, tag)?;
    Ok(())
}

fn decode_object_property_reference(
    data: &[u8],
    tag: u8,
) -> EncodingResult<(ObjectPropertyReference, usize)> {
    let mut consumed = expect_constructed_tag(data, tag, 6)?;
    let (reference, length) = ObjectPropertyReference::decode(&data[consumed..])?;
    consumed += length;
    consumed += expect_constructed_tag(&data[consumed..], tag, 7)?;

    Ok((reference, consumed))
}

fn encode_context_boolean(buffer: &mut Vec<u8>, tag: u8, value: bool) -> EncodingResult<()> {
    encode_context_tag(buffer, tag, 1)?;
    buffer.push(u8::from(value));
    Ok(())
}

fn decode_context_boolean(data: &[u8], tag: u8) -> EncodingResult<(bool, usize)> {
    let (actual_tag, length, header) = decode_context_tag(data)?;
    if actual_tag != tag || length != 1 || data.len() < header + 1 {
        return Err(EncodingError::InvalidTag);
    }
    match data[header] {
        0 => Ok((false, header + 1)),
        1 => Ok((true, header + 1)),
        _ => Err(EncodingError::InvalidFormat(
            "context Boolean is not zero or one".into(),
        )),
    }
}

fn encode_context_real(buffer: &mut Vec<u8>, tag: u8, value: f32) -> EncodingResult<()> {
    encode_context_tag(buffer, tag, 4)?;
    buffer.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

fn decode_context_real(data: &[u8], tag: u8) -> EncodingResult<(f32, usize)> {
    let (actual_tag, length, header) = decode_context_tag(data)?;
    if actual_tag != tag || length != 4 || data.len() < header + 4 {
        return Err(EncodingError::InvalidTag);
    }
    Ok((
        f32::from_be_bytes(data[header..header + 4].try_into().unwrap()),
        header + 4,
    ))
}

fn encode_time_values(out: &mut Vec<u8>, values: &[TimeValueValue]) -> EncodingResult<()> {
    for value in values {
        encode_time(out, value.time.0, value.time.1, value.time.2, value.time.3)?;
        crate::property::encode_property_value(&value.value, out)?;
    }
    Ok(())
}

/// Decode time/value pairs up to the closing tag `tag`, consuming the pairs but
/// not the closing tag itself.
fn decode_time_values(data: &[u8], tag: u8) -> EncodingResult<(Vec<TimeValueValue>, usize)> {
    let mut time_values = Vec::new();
    let mut consumed = 0;
    while !context_tag_matches(&data[consumed..], tag, Some(7)) {
        let (time, length) = decode_property_value(&data[consumed..])?;
        consumed += length;
        let PropertyValue::Time(hour, minute, second, hundredths) = time else {
            return Err(EncodingError::InvalidTag);
        };
        let (value, length) = decode_property_value(&data[consumed..])?;
        consumed += length;
        time_values.push(TimeValueValue {
            time: (hour, minute, second, hundredths),
            value: Box::new(value),
        });
    }
    Ok((time_values, consumed))
}

/// Encode a context-tagged Date, which stores the year as `year - 1900` in a
/// single octet rather than as the application form's full year.
fn encode_context_date(out: &mut Vec<u8>, tag: u8, date: (u16, u8, u8, u8)) -> EncodingResult<()> {
    let (year, month, day, weekday) = date;
    let year = if year == UNSPECIFIED_YEAR {
        ANY
    } else {
        year.checked_sub(1900)
            .and_then(|offset| u8::try_from(offset).ok())
            .ok_or(EncodingError::ValueOutOfRange)?
    };
    encode_context_tag(out, tag, 4)?;
    out.extend_from_slice(&[year, month, day, weekday]);
    Ok(())
}

fn decode_context_date(data: &[u8], tag: u8) -> EncodingResult<((u16, u8, u8, u8), usize)> {
    let (actual_tag, length, header) = decode_context_tag(data)?;
    if actual_tag != tag || length != 4 {
        return Err(EncodingError::InvalidTag);
    }
    let date = data
        .get(header..header + 4)
        .ok_or(EncodingError::BufferUnderflow)?;
    let year = if date[0] == ANY {
        UNSPECIFIED_YEAR
    } else {
        1900 + u16::from(date[0])
    };
    Ok(((year, date[1], date[2], date[3]), header + 4))
}

/// A date as a comparable year/month/day, or `None` if any of the three is a
/// wildcard and so cannot be ordered.
fn calendar_ordinal(date: (u16, u8, u8, u8)) -> Option<(u16, u8, u8)> {
    let (year, month, day, _) = date;
    if year == UNSPECIFIED_YEAR || month == ANY || month > 12 || day == ANY || day > 31 {
        return None;
    }
    Some((year, month, day))
}

fn month_matches(pattern: u8, month: u8) -> bool {
    match pattern {
        ANY => true,
        ODD_MONTHS => month % 2 == 1,
        EVEN_MONTHS => month.is_multiple_of(2),
        pattern => pattern == month,
    }
}

fn date_pattern_matches(pattern: (u16, u8, u8, u8), date: (u16, u8, u8, u8)) -> bool {
    let (year, month, day, weekday) = pattern;
    let (actual_year, actual_month, actual_day, actual_weekday) = date;

    let day_matches = match day {
        ANY => true,
        LAST_DAY_OF_MONTH => actual_day == days_in_month(actual_year, actual_month),
        ODD_DAYS => actual_day % 2 == 1,
        EVEN_DAYS => actual_day % 2 == 0,
        day => day == actual_day,
    };

    (year == UNSPECIFIED_YEAR || year == actual_year)
        && month_matches(month, actual_month)
        && day_matches
        && (weekday == ANY || weekday == actual_weekday)
}

fn week_n_day_matches(pattern: &WeekNDayValue, date: (u16, u8, u8, u8)) -> bool {
    let (year, month, day, weekday) = date;

    let week_matches = match pattern.week_of_month {
        ANY => true,
        // A wildcard or out-of-range day cannot be placed within the month, and
        // `day + 7` below would overflow on the 255 that means "any day".
        _ if !(1..=31).contains(&day) => false,
        LAST_WEEK_OF_MONTH => day + 7 > days_in_month(year, month),
        week => week == day.div_ceil(7),
    };

    month_matches(pattern.month, month)
        && week_matches
        && (pattern.day_of_week == ANY || pattern.day_of_week == weekday)
}

/// Days in `month`, treating an unspecified year as a common year.
fn days_in_month(year: u16, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn is_leap_year(year: u16) -> bool {
    year != UNSPECIFIED_YEAR
        && year.is_multiple_of(4)
        && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

fn expect_constructed_tag(data: &[u8], tag: u8, kind: usize) -> EncodingResult<usize> {
    let (actual_tag, actual_kind, consumed) = decode_context_tag(data)?;
    if actual_tag == tag && actual_kind == kind {
        Ok(consumed)
    } else {
        Err(EncodingError::InvalidTag)
    }
}

fn context_tag_matches(data: &[u8], tag: u8, length: Option<usize>) -> bool {
    decode_context_tag(data).is_ok_and(|(actual_tag, actual_length, _)| {
        actual_tag == tag && length.is_none_or(|length| actual_length == length)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::ObjectType;

    #[test]
    fn decodes_and_reencodes_real_active_cov_subscription() {
        let encoded = vec![
            0x0E, 0x0E, 0x1E, 0x21, 0x00, 0x65, 0x06, 192, 168, 34, 7, 186, 192, 0x1F, 0x0F, 0x1A,
            0x27, 0x27, 0x0F, 0x1E, 0x0C, 0, 0, 0, 2, 0x19, 85, 0x1F, 0x29, 0, 0x3B, 0x01, 0x50,
            0xEB,
        ];

        let (decoded, consumed) = CovSubscriptionValue::decode(&encoded).unwrap();

        assert_eq!(consumed, encoded.len());
        assert_eq!(
            decoded.recipient,
            RecipientProcess {
                recipient: Recipient::Address(BacnetAddress {
                    network: 0,
                    mac_address: vec![192, 168, 34, 7, 186, 192],
                }),
                process_identifier: 10_023,
            }
        );
        assert_eq!(
            decoded.monitored_property,
            ObjectPropertyReference {
                object_identifier: ObjectIdentifier::new(ObjectType::AnalogInput, 2),
                property_identifier: PropertyIdentifier::PresentValue,
                array_index: None,
            }
        );
        assert!(!decoded.issue_confirmed_notifications);
        assert_eq!(decoded.time_remaining, 86_251);
        assert_eq!(decoded.cov_increment, None);

        let mut reencoded = Vec::new();
        decoded.encode(&mut reencoded).unwrap();
        assert_eq!(reencoded, encoded);
    }

    #[test]
    fn roundtrips_device_recipient_array_index_and_cov_increment() {
        let value = CovSubscriptionValue {
            recipient: RecipientProcess {
                recipient: Recipient::Device(ObjectIdentifier::new(ObjectType::Device, 42)),
                process_identifier: 300,
            },
            monitored_property: ObjectPropertyReference {
                object_identifier: ObjectIdentifier::new(ObjectType::AnalogValue, 7),
                property_identifier: PropertyIdentifier::PriorityArray,
                array_index: Some(8),
            },
            issue_confirmed_notifications: true,
            time_remaining: 60,
            cov_increment: Some(0.5),
        };
        let mut encoded = Vec::new();
        value.encode(&mut encoded).unwrap();

        let (decoded, consumed) = CovSubscriptionValue::decode(&encoded).unwrap();

        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded, value);
    }

    #[test]
    fn decodes_address_binding_list_and_reencodes_entries() {
        let bindings = vec![
            AddressBindingValue {
                device_identifier: ObjectIdentifier::new(ObjectType::Device, 904),
                address: BacnetAddress {
                    network: 412,
                    mac_address: vec![7, 34, 168, 3, 186, 192],
                },
            },
            AddressBindingValue {
                device_identifier: ObjectIdentifier::new(ObjectType::Device, 5780),
                address: BacnetAddress {
                    network: 0,
                    mac_address: vec![192, 168, 34, 7, 186, 192],
                },
            },
        ];
        let mut encoded = Vec::new();
        for binding in &bindings {
            binding.encode(&mut encoded).unwrap();
        }

        let decoded = decode_address_bindings(&encoded).unwrap();

        assert_eq!(
            decoded,
            bindings
                .into_iter()
                .map(PropertyValue::AddressBinding)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn decodes_and_reencodes_wildcard_datetime_timestamp() {
        let encoded = vec![
            0x2E, 0xA4, 0xFF, 0xFF, 0xFF, 0xFF, 0xB4, 0xFF, 0xFF, 0xFF, 0xFF, 0x2F,
        ];

        let (decoded, consumed) = TimestampValue::decode(&encoded).unwrap();
        let mut reencoded = Vec::new();
        decoded.encode(&mut reencoded).unwrap();

        assert_eq!(consumed, encoded.len());
        assert_eq!(
            decoded,
            TimestampValue::DateTime {
                date: (255, 255, 255, 255),
                time: (255, 255, 255, 255),
            }
        );
        assert_eq!(reencoded, encoded);
    }

    #[test]
    fn decodes_schedule_object_property_reference() {
        let encoded = vec![0x0C, 0x04, 0xC0, 0, 0, 0x19, 85, 0x29, 15];

        let (decoded, consumed) = ObjectPropertyReference::decode(&encoded).unwrap();
        let mut reencoded = Vec::new();
        decoded.encode(&mut reencoded).unwrap();

        assert_eq!(consumed, encoded.len());
        assert_eq!(
            decoded.object_identifier.object_type,
            ObjectType::MultiStateValue
        );
        assert_eq!(
            decoded.property_identifier,
            PropertyIdentifier::PresentValue
        );
        assert_eq!(decoded.array_index, Some(15));
        assert_eq!(reencoded, encoded);
    }

    #[test]
    fn roundtrips_notification_destination() {
        let value = DestinationValue {
            valid_days: vec![true; 7],
            from_time: (0, 0, 0, 0),
            to_time: (23, 59, 0, 0),
            recipient: Recipient::Device(ObjectIdentifier::new(ObjectType::Device, 777)),
            process_identifier: 1337,
            issue_confirmed_notifications: true,
            transitions: vec![true, true, true],
        };
        let mut encoded = Vec::new();
        value.encode(&mut encoded).unwrap();
        let (decoded, consumed) = DestinationValue::decode(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded, value);
    }

    #[test]
    fn decodes_real_daily_schedule_and_empty_day() {
        let populated = vec![
            0x0E, 0xB4, 19, 0, 0, 0, 0x91, 1, 0xB4, 19, 59, 58, 0, 0x91, 0, 0x0F,
        ];
        let (day, consumed) = DailyScheduleValue::decode(&populated).unwrap();
        assert_eq!(consumed, populated.len());
        assert_eq!(day.time_values.len(), 2);
        let (empty, consumed) = DailyScheduleValue::decode(&[0x0E, 0x0F]).unwrap();
        assert_eq!(consumed, 2);
        assert!(empty.time_values.is_empty());
    }

    #[test]
    fn roundtrips_empty_value_source() {
        let encoded = [0x08];
        let (value, consumed) = ValueSourceValue::decode(&encoded).unwrap();
        let mut reencoded = Vec::new();
        value.encode(&mut reencoded).unwrap();
        assert_eq!(consumed, 1);
        assert_eq!(reencoded, encoded);
    }

    fn time_value(hour: u8, minute: u8, value: PropertyValue) -> TimeValueValue {
        TimeValueValue {
            time: (hour, minute, 0, 0),
            value: Box::new(value),
        }
    }

    #[test]
    fn calendar_entry_date_encodes_the_year_as_an_offset_from_1900() {
        let entry = CalendarEntryValue::Date(2026, 12, 24, 4);

        let mut encoded = Vec::new();
        entry.encode(&mut encoded).unwrap();

        assert_eq!(encoded, vec![0x0C, 0x7E, 0x0C, 0x18, 0x04]);
        assert_eq!(
            CalendarEntryValue::decode(&encoded).unwrap(),
            (entry, encoded.len())
        );
    }

    #[test]
    fn calendar_entry_date_range_round_trips() {
        let entry = CalendarEntryValue::DateRange(DateRangeValue {
            start: (2026, 1, 1, 4),
            end: (2026, 12, 31, 4),
        });

        let mut encoded = Vec::new();
        entry.encode(&mut encoded).unwrap();

        assert_eq!(
            CalendarEntryValue::decode(&encoded).unwrap(),
            (entry, encoded.len())
        );
    }

    #[test]
    fn calendar_entry_week_n_day_round_trips() {
        let entry = CalendarEntryValue::WeekNDay(WeekNDayValue {
            month: 1,
            week_of_month: 1,
            day_of_week: 7,
        });

        let mut encoded = Vec::new();
        entry.encode(&mut encoded).unwrap();

        assert_eq!(encoded, vec![0x2B, 0x01, 0x01, 0x07]);
        assert_eq!(
            CalendarEntryValue::decode(&encoded).unwrap(),
            (entry, encoded.len())
        );
    }

    #[test]
    fn a_date_list_decodes_entries_of_mixed_kinds() {
        let list = vec![
            CalendarEntryValue::Date(2026, 5, 4, 1),
            CalendarEntryValue::WeekNDay(WeekNDayValue {
                month: ODD_MONTHS,
                week_of_month: LAST_WEEK_OF_MONTH,
                day_of_week: 1,
            }),
            CalendarEntryValue::DateRange(DateRangeValue {
                start: (2026, 7, 1, ANY),
                end: (2026, 7, 31, ANY),
            }),
        ];

        let mut encoded = Vec::new();
        for entry in &list {
            entry.encode(&mut encoded).unwrap();
        }

        assert_eq!(
            decode_date_list(&encoded).unwrap(),
            list.into_iter()
                .map(PropertyValue::CalendarEntry)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_special_event_with_an_inline_entry_round_trips() {
        let event = SpecialEventValue {
            period: SpecialEventPeriod::CalendarEntry(CalendarEntryValue::Date(2026, 12, 24, 4)),
            time_values: vec![time_value(9, 30, PropertyValue::Enumerated(1))],
            priority: 8,
        };

        let mut encoded = Vec::new();
        event.encode(&mut encoded).unwrap();

        assert_eq!(
            encoded,
            vec![
                0x0E, 0x0C, 0x7E, 0x0C, 0x18, 0x04, 0x0F, 0x2E, 0xB4, 0x09, 0x1E, 0x00, 0x00, 0x91,
                0x01, 0x2F, 0x39, 0x08,
            ]
        );
        assert_eq!(
            SpecialEventValue::decode(&encoded).unwrap(),
            (event, encoded.len())
        );
    }

    /// The calendarReference alternative is a primitive context tag holding the
    /// object identifier, not a constructed one.
    #[test]
    fn a_special_event_referencing_a_calendar_uses_a_primitive_context_tag() {
        let event = SpecialEventValue {
            period: SpecialEventPeriod::CalendarReference(ObjectIdentifier::new(
                ObjectType::Calendar,
                3,
            )),
            time_values: vec![time_value(0, 0, PropertyValue::Real(1.0))],
            priority: 16,
        };

        let mut encoded = Vec::new();
        event.encode(&mut encoded).unwrap();

        assert_eq!(encoded[..5], [0x1C, 0x01, 0x80, 0x00, 0x03]);
        assert_eq!(
            SpecialEventValue::decode(&encoded).unwrap(),
            (event, encoded.len())
        );
    }

    #[test]
    fn an_exception_schedule_decodes_back_to_its_events() {
        let events = vec![
            SpecialEventValue {
                period: SpecialEventPeriod::CalendarEntry(CalendarEntryValue::Date(
                    2026, 12, 24, 4,
                )),
                time_values: vec![time_value(9, 30, PropertyValue::Real(18.0))],
                priority: 8,
            },
            SpecialEventValue {
                period: SpecialEventPeriod::CalendarReference(ObjectIdentifier::new(
                    ObjectType::Calendar,
                    1,
                )),
                time_values: Vec::new(),
                priority: 16,
            },
        ];

        let mut encoded = Vec::new();
        for event in &events {
            event.encode(&mut encoded).unwrap();
        }

        assert_eq!(
            decode_exception_schedule(&encoded).unwrap(),
            events
                .into_iter()
                .map(PropertyValue::SpecialEvent)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn an_effective_period_of_two_application_dates_round_trips() {
        let range = DateRangeValue {
            start: (2026, 1, 1, ANY),
            end: (2026, 12, 31, ANY),
        };

        let mut encoded = Vec::new();
        range.encode(&mut encoded).unwrap();

        assert_eq!(
            decode_date_range(&encoded).unwrap(),
            vec![PropertyValue::DateRange(range)]
        );
    }

    #[test]
    fn an_open_ended_date_range_contains_everything() {
        let always = DateRangeValue {
            start: (UNSPECIFIED_YEAR, ANY, ANY, ANY),
            end: (UNSPECIFIED_YEAR, ANY, ANY, ANY),
        };

        assert!(always.contains((2026, 7, 30, 4)));

        let summer = DateRangeValue {
            start: (2026, 6, 1, ANY),
            end: (2026, 8, 31, ANY),
        };
        assert!(summer.contains((2026, 6, 1, 1)), "inclusive start");
        assert!(summer.contains((2026, 8, 31, 1)), "inclusive end");
        assert!(!summer.contains((2026, 5, 31, 1)));
        assert!(!summer.contains((2027, 7, 1, 1)));
    }

    #[test]
    fn a_wildcarded_date_matches_every_year() {
        let christmas = CalendarEntryValue::Date(UNSPECIFIED_YEAR, 12, 24, ANY);

        assert!(christmas.matches((2026, 12, 24, 4)));
        assert!(christmas.matches((2027, 12, 24, 5)));
        assert!(!christmas.matches((2026, 12, 25, 5)));
    }

    #[test]
    fn the_last_day_of_month_wildcard_follows_the_calendar() {
        let month_end = CalendarEntryValue::Date(UNSPECIFIED_YEAR, ANY, LAST_DAY_OF_MONTH, ANY);

        assert!(month_end.matches((2026, 2, 28, 6)), "common February");
        assert!(!month_end.matches((2026, 2, 27, 5)));
        assert!(month_end.matches((2024, 2, 29, 4)), "leap February");
        assert!(!month_end.matches((2024, 2, 28, 3)));
        assert!(month_end.matches((2026, 4, 30, 4)));
    }

    #[test]
    fn week_n_day_selects_a_weekday_within_a_seven_day_block() {
        // The first Monday of every odd-numbered month.
        let entry = CalendarEntryValue::WeekNDay(WeekNDayValue {
            month: ODD_MONTHS,
            week_of_month: 1,
            day_of_week: 1,
        });

        assert!(entry.matches((2026, 1, 5, 1)), "5 January 2026, a Monday");
        assert!(!entry.matches((2026, 1, 12, 1)), "second Monday");
        assert!(!entry.matches((2026, 2, 2, 1)), "even month");
        assert!(!entry.matches((2026, 1, 6, 2)), "wrong weekday");
    }

    /// A date with an unspecified day cannot be placed within a month, so no
    /// WeekNDay pattern covers it. Before this was guarded, the last-week
    /// arithmetic overflowed on the 255.
    #[test]
    fn a_wildcard_day_matches_no_week_n_day_pattern() {
        for week_of_month in [1, 5, LAST_WEEK_OF_MONTH] {
            let entry = CalendarEntryValue::WeekNDay(WeekNDayValue {
                month: ANY,
                week_of_month,
                day_of_week: ANY,
            });
            assert!(!entry.matches((2026, 7, ANY, ANY)), "week {week_of_month}");
            assert!(!entry.matches((2026, 7, 0, ANY)), "day zero");
            assert!(!entry.matches((2026, 7, 32, ANY)), "day past the month");
        }
    }

    #[test]
    fn the_last_week_wildcard_covers_the_final_seven_days() {
        let entry = CalendarEntryValue::WeekNDay(WeekNDayValue {
            month: ANY,
            week_of_month: LAST_WEEK_OF_MONTH,
            day_of_week: ANY,
        });

        assert!(entry.matches((2026, 4, 24, 5)), "30 - 7 + 1");
        assert!(!entry.matches((2026, 4, 23, 4)));
        assert!(entry.matches((2026, 2, 22, 7)), "28 - 7 + 1");
        assert!(!entry.matches((2026, 2, 21, 6)));
    }
}
