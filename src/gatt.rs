//! GATT (Generic Attribute Profile) parsing
//!
//! GATT defines how attribute data is grouped into services and characteristics.
//! This module provides structures and parsing for GATT service discovery
//! and characteristic operations.

use bytes::{Buf, Bytes};
use std::collections::BTreeMap;
use std::fmt;

/// Bluetooth UUID types
///
/// UUIDs can be 16-bit (for Bluetooth SIG assigned), 32-bit, or 128-bit (for custom).
/// 16-bit and 32-bit UUIDs are aliases into the Bluetooth Base UUID:
/// `00000000-0000-1000-8000-00805F9B34FB`
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Uuid {
    /// 16-bit UUID (Bluetooth SIG assigned)
    Uuid16(u16),
    /// 32-bit UUID
    Uuid32(u32),
    /// 128-bit UUID
    Uuid128([u8; 16]),
}

/// Bluetooth Base UUID: 00000000-0000-1000-8000-00805F9B34FB
const BLUETOOTH_BASE_UUID: [u8; 16] = [
    0xFB, 0x34, 0x9B, 0x5F, 0x80, 0x00, 0x00, 0x80, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

impl Uuid {
    /// Parse UUID from bytes (little-endian format as used in ATT)
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        match data.len() {
            2 => Some(Uuid::Uuid16(u16::from_le_bytes([data[0], data[1]]))),
            4 => Some(Uuid::Uuid32(u32::from_le_bytes([
                data[0], data[1], data[2], data[3],
            ]))),
            16 => {
                let mut uuid = [0u8; 16];
                uuid.copy_from_slice(data);
                Some(Uuid::Uuid128(uuid))
            }
            _ => None,
        }
    }

    /// Parse UUID from Bytes buffer
    pub fn parse(data: Bytes) -> Option<Self> {
        Self::from_bytes(&data)
    }

    /// Get UUID as 16-bit value if it's a 16-bit UUID
    pub fn as_u16(&self) -> Option<u16> {
        match self {
            Uuid::Uuid16(v) => Some(*v),
            _ => None,
        }
    }

    /// Convert to 128-bit UUID representation
    pub fn to_uuid128(&self) -> [u8; 16] {
        match self {
            Uuid::Uuid16(v) => {
                let mut uuid = BLUETOOTH_BASE_UUID;
                uuid[12] = (*v & 0xff) as u8;
                uuid[13] = ((*v >> 8) & 0xff) as u8;
                uuid
            }
            Uuid::Uuid32(v) => {
                let mut uuid = BLUETOOTH_BASE_UUID;
                uuid[12] = (*v & 0xff) as u8;
                uuid[13] = ((*v >> 8) & 0xff) as u8;
                uuid[14] = ((*v >> 16) & 0xff) as u8;
                uuid[15] = ((*v >> 24) & 0xff) as u8;
                uuid
            }
            Uuid::Uuid128(uuid) => *uuid,
        }
    }

    /// Check if this is a standard Bluetooth SIG UUID
    pub fn is_sig_uuid(&self) -> bool {
        matches!(self, Uuid::Uuid16(_))
    }

    /// Get the human-readable name for known UUIDs
    pub fn name(&self) -> &'static str {
        match self {
            Uuid::Uuid16(v) => uuid16_name(*v),
            Uuid::Uuid32(v) => {
                if *v <= 0xFFFF {
                    uuid16_name(*v as u16)
                } else {
                    "Unknown"
                }
            }
            Uuid::Uuid128(_) => "Custom UUID",
        }
    }
}

impl fmt::Display for Uuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Uuid::Uuid16(v) => {
                let name = uuid16_name(*v);
                if name != "Unknown" {
                    write!(f, "{} (0x{:04x})", name, v)
                } else {
                    write!(f, "0x{:04x}", v)
                }
            }
            Uuid::Uuid32(v) => write!(f, "0x{:08x}", v),
            Uuid::Uuid128(uuid) => {
                // Format as standard UUID string (big-endian display)
                write!(
                    f,
                    "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                    uuid[15],
                    uuid[14],
                    uuid[13],
                    uuid[12],
                    uuid[11],
                    uuid[10],
                    uuid[9],
                    uuid[8],
                    uuid[7],
                    uuid[6],
                    uuid[5],
                    uuid[4],
                    uuid[3],
                    uuid[2],
                    uuid[1],
                    uuid[0]
                )
            }
        }
    }
}

/// Get the human-readable name for a 16-bit UUID
pub fn uuid16_name(uuid: u16) -> &'static str {
    match uuid {
        // GATT Declaration UUIDs
        0x2800 => "Primary Service",
        0x2801 => "Secondary Service",
        0x2802 => "Include",
        0x2803 => "Characteristic",

        // GATT Descriptor UUIDs
        0x2900 => "Characteristic Extended Properties",
        0x2901 => "Characteristic User Description",
        0x2902 => "Client Characteristic Configuration",
        0x2903 => "Server Characteristic Configuration",
        0x2904 => "Characteristic Presentation Format",
        0x2905 => "Characteristic Aggregate Format",
        0x2906 => "Valid Range",
        0x2907 => "External Report Reference",
        0x2908 => "Report Reference",
        0x2909 => "Number of Digitals",
        0x290A => "Value Trigger Setting",
        0x290B => "Environmental Sensing Configuration",
        0x290C => "Environmental Sensing Measurement",
        0x290D => "Environmental Sensing Trigger Setting",
        0x290E => "Time Trigger Setting",
        0x290F => "Complete BR-EDR Transport Block Data",

        // GATT Service UUIDs
        0x1800 => "Generic Access",
        0x1801 => "Generic Attribute",
        0x1802 => "Immediate Alert",
        0x1803 => "Link Loss",
        0x1804 => "Tx Power",
        0x1805 => "Current Time",
        0x1806 => "Reference Time Update",
        0x1807 => "Next DST Change",
        0x1808 => "Glucose",
        0x1809 => "Health Thermometer",
        0x180A => "Device Information",
        0x180D => "Heart Rate",
        0x180E => "Phone Alert Status",
        0x180F => "Battery Service",
        0x1810 => "Blood Pressure",
        0x1811 => "Alert Notification",
        0x1812 => "Human Interface Device",
        0x1813 => "Scan Parameters",
        0x1814 => "Running Speed and Cadence",
        0x1815 => "Automation IO",
        0x1816 => "Cycling Speed and Cadence",
        0x1818 => "Cycling Power",
        0x1819 => "Location and Navigation",
        0x181A => "Environmental Sensing",
        0x181B => "Body Composition",
        0x181C => "User Data",
        0x181D => "Weight Scale",
        0x181E => "Bond Management",
        0x181F => "Continuous Glucose Monitoring",
        0x1820 => "Internet Protocol Support",
        0x1821 => "Indoor Positioning",
        0x1822 => "Pulse Oximeter",
        0x1823 => "HTTP Proxy",
        0x1824 => "Transport Discovery",
        0x1825 => "Object Transfer",
        0x1826 => "Fitness Machine",
        0x1827 => "Mesh Provisioning",
        0x1828 => "Mesh Proxy",
        0x1829 => "Reconnection Configuration",
        0x183A => "Insulin Delivery",
        0x183B => "Binary Sensor",
        0x183C => "Emergency Configuration",
        0x183E => "Physical Activity Monitor",
        0x1843 => "Audio Input Control",
        0x1844 => "Volume Control",
        0x1845 => "Volume Offset Control",
        0x1846 => "Coordinated Set Identification",
        0x1847 => "Device Time",
        0x1848 => "Media Control",
        0x1849 => "Generic Media Control",
        0x184A => "Constant Tone Extension",
        0x184B => "Telephone Bearer",
        0x184C => "Generic Telephone Bearer",
        0x184D => "Microphone Control",
        0x184E => "Audio Stream Control",
        0x184F => "Broadcast Audio Scan",
        0x1850 => "Published Audio Capabilities",
        0x1851 => "Basic Audio Announcement",
        0x1852 => "Broadcast Audio Announcement",
        0x1853 => "Common Audio",
        0x1854 => "Hearing Access",
        0x1855 => "TMAS",
        0x1856 => "Public Broadcast Announcement",

        // Common Characteristic UUIDs
        0x2A00 => "Device Name",
        0x2A01 => "Appearance",
        0x2A02 => "Peripheral Privacy Flag",
        0x2A03 => "Reconnection Address",
        0x2A04 => "Peripheral Preferred Connection Parameters",
        0x2A05 => "Service Changed",
        0x2A06 => "Alert Level",
        0x2A07 => "Tx Power Level",
        0x2A08 => "Date Time",
        0x2A09 => "Day of Week",
        0x2A0A => "Day Date Time",
        0x2A19 => "Battery Level",
        0x2A23 => "System ID",
        0x2A24 => "Model Number String",
        0x2A25 => "Serial Number String",
        0x2A26 => "Firmware Revision String",
        0x2A27 => "Hardware Revision String",
        0x2A28 => "Software Revision String",
        0x2A29 => "Manufacturer Name String",
        0x2A2A => "IEEE 11073-20601 Regulatory",
        0x2A37 => "Heart Rate Measurement",
        0x2A38 => "Body Sensor Location",
        0x2A39 => "Heart Rate Control Point",
        0x2A4A => "HID Information",
        0x2A4B => "Report Map",
        0x2A4C => "HID Control Point",
        0x2A4D => "Report",
        0x2A4E => "Protocol Mode",
        0x2A50 => "PnP ID",

        _ => "Unknown",
    }
}

/// GATT Characteristic Properties
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CharacteristicProperties(pub u8);

impl CharacteristicProperties {
    pub const BROADCAST: u8 = 0x01;
    pub const READ: u8 = 0x02;
    pub const WRITE_WITHOUT_RESPONSE: u8 = 0x04;
    pub const WRITE: u8 = 0x08;
    pub const NOTIFY: u8 = 0x10;
    pub const INDICATE: u8 = 0x20;
    pub const AUTHENTICATED_SIGNED_WRITES: u8 = 0x40;
    pub const EXTENDED_PROPERTIES: u8 = 0x80;

    pub fn can_broadcast(&self) -> bool {
        self.0 & Self::BROADCAST != 0
    }

    pub fn can_read(&self) -> bool {
        self.0 & Self::READ != 0
    }

    pub fn can_write_without_response(&self) -> bool {
        self.0 & Self::WRITE_WITHOUT_RESPONSE != 0
    }

    pub fn can_write(&self) -> bool {
        self.0 & Self::WRITE != 0
    }

    pub fn can_notify(&self) -> bool {
        self.0 & Self::NOTIFY != 0
    }

    pub fn can_indicate(&self) -> bool {
        self.0 & Self::INDICATE != 0
    }

    pub fn has_authenticated_signed_writes(&self) -> bool {
        self.0 & Self::AUTHENTICATED_SIGNED_WRITES != 0
    }

    pub fn has_extended_properties(&self) -> bool {
        self.0 & Self::EXTENDED_PROPERTIES != 0
    }
}

impl fmt::Display for CharacteristicProperties {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut props = Vec::new();

        if self.can_broadcast() {
            props.push("Broadcast");
        }
        if self.can_read() {
            props.push("Read");
        }
        if self.can_write_without_response() {
            props.push("WriteNoRsp");
        }
        if self.can_write() {
            props.push("Write");
        }
        if self.can_notify() {
            props.push("Notify");
        }
        if self.can_indicate() {
            props.push("Indicate");
        }
        if self.has_authenticated_signed_writes() {
            props.push("AuthSign");
        }
        if self.has_extended_properties() {
            props.push("ExtProps");
        }

        if props.is_empty() {
            write!(f, "(none)")
        } else {
            write!(f, "{}", props.join("|"))
        }
    }
}

/// GATT Descriptor
#[derive(Debug, Clone)]
pub struct GattDescriptor {
    /// Descriptor handle
    pub handle: u16,
    /// Descriptor UUID
    pub uuid: Uuid,
    /// Descriptor value (if read)
    pub value: Option<Bytes>,
}

impl GattDescriptor {
    /// Check if this is a Client Characteristic Configuration descriptor
    pub fn is_cccd(&self) -> bool {
        matches!(self.uuid, Uuid::Uuid16(0x2902))
    }
}

impl fmt::Display for GattDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Descriptor[0x{:04x}]: {}", self.handle, self.uuid)
    }
}

/// GATT Characteristic
#[derive(Debug, Clone)]
pub struct GattCharacteristic {
    /// Attribute handle of the characteristic declaration
    pub declaration_handle: u16,
    /// Handle of the characteristic value
    pub value_handle: u16,
    /// End handle of this characteristic (start of next - 1, or service end)
    pub end_handle: u16,
    /// Characteristic properties
    pub properties: CharacteristicProperties,
    /// Characteristic UUID
    pub uuid: Uuid,
    /// Descriptors (discovered via Find Information)
    pub descriptors: Vec<GattDescriptor>,
    /// Last read value
    pub value: Option<Bytes>,
}

impl GattCharacteristic {
    /// Check if this characteristic has a CCCD
    pub fn has_cccd(&self) -> bool {
        self.descriptors.iter().any(|d| d.is_cccd())
    }
}

impl fmt::Display for GattCharacteristic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Characteristic[0x{:04x}]: {} (value@0x{:04x}) [{}]",
            self.declaration_handle, self.uuid, self.value_handle, self.properties
        )
    }
}

/// GATT Service
#[derive(Debug, Clone)]
pub struct GattService {
    /// Service handle (start of attribute range)
    pub start_handle: u16,
    /// End handle of the service
    pub end_handle: u16,
    /// Service UUID
    pub uuid: Uuid,
    /// Is this a primary service?
    pub is_primary: bool,
    /// Included services
    pub includes: Vec<IncludedService>,
    /// Characteristics in this service
    pub characteristics: Vec<GattCharacteristic>,
}

impl GattService {
    /// Get a characteristic by its value handle
    pub fn characteristic_by_handle(&self, handle: u16) -> Option<&GattCharacteristic> {
        self.characteristics
            .iter()
            .find(|c| c.value_handle == handle)
    }

    /// Get a characteristic by its UUID
    pub fn characteristic_by_uuid(&self, uuid: &Uuid) -> Option<&GattCharacteristic> {
        self.characteristics.iter().find(|c| &c.uuid == uuid)
    }
}

impl fmt::Display for GattService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let svc_type = if self.is_primary {
            "Primary"
        } else {
            "Secondary"
        };
        write!(
            f,
            "{} Service[0x{:04x}-0x{:04x}]: {}",
            svc_type, self.start_handle, self.end_handle, self.uuid
        )
    }
}

/// Included Service
#[derive(Debug, Clone)]
pub struct IncludedService {
    /// Handle of the include declaration
    pub include_handle: u16,
    /// Start handle of the included service
    pub start_handle: u16,
    /// End handle of the included service
    pub end_handle: u16,
    /// UUID of the included service
    pub uuid: Uuid,
}

/// Client Characteristic Configuration value
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CccdValue(pub u16);

impl CccdValue {
    pub const NONE: u16 = 0x0000;
    pub const NOTIFICATION: u16 = 0x0001;
    pub const INDICATION: u16 = 0x0002;

    pub fn notifications_enabled(&self) -> bool {
        self.0 & Self::NOTIFICATION != 0
    }

    pub fn indications_enabled(&self) -> bool {
        self.0 & Self::INDICATION != 0
    }
}

impl fmt::Display for CccdValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let notify = if self.notifications_enabled() {
            "Notify"
        } else {
            ""
        };
        let indicate = if self.indications_enabled() {
            "Indicate"
        } else {
            ""
        };

        if notify.is_empty() && indicate.is_empty() {
            write!(f, "(disabled)")
        } else if !notify.is_empty() && !indicate.is_empty() {
            write!(f, "Notify|Indicate")
        } else {
            write!(f, "{}{}", notify, indicate)
        }
    }
}

/// GATT Database - stores discovered services and characteristics
#[derive(Debug, Clone, Default)]
pub struct GattDatabase {
    /// Discovered services, keyed by start handle
    pub services: BTreeMap<u16, GattService>,
}

impl GattDatabase {
    /// Create a new empty GATT database
    pub fn new() -> Self {
        Self {
            services: BTreeMap::new(),
        }
    }

    /// Add a service to the database
    pub fn add_service(&mut self, service: GattService) {
        self.services.insert(service.start_handle, service);
    }

    /// Get a service by its start handle
    pub fn service_by_handle(&self, handle: u16) -> Option<&GattService> {
        self.services.get(&handle)
    }

    /// Get a service by its UUID (returns first match)
    pub fn service_by_uuid(&self, uuid: &Uuid) -> Option<&GattService> {
        self.services.values().find(|s| &s.uuid == uuid)
    }

    /// Find which service contains a given handle
    pub fn service_containing_handle(&self, handle: u16) -> Option<&GattService> {
        self.services
            .values()
            .find(|s| handle >= s.start_handle && handle <= s.end_handle)
    }

    /// Get a characteristic by its value handle
    pub fn characteristic_by_handle(
        &self,
        handle: u16,
    ) -> Option<(&GattService, &GattCharacteristic)> {
        for service in self.services.values() {
            if let Some(chrc) = service.characteristic_by_handle(handle) {
                return Some((service, chrc));
            }
        }
        None
    }

    /// Get all services as an iterator
    pub fn iter_services(&self) -> impl Iterator<Item = &GattService> {
        self.services.values()
    }

    /// Get total number of services
    pub fn service_count(&self) -> usize {
        self.services.len()
    }

    /// Get total number of characteristics across all services
    pub fn characteristic_count(&self) -> usize {
        self.services
            .values()
            .map(|s| s.characteristics.len())
            .sum()
    }

    /// Clear all services from the database
    pub fn clear(&mut self) {
        self.services.clear();
    }

    /// Save the GATT database to a JSON file
    ///
    /// This feature requires the `persist` feature flag to be enabled.
    #[cfg(feature = "persist")]
    pub fn save_to_file(&self, path: &std::path::Path) -> std::io::Result<()> {
        use std::io::Write;

        let serializable = SerializableGattDatabase::from(self);
        let json = serde_json::to_string_pretty(&serializable)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let mut file = std::fs::File::create(path)?;
        file.write_all(json.as_bytes())?;
        Ok(())
    }

    /// Load a GATT database from a JSON file
    ///
    /// This feature requires the `persist` feature flag to be enabled.
    #[cfg(feature = "persist")]
    pub fn load_from_file(path: &std::path::Path) -> std::io::Result<Self> {
        let json = std::fs::read_to_string(path)?;
        let serializable: SerializableGattDatabase = serde_json::from_str(&json)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(Self::from(serializable))
    }
}

impl fmt::Display for GattDatabase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "GATT Database: {} services", self.services.len())?;
        for service in self.services.values() {
            writeln!(f, "  {}", service)?;
            for chrc in &service.characteristics {
                writeln!(f, "    {}", chrc)?;
                for desc in &chrc.descriptors {
                    writeln!(f, "      {}", desc)?;
                }
            }
        }
        Ok(())
    }
}

/// Parsed Read By Group Type Response entry
#[derive(Debug, Clone)]
pub struct GroupTypeEntry {
    /// Attribute handle
    pub handle: u16,
    /// End group handle
    pub end_group_handle: u16,
    /// Attribute value (UUID for services)
    pub value: Bytes,
}

/// Parsed Read By Type Response entry
#[derive(Debug, Clone)]
pub struct TypeValueEntry {
    /// Attribute handle
    pub handle: u16,
    /// Attribute value
    pub value: Bytes,
}

/// Parsed Find Information Response entry
#[derive(Debug, Clone)]
pub struct HandleUuidEntry {
    /// Attribute handle
    pub handle: u16,
    /// Attribute UUID
    pub uuid: Uuid,
}

/// Parse Read By Group Type Response data
///
/// Returns a list of (start_handle, end_handle, uuid) tuples for services
pub fn parse_read_by_group_type_response(mut data: Bytes) -> Vec<GroupTypeEntry> {
    let mut entries = Vec::new();

    if data.remaining() < 1 {
        return entries;
    }

    let length = data.get_u8() as usize;
    if length < 4 {
        return entries;
    }

    while data.remaining() >= length {
        let handle = data.get_u16_le();
        let end_group_handle = data.get_u16_le();
        let value_len = length - 4;

        if data.remaining() < value_len {
            break;
        }

        let value = data.split_to(value_len);
        entries.push(GroupTypeEntry {
            handle,
            end_group_handle,
            value,
        });
    }

    entries
}

/// Parse Read By Type Response data
///
/// Returns a list of (handle, value) tuples
pub fn parse_read_by_type_response(mut data: Bytes) -> Vec<TypeValueEntry> {
    let mut entries = Vec::new();

    if data.remaining() < 1 {
        return entries;
    }

    let length = data.get_u8() as usize;
    if length < 2 {
        return entries;
    }

    while data.remaining() >= length {
        let handle = data.get_u16_le();
        let value_len = length - 2;

        if data.remaining() < value_len {
            break;
        }

        let value = data.split_to(value_len);
        entries.push(TypeValueEntry { handle, value });
    }

    entries
}

/// Parse Find Information Response data
///
/// Returns a list of (handle, uuid) tuples
pub fn parse_find_info_response(mut data: Bytes) -> Vec<HandleUuidEntry> {
    let mut entries = Vec::new();

    if data.remaining() < 1 {
        return entries;
    }

    let format = data.get_u8();
    let uuid_len = match format {
        0x01 => 2,  // 16-bit UUIDs
        0x02 => 16, // 128-bit UUIDs
        _ => return entries,
    };

    let entry_len = 2 + uuid_len;

    while data.remaining() >= entry_len {
        let handle = data.get_u16_le();

        if data.remaining() < uuid_len {
            break;
        }

        let uuid_bytes = data.split_to(uuid_len);
        if let Some(uuid) = Uuid::parse(uuid_bytes) {
            entries.push(HandleUuidEntry { handle, uuid });
        }
    }

    entries
}

/// Parse Characteristic Declaration value
///
/// Returns (properties, value_handle, uuid) if valid
pub fn parse_characteristic_declaration(
    data: &[u8],
) -> Option<(CharacteristicProperties, u16, Uuid)> {
    if data.len() < 5 {
        return None;
    }

    let properties = CharacteristicProperties(data[0]);
    let value_handle = u16::from_le_bytes([data[1], data[2]]);
    let uuid = Uuid::from_bytes(&data[3..])?;

    Some((properties, value_handle, uuid))
}

// ============================================================================
// Serializable types for persist feature
// ============================================================================

#[cfg(feature = "persist")]
mod serializable {
    use super::*;
    use serde::{Deserialize, Serialize};

    /// Serializable UUID representation
    #[derive(Serialize, Deserialize, Debug, Clone)]
    #[serde(tag = "type", content = "value")]
    pub enum SerializableUuid {
        Uuid16(u16),
        Uuid32(u32),
        Uuid128(String), // Hex string
    }

    impl From<&Uuid> for SerializableUuid {
        fn from(uuid: &Uuid) -> Self {
            match uuid {
                Uuid::Uuid16(v) => SerializableUuid::Uuid16(*v),
                Uuid::Uuid32(v) => SerializableUuid::Uuid32(*v),
                Uuid::Uuid128(arr) => {
                    // Convert to hex string
                    SerializableUuid::Uuid128(arr.iter().map(|b| format!("{:02x}", b)).collect())
                }
            }
        }
    }

    impl From<SerializableUuid> for Uuid {
        fn from(uuid: SerializableUuid) -> Self {
            match uuid {
                SerializableUuid::Uuid16(v) => Uuid::Uuid16(v),
                SerializableUuid::Uuid32(v) => Uuid::Uuid32(v),
                SerializableUuid::Uuid128(s) => {
                    // Parse hex string back to bytes
                    let mut arr = [0u8; 16];
                    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
                        if i < 16
                            && let Ok(byte) =
                                u8::from_str_radix(std::str::from_utf8(chunk).unwrap_or("00"), 16)
                        {
                            arr[i] = byte;
                        }
                    }
                    Uuid::Uuid128(arr)
                }
            }
        }
    }

    /// Serializable descriptor
    #[derive(Serialize, Deserialize, Debug, Clone)]
    pub struct SerializableDescriptor {
        pub handle: u16,
        pub uuid: SerializableUuid,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub value: Option<String>, // Hex encoded
    }

    impl From<&GattDescriptor> for SerializableDescriptor {
        fn from(desc: &GattDescriptor) -> Self {
            SerializableDescriptor {
                handle: desc.handle,
                uuid: SerializableUuid::from(&desc.uuid),
                value: desc
                    .value
                    .as_ref()
                    .map(|v| v.iter().map(|b| format!("{:02x}", b)).collect()),
            }
        }
    }

    impl From<SerializableDescriptor> for GattDescriptor {
        fn from(desc: SerializableDescriptor) -> Self {
            GattDescriptor {
                handle: desc.handle,
                uuid: Uuid::from(desc.uuid),
                value: None, // We don't restore values
            }
        }
    }

    /// Serializable characteristic
    #[derive(Serialize, Deserialize, Debug, Clone)]
    pub struct SerializableCharacteristic {
        pub declaration_handle: u16,
        pub value_handle: u16,
        pub end_handle: u16,
        pub properties: u8,
        pub uuid: SerializableUuid,
        pub descriptors: Vec<SerializableDescriptor>,
    }

    impl From<&GattCharacteristic> for SerializableCharacteristic {
        fn from(chrc: &GattCharacteristic) -> Self {
            SerializableCharacteristic {
                declaration_handle: chrc.declaration_handle,
                value_handle: chrc.value_handle,
                end_handle: chrc.end_handle,
                properties: chrc.properties.0,
                uuid: SerializableUuid::from(&chrc.uuid),
                descriptors: chrc
                    .descriptors
                    .iter()
                    .map(SerializableDescriptor::from)
                    .collect(),
            }
        }
    }

    impl From<SerializableCharacteristic> for GattCharacteristic {
        fn from(chrc: SerializableCharacteristic) -> Self {
            GattCharacteristic {
                declaration_handle: chrc.declaration_handle,
                value_handle: chrc.value_handle,
                end_handle: chrc.end_handle,
                properties: CharacteristicProperties(chrc.properties),
                uuid: Uuid::from(chrc.uuid),
                descriptors: chrc
                    .descriptors
                    .into_iter()
                    .map(GattDescriptor::from)
                    .collect(),
                value: None,
            }
        }
    }

    /// Serializable service
    #[derive(Serialize, Deserialize, Debug, Clone)]
    pub struct SerializableService {
        pub start_handle: u16,
        pub end_handle: u16,
        pub uuid: SerializableUuid,
        pub is_primary: bool,
        pub characteristics: Vec<SerializableCharacteristic>,
    }

    impl From<&GattService> for SerializableService {
        fn from(svc: &GattService) -> Self {
            SerializableService {
                start_handle: svc.start_handle,
                end_handle: svc.end_handle,
                uuid: SerializableUuid::from(&svc.uuid),
                is_primary: svc.is_primary,
                characteristics: svc
                    .characteristics
                    .iter()
                    .map(SerializableCharacteristic::from)
                    .collect(),
            }
        }
    }

    impl From<SerializableService> for GattService {
        fn from(svc: SerializableService) -> Self {
            GattService {
                start_handle: svc.start_handle,
                end_handle: svc.end_handle,
                uuid: Uuid::from(svc.uuid),
                is_primary: svc.is_primary,
                includes: vec![],
                characteristics: svc
                    .characteristics
                    .into_iter()
                    .map(GattCharacteristic::from)
                    .collect(),
            }
        }
    }

    /// Serializable GATT database
    #[derive(Serialize, Deserialize, Debug, Clone)]
    pub struct SerializableGattDatabase {
        pub version: u32,
        pub services: Vec<SerializableService>,
    }

    impl From<&GattDatabase> for SerializableGattDatabase {
        fn from(db: &GattDatabase) -> Self {
            SerializableGattDatabase {
                version: 1,
                services: db
                    .services
                    .values()
                    .map(SerializableService::from)
                    .collect(),
            }
        }
    }

    impl From<SerializableGattDatabase> for GattDatabase {
        fn from(db: SerializableGattDatabase) -> Self {
            let mut result = GattDatabase::new();
            for svc in db.services {
                result.add_service(GattService::from(svc));
            }
            result
        }
    }
}

#[cfg(feature = "persist")]
pub use serializable::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uuid16_parse() {
        let data = [0x00, 0x28]; // Primary Service UUID (little-endian)
        let uuid = Uuid::from_bytes(&data).unwrap();
        assert!(matches!(uuid, Uuid::Uuid16(0x2800)));
        assert_eq!(uuid.name(), "Primary Service");
    }

    #[test]
    fn test_uuid128_parse() {
        let data = [
            0xFB, 0x34, 0x9B, 0x5F, 0x80, 0x00, 0x00, 0x80, 0x00, 0x10, 0x00, 0x00, 0x01, 0x18,
            0x00, 0x00,
        ];
        let uuid = Uuid::from_bytes(&data).unwrap();
        assert!(matches!(uuid, Uuid::Uuid128(_)));
    }

    #[test]
    fn test_uuid_to_string() {
        let uuid = Uuid::Uuid16(0x1800);
        assert_eq!(format!("{}", uuid), "Generic Access (0x1800)");

        let uuid = Uuid::Uuid16(0xFFFF);
        assert_eq!(format!("{}", uuid), "0xffff");
    }

    #[test]
    fn test_characteristic_properties() {
        let props = CharacteristicProperties(0x12); // Read (0x02) | Notify (0x10)
        assert!(props.can_read());
        assert!(props.can_notify());
        assert!(!props.can_write());
    }

    #[test]
    fn test_parse_read_by_group_type_response() {
        // Length=6, entries: (0x0001, 0x0005, 0x1800)
        let data = Bytes::from_static(&[
            0x06, // length
            0x01, 0x00, // start handle
            0x05, 0x00, // end handle
            0x00, 0x18, // UUID (Generic Access)
        ]);
        let entries = parse_read_by_group_type_response(data);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].handle, 0x0001);
        assert_eq!(entries[0].end_group_handle, 0x0005);
    }

    #[test]
    fn test_parse_characteristic_declaration() {
        // Properties=0x02 (Read), value_handle=0x0003, UUID=0x2A00 (Device Name)
        let data = [0x02, 0x03, 0x00, 0x00, 0x2A];
        let (props, handle, uuid) = parse_characteristic_declaration(&data).unwrap();
        assert!(props.can_read());
        assert_eq!(handle, 0x0003);
        assert!(matches!(uuid, Uuid::Uuid16(0x2A00)));
    }

    #[test]
    fn test_gatt_database() {
        let mut db = GattDatabase::new();

        let service = GattService {
            start_handle: 0x0001,
            end_handle: 0x0005,
            uuid: Uuid::Uuid16(0x1800),
            is_primary: true,
            includes: vec![],
            characteristics: vec![GattCharacteristic {
                declaration_handle: 0x0002,
                value_handle: 0x0003,
                end_handle: 0x0005,
                properties: CharacteristicProperties(0x02),
                uuid: Uuid::Uuid16(0x2A00),
                descriptors: vec![],
                value: None,
            }],
        };

        db.add_service(service);
        assert_eq!(db.service_count(), 1);
        assert_eq!(db.characteristic_count(), 1);

        let svc = db.service_by_uuid(&Uuid::Uuid16(0x1800));
        assert!(svc.is_some());
        assert_eq!(svc.unwrap().uuid.name(), "Generic Access");
    }
}
