//! Learned bindings from BACnet device identifiers to network addresses.
//!
//! A `Recipient_List` entry names *who* to notify — `device,5785` — but not where
//! that device lives. BACnet's answer is dynamic binding through Who-Is/I-Am,
//! which a hosted device would have to originate and then correlate.
//!
//! A recipient that registers itself hands us the answer for free: the
//! WriteProperty that adds it to the list arrives *from* that recipient. Binding
//! the identifiers named in the payload to the request's source address needs no
//! extra traffic and is how a gateway actually enrols itself.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, RwLock},
};

use crate::object::ObjectIdentifier;
use crate::property::Recipient;

/// Where a notification goes.
///
/// A `Recipient_List` entry may name a broadcast rather than one device, which
/// is not a socket address the cache can hand back — the caller has to send it
/// differently. Keeping the two apart in the type stops a broadcast recipient
/// being silently dropped for having no address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotificationTarget {
    /// One device, at a known address.
    Unicast(SocketAddr),
    /// Every device on the local network.
    Broadcast,
}

impl std::fmt::Display for NotificationTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unicast(address) => write!(f, "{address}"),
            Self::Broadcast => write!(f, "broadcast"),
        }
    }
}

/// Device-to-address bindings shared between the request path that learns them
/// and the notification path that uses them.
#[derive(Clone, Default)]
pub struct AddressCache {
    bindings: Arc<RwLock<HashMap<ObjectIdentifier, SocketAddr>>>,
}

impl AddressCache {
    /// An empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Bind `device` to `address`, replacing any previous binding.
    pub fn learn(&self, device: ObjectIdentifier, address: SocketAddr) {
        self.bindings.write().unwrap().insert(device, address);
    }

    /// The address bound to `device`, if one has been learned.
    pub fn lookup(&self, device: ObjectIdentifier) -> Option<SocketAddr> {
        self.bindings.read().unwrap().get(&device).copied()
    }

    /// Resolve a `Recipient_List` recipient to somewhere to send.
    ///
    /// A `Recipient::Address` with an empty MAC is a broadcast — that is how a
    /// client registers for notifications without naming itself, and gateways
    /// fall back to it when a device rejects a device-form recipient. Otherwise
    /// the MAC must be a BACnet/IP one: four octets of address and a port.
    pub fn resolve(&self, recipient: &Recipient) -> Option<NotificationTarget> {
        match recipient {
            Recipient::Device(device) => self.lookup(*device).map(NotificationTarget::Unicast),
            Recipient::Address(address) if address.mac_address.is_empty() => {
                Some(NotificationTarget::Broadcast)
            }
            Recipient::Address(address) => {
                socket_address_from_mac(&address.mac_address).map(NotificationTarget::Unicast)
            }
        }
    }

    /// Every binding currently held, for persisting across restarts.
    pub fn bindings(&self) -> Vec<(ObjectIdentifier, SocketAddr)> {
        self.bindings
            .read()
            .unwrap()
            .iter()
            .map(|(device, address)| (*device, *address))
            .collect()
    }
}

/// Describe an address as a BACnet/IP MAC: four octets of IPv4 then a port.
///
/// The inverse of [`socket_address_from_mac`]. Only an IPv4 peer has one —
/// Annex J's MAC is six octets, and there is nothing honest to put there for an
/// IPv6 peer — so this returns `None` rather than a shortened address that would
/// decode as somewhere else.
pub(crate) fn mac_from_socket_address(address: SocketAddr) -> Option<Vec<u8>> {
    let SocketAddr::V4(address) = address else {
        return None;
    };
    let mut mac = address.ip().octets().to_vec();
    mac.extend_from_slice(&address.port().to_be_bytes());
    Some(mac)
}

/// Interpret a BACnet/IP MAC as an address: four octets of IPv4 then a port.
fn socket_address_from_mac(mac: &[u8]) -> Option<SocketAddr> {
    if mac.len() != 6 {
        return None;
    }
    let octets = [mac[0], mac[1], mac[2], mac[3]];
    let port = u16::from_be_bytes([mac[4], mac[5]]);
    Some(SocketAddr::from((octets, port)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::ObjectType;
    use crate::property::BacnetAddress;

    fn gateway() -> ObjectIdentifier {
        ObjectIdentifier::new(ObjectType::Device, 5785)
    }

    fn unicast(address: &str) -> Option<NotificationTarget> {
        Some(NotificationTarget::Unicast(address.parse().unwrap()))
    }

    #[test]
    fn a_learned_binding_resolves_a_device_recipient() {
        let cache = AddressCache::new();
        assert!(cache.resolve(&Recipient::Device(gateway())).is_none());

        let address: SocketAddr = "192.168.6.1:47808".parse().unwrap();
        cache.learn(gateway(), address);

        assert_eq!(
            cache.resolve(&Recipient::Device(gateway())),
            Some(NotificationTarget::Unicast(address))
        );
    }

    #[test]
    fn learning_again_replaces_the_binding() {
        let cache = AddressCache::new();
        cache.learn(gateway(), "192.168.6.1:47808".parse().unwrap());
        cache.learn(gateway(), "192.168.6.9:47808".parse().unwrap());

        assert_eq!(
            cache.resolve(&Recipient::Device(gateway())),
            unicast("192.168.6.9:47808")
        );
    }

    #[test]
    fn an_address_recipient_resolves_without_a_binding() {
        let cache = AddressCache::new();
        let recipient = Recipient::Address(BacnetAddress {
            network: 0,
            mac_address: vec![192, 168, 6, 1, 0xBA, 0xC0],
        });

        assert_eq!(cache.resolve(&recipient), unicast("192.168.6.1:47808"));
    }

    /// An empty MAC is how a recipient asks to be broadcast to, and it is what a
    /// gateway falls back to when a device rejects a device-form recipient. It
    /// used to resolve to nothing, so every notification to it was dropped.
    #[test]
    fn an_empty_mac_is_a_broadcast_recipient() {
        let cache = AddressCache::new();

        for network in [0, 65535] {
            let recipient = Recipient::Address(BacnetAddress {
                network,
                mac_address: Vec::new(),
            });
            assert_eq!(
                cache.resolve(&recipient),
                Some(NotificationTarget::Broadcast),
                "network {network}"
            );
        }
    }

    #[test]
    fn a_non_ip_mac_does_not_resolve() {
        let cache = AddressCache::new();
        let recipient = Recipient::Address(BacnetAddress {
            network: 1,
            mac_address: vec![0x0A],
        });

        assert!(cache.resolve(&recipient).is_none());
    }
}
