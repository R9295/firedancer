//! Local test-cluster configuration and directed packet-fault policy.

use std::collections::{HashMap, HashSet};
use std::fmt::Write;
use std::path::Path;
pub mod typesafe;
use typesafe::{DropFault, Protocol, Snapshot};

pub const QUEUE: u16 = 0;
// Absorb short validator bursts without making packet buffering unbounded.
// At the 2048-byte copy range, this is at most roughly 16 MiB of packet data.
pub const QUEUE_LEN: u32 = 8192;
// Controller-generated copies must not be queued (and duplicated) again.
pub const COPY_MARK: u32 = 0xfd01;
pub const MAX_DELAY_MS: u64 = 5000;
const MAX_NODES: usize = 128;
const PORT_FIELDS: &[(&str, Option<Protocol>)] = &[
    ("gossip.port", Some(Protocol::Gossip)),
    ("tiles.quic.regular_transaction_listen_port", None),
    ("tiles.quic.quic_transaction_listen_port", None),
    ("tiles.shred.shred_listen_port", Some(Protocol::Shred)),
    (
        "tiles.repair.repair_client_listen_port",
        Some(Protocol::Repair),
    ),
    (
        "tiles.rserve.repair_serve_listen_port",
        Some(Protocol::Repair),
    ),
    ("tiles.txsend.txsend_src_port", None),
    (
        "development.votor.quic_client_listen_port",
        Some(Protocol::Votor),
    ),
    (
        "development.votor.quic_server_listen_port",
        Some(Protocol::Votor),
    ),
];

#[derive(Debug)]
pub struct Node {
    pub name: String,
    pub ports: Vec<u16>,
}

fn field<'a>(value: &'a toml::Value, path: &str) -> Option<&'a toml::Value> {
    path.split('.').try_fold(value, |v, key| v.get(key))
}

impl Node {
    pub fn parse(text: &str) -> Result<Self, String> {
        let value: toml::Value = text.parse().map_err(|e| format!("invalid TOML: {e}"))?;
        // Deliberately scoped to the socket/loopback development cluster.
        for (key, expected) in [
            ("net.provider", "socket"),
            ("net.interface", "lo"),
            ("net.bind_address", "127.0.0.1"),
            ("gossip.host", "127.0.0.1"),
        ] {
            if field(&value, key).and_then(toml::Value::as_str) != Some(expected) {
                return Err(format!("{key} must be explicitly set to {expected:?}"));
            }
        }
        let name = field(&value, "name")
            .and_then(toml::Value::as_str)
            .filter(|s| {
                !s.is_empty()
                    && s.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            })
            .ok_or("name must contain only letters, digits, '-', '_', or '.'")?
            .to_owned();
        let mut ports = Vec::new();
        for (key, _) in PORT_FIELDS {
            let port = field(&value, key)
                .and_then(toml::Value::as_integer)
                .and_then(|n| u16::try_from(n).ok())
                .filter(|n| *n != 0)
                .ok_or_else(|| format!("{key} must explicitly specify a port in 1..65535"))?;
            if ports.contains(&port) {
                return Err(format!("duplicate port {port} in {name}"));
            }
            ports.push(port);
        }
        Ok(Self { name, ports })
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Link {
    pub blocked: bool,
    pub delay_ms: u64,
    pub duplicate: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct Delivery {
    pub src: usize,
    pub dst: usize,
    pub link: Link,
    pub protocol: Option<Protocol>,
}

pub struct Policy {
    pub nodes: Vec<Node>,
    owners: HashMap<u16, (usize, Option<Protocol>)>,
    links: Vec<Link>,
    instance: String,
    typesafe_session: Option<u64>,
    active_drop: Option<DropFault>,
    pub accepted: u64,
    pub dropped: u64,
    pub unclassified: u64,
    pub generation: u64,
    pub duplicated: u64,
    pub delayed: u64,
    pub pending: usize,
    pub overruns: u64,
}

impl Policy {
    pub fn load(paths: &[String]) -> Result<Self, String> {
        let nodes = paths
            .iter()
            .map(|path| {
                let text =
                    std::fs::read_to_string(Path::new(path)).map_err(|e| format!("{path}: {e}"))?;
                Node::parse(&text).map_err(|e| format!("{path}: {e}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(nodes)
    }

    pub fn new(nodes: Vec<Node>) -> Result<Self, String> {
        if !(1..=MAX_NODES).contains(&nodes.len()) {
            return Err(format!("provide between 1 and {MAX_NODES} node configs"));
        }
        let mut owners = HashMap::new();
        let mut names = HashSet::new();
        for (id, node) in nodes.iter().enumerate() {
            if !names.insert(&node.name) {
                return Err(format!("duplicate node name {}", node.name));
            }
            for (&port, (_, protocol)) in node.ports.iter().zip(PORT_FIELDS) {
                if let Some((other, _)) = owners.insert(port, (id, *protocol)) {
                    return Err(format!("port {port} is shared by nodes {other} and {id}"));
                }
            }
        }
        Ok(Self {
            links: vec![Link::default(); nodes.len() * nodes.len()],
            nodes,
            owners,
            instance: format!(
                "{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|e| e.to_string())?
                    .as_nanos()
            ),
            typesafe_session: None,
            active_drop: None,
            accepted: 0,
            dropped: 0,
            unclassified: 0,
            generation: 0,
            duplicated: 0,
            delayed: 0,
            pending: 0,
            overruns: 0,
        })
    }

    /// Rules are installed only after entering a fresh network namespace.
    /// INPUT loss is silent to the sender; OUTPUT drops can return EPERM.
    pub fn rules(&self) -> String {
        let mut ports: Vec<_> = self.owners.keys().copied().collect();
        ports.sort_unstable();
        let ports = ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "table ip fd_cluster_net {{\n\
             set ports {{ type inet_service; elements = {{ {ports} }}; }}\n\
             chain input {{ type filter hook input priority 0; policy accept;\n\
             iifname \"lo\" ip saddr 127.0.0.1 ip daddr 127.0.0.1 udp sport @ports udp dport @ports meta mark != {COPY_MARK} counter queue num {QUEUE}\n\
             }}\n}}\n"
        )
    }

    /// Snapshot the link policy for a new packet. Blocked/unknown packets drop.
    pub fn delivery(&mut self, packet: &[u8]) -> Option<Delivery> {
        let Some((src, dst, protocol)) = self.endpoints(packet) else {
            self.unclassified += 1;
            self.dropped += 1;
            return None;
        };
        let link = self.links[src * self.nodes.len() + dst];
        let delivery = Delivery {
            src,
            dst,
            link,
            protocol,
        };
        if self.is_blocked(delivery) {
            self.dropped += 1;
            return None;
        }
        Some(delivery)
    }

    pub fn is_blocked(&self, delivery: Delivery) -> bool {
        self.links[delivery.src * self.nodes.len() + delivery.dst].blocked
            || self
                .active_drop
                .is_some_and(|fault| fault.matches(delivery.src, delivery.dst, delivery.protocol))
    }

    #[cfg(test)]
    fn accept(&mut self, packet: &[u8]) -> bool {
        self.delivery(packet).is_some()
    }

    fn endpoints(&self, packet: &[u8]) -> Option<(usize, usize, Option<Protocol>)> {
        if packet.len() < 20 || packet[0] >> 4 != 4 || packet[9] != 17 {
            return None;
        }
        let header = usize::from(packet[0] & 15) * 4;
        if header < 20 || packet.len() < header + 8 {
            return None;
        }
        // NFQUEUE can truncate a packet copy; the original stays in the kernel.
        let total = u16::from_be_bytes([packet[2], packet[3]]) as usize;
        let udp_len = u16::from_be_bytes([packet[header + 4], packet[header + 5]]) as usize;
        if total < header + 8
            || udp_len < 8
            || udp_len > total - header
            || u16::from_be_bytes([packet[6], packet[7]]) & 0x3fff != 0
            || packet[12..16] != [127, 0, 0, 1]
            || packet[16..20] != [127, 0, 0, 1]
        {
            return None;
        }
        let src = u16::from_be_bytes([packet[header], packet[header + 1]]);
        let dst = u16::from_be_bytes([packet[header + 2], packet[header + 3]]);
        let (src, _) = *self.owners.get(&src)?;
        let (dst, protocol) = *self.owners.get(&dst)?;
        Some((src, dst, protocol))
    }

    pub fn command(&mut self, command: &str) -> Result<String, String> {
        let words: Vec<_> = command.split_whitespace().collect();
        if self.typesafe_session.is_some()
            && matches!(
                words.first(),
                Some(&("block" | "allow" | "delay" | "duplicate"))
            )
        {
            return Err(
                "TypeSafe owns the fault policy; use heal to stop automatic injection first".into(),
            );
        }
        match words.as_slice() {
            ["status"] => Ok(self.status()),
            ["typesafe-state"] => Ok(self.typesafe_state()),
            ["typesafe-start"] => {
                if self.nodes.len() != 3 {
                    return Err("TypeSafe's 24 choices require exactly three node configs".into());
                }
                if self.typesafe_session.is_some() {
                    return Err("TypeSafe is already running; use heal to stop it first".into());
                }
                self.heal();
                self.typesafe_session = Some(self.generation);
                Ok(self.typesafe_state())
            }
            ["typesafe-end", instance, session] => {
                self.check_session(instance, session)?;
                self.heal();
                Ok(format!("OK generation={}\n", self.generation))
            }
            ["typesafe-drop", instance, session, generation, id] => {
                self.check_session(instance, session)?;
                if generation.parse::<u64>().ok() != Some(self.generation) {
                    return Err("stale TypeSafe selection; policy changed".into());
                }
                let fault = DropFault::parse(id)?;
                // One Option, never a list: replacement cannot stack faults.
                self.active_drop = Some(fault);
                self.generation += 1;
                Ok(format!("OK {}\n", self.fault_message(fault)))
            }
            ["heal"] => {
                self.heal();
                Ok(format!("OK generation={}\n", self.generation))
            }
            [action @ ("block" | "allow"), from, to] => {
                let index = self.link_index(from, to)?;
                self.links[index].blocked = *action == "block";
                self.generation += 1;
                Ok(format!("OK generation={}\n", self.generation))
            }
            ["delay", from, to, millis] => {
                let index = self.link_index(from, to)?;
                let millis: u64 = millis.parse().map_err(|_| "delay must be milliseconds")?;
                if millis > MAX_DELAY_MS {
                    return Err(format!("delay must be in 0..{MAX_DELAY_MS} milliseconds"));
                }
                self.links[index].delay_ms = millis;
                self.generation += 1;
                Ok(format!("OK generation={}\n", self.generation))
            }
            ["duplicate", from, to, copies @ ("0" | "1")] => {
                let index = self.link_index(from, to)?;
                self.links[index].duplicate = *copies == "1";
                self.generation += 1;
                Ok(format!("OK generation={}\n", self.generation))
            }
            _ => Err("expected: status | block FROM TO | allow FROM TO | delay FROM TO MS | duplicate FROM TO 0|1 | heal | stop".into()),
        }
    }

    fn heal(&mut self) {
        self.links.fill(Link::default());
        self.active_drop = None;
        self.typesafe_session = None;
        self.generation += 1;
    }

    fn check_session(&self, instance: &str, session: &str) -> Result<(), String> {
        if instance != self.instance
            || self.typesafe_session.is_none()
            || session.parse::<u64>().ok() != self.typesafe_session
        {
            return Err("TypeSafe session ended or controller restarted".into());
        }
        Ok(())
    }

    fn typesafe_state(&self) -> String {
        let snapshot = Snapshot {
            instance: self.instance.clone(),
            session: self.typesafe_session,
            generation: self.generation,
            node_count: self.nodes.len(),
            active: self.active_drop,
            accepted: self.accepted,
            dropped: self.dropped,
        };
        format!("OK {}\n", serde_json::to_string(&snapshot).unwrap())
    }

    fn fault_message(&self, fault: DropFault) -> String {
        let ports: Vec<_> = self.nodes[fault.dst]
            .ports
            .iter()
            .zip(PORT_FIELDS)
            .filter_map(|(&port, (_, protocol))| fault.includes(*protocol).then_some(port))
            .collect();
        format!(
            "FAULT applied: drop node {} -> node {} {} ports={ports:?} generation={}",
            fault.src,
            fault.dst,
            fault.target.name(),
            self.generation
        )
    }

    fn link_index(&self, from: &str, to: &str) -> Result<usize, String> {
        let from: usize = from.parse().map_err(|_| "invalid source node")?;
        let to: usize = to.parse().map_err(|_| "invalid destination node")?;
        if from >= self.nodes.len() || to >= self.nodes.len() || from == to {
            return Err("use distinct node IDs listed by status".into());
        }
        Ok(from * self.nodes.len() + to)
    }

    pub fn status(&self) -> String {
        let mut out = format!(
            "OK pid={} generation={} accepted={} dropped={} unclassified={} duplicated={} delayed={} pending={} overruns={}\n",
            std::process::id(),
            self.generation,
            self.accepted,
            self.dropped,
            self.unclassified,
            self.duplicated,
            self.delayed,
            self.pending,
            self.overruns
        );
        for (id, node) in self.nodes.iter().enumerate() {
            writeln!(out, "node {id} {} {:?}", node.name, node.ports).unwrap();
        }
        if self.typesafe_session.is_some() {
            writeln!(out, "typesafe automatic (one drop fault maximum)").unwrap();
        }
        if let Some(fault) = self.active_drop {
            writeln!(
                out,
                "{}",
                self.fault_message(fault)
                    .replace("FAULT applied:", "active:")
            )
            .unwrap();
        }
        for src in 0..self.nodes.len() {
            for dst in 0..self.nodes.len() {
                let link = self.links[src * self.nodes.len() + dst];
                if link.blocked {
                    writeln!(out, "blocked {src} -> {dst}").unwrap();
                }
                if link.delay_ms != 0 {
                    writeln!(out, "delay {src} -> {dst} {}ms", link.delay_ms).unwrap();
                }
                if link.duplicate {
                    writeln!(out, "duplicate {src} -> {dst} 1 extra copy").unwrap();
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(n: usize) -> Policy {
        Policy::new(
            (0..n)
                .map(|id| Node {
                    name: format!("node-{id}"),
                    ports: vec![8000 + id as u16],
                })
                .collect(),
        )
        .unwrap()
    }
    fn packet(src: u16, dst: u16) -> Vec<u8> {
        let mut p = vec![0; 28];
        p[0] = 0x45;
        p[3] = 28;
        p[9] = 17;
        p[12..16].copy_from_slice(&[127, 0, 0, 1]);
        p[16..20].copy_from_slice(&[127, 0, 0, 1]);
        p[20..22].copy_from_slice(&src.to_be_bytes());
        p[22..24].copy_from_slice(&dst.to_be_bytes());
        p[25] = 8;
        p
    }
    #[test]
    fn config_requires_explicit_unambiguous_loopback_ports() {
        let mut config = String::from("name = 'node-0'\nnet.provider = 'socket'\nnet.interface = 'lo'\nnet.bind_address = '127.0.0.1'\ngossip.host = '127.0.0.1'\n");
        for (id, (key, _)) in PORT_FIELDS.iter().enumerate() {
            writeln!(config, "{key} = {}", 8000 + id).unwrap();
        }
        let node = Node::parse(&config).unwrap();
        assert_eq!(node.name, "node-0");
        assert_eq!(node.ports, (8000..8009).collect::<Vec<_>>());
        for bad in [
            config.replace("'socket'", "'xdp'"),
            config.replace("'lo'", "'eth0'"),
            config.replace("'127.0.0.1'", "'10.0.0.1'"),
            config.replace("gossip.port = 8000\n", ""),
            config.replace("8000", "0"),
            config.replace("8000", "65536"),
            config.replace("8000", "-1"),
            config.replace("8001", "8000"),
        ] {
            assert!(Node::parse(&bad).is_err(), "accepted invalid config: {bad}");
        }
        assert!(Node::parse("not toml").is_err());
    }
    #[test]
    fn directed_links_and_arbitrary_node_count() {
        for n in [2, 3, 7, 128] {
            let mut p = policy(n);
            let dst = 8000 + (n - 1) as u16;
            assert!(p.accept(&packet(8000, dst)));
            p.command(&format!("block 0 {}", n - 1)).unwrap();
            assert!(!p.accept(&packet(8000, dst)));
            assert!(p.accept(&packet(dst, 8000)));
            p.command(&format!("allow 0 {}", n - 1)).unwrap();
            assert!(p.accept(&packet(8000, dst)));
            p.command(&format!("block 0 {}", n - 1)).unwrap();
            p.command("heal").unwrap();
            assert!(p.accept(&packet(8000, dst)));
        }
    }
    #[test]
    fn single_node_baseline() {
        let mut p = policy(1);
        assert!(p.accept(&packet(8000, 8000)));
        assert!(p.command("block 0 0").is_err());
        assert!(p.command("heal").is_ok());
    }
    #[test]
    fn invalid_commands_do_not_change_policy() {
        let mut p = policy(3);
        for cmd in [
            "block 0 3",
            "block 0 0",
            "block -1 1",
            "allow",
            "delay 0 1 -1",
            "delay 0 1 5001",
            "delay 0 1 18446744073709551616",
            "delay 0 3 10",
            "duplicate 0 1 2",
            "duplicate 0 0 1",
            "heal now",
            "wat",
        ] {
            assert!(p.command(cmd).is_err());
        }
        assert_eq!(p.generation, 0);
        assert!(p.accept(&packet(8000, 8001)));
    }
    #[test]
    fn faults_compose_and_heal_resets_them() {
        let mut p = policy(7);
        p.command("delay 0 6 150").unwrap();
        p.command("duplicate 0 6 1").unwrap();
        let forward = p.delivery(&packet(8000, 8006)).unwrap();
        assert_eq!(forward.link.delay_ms, 150);
        assert!(forward.link.duplicate);
        assert_eq!(
            p.delivery(&packet(8006, 8000)).unwrap().link,
            Link::default()
        );
        p.command("block 0 6").unwrap();
        assert!(p.is_blocked(forward));
        assert!(p.delivery(&packet(8000, 8006)).is_none());
        p.command("allow 0 6").unwrap();
        assert_eq!(p.delivery(&packet(8000, 8006)).unwrap().link, forward.link);
        p.command("duplicate 0 6 0").unwrap();
        assert!(!p.delivery(&packet(8000, 8006)).unwrap().link.duplicate);
        p.command("heal").unwrap();
        assert_eq!(
            p.delivery(&packet(8000, 8006)).unwrap().link,
            Link::default()
        );
    }
    #[test]
    fn header_parsing() {
        let mut p = policy(3);
        let good = packet(8000, 8001);
        for len in 0..good.len() {
            assert!(!p.accept(&good[..len]));
        }
        assert!(!p.accept(&packet(1, 8001)));
        let mut fragment = good.clone();
        fragment[6] = 0x20;
        assert!(!p.accept(&fragment));
        let mut remote = good.clone();
        remote[12] = 10;
        assert!(!p.accept(&remote));
        let mut options = good.clone();
        options.splice(20..20, [0; 4]);
        options[0] = 0x46;
        options[3] = 32;
        assert!(p.accept(&options));
        let mut truncated_payload = good;
        truncated_payload[3] = 100;
        truncated_payload[25] = 80;
        assert!(p.accept(&truncated_payload));
    }
    #[test]
    fn rejects_ambiguous_topology() {
        assert!(Policy::new(vec![]).is_err());
        assert!(Policy::new(vec![
            Node {
                name: "a".into(),
                ports: vec![8001]
            },
            Node {
                name: "b".into(),
                ports: vec![8001]
            }
        ])
        .is_err());
        assert!(Policy::new(vec![
            Node {
                name: "a".into(),
                ports: vec![8001]
            },
            Node {
                name: "a".into(),
                ports: vec![8002]
            }
        ])
        .is_err());
    }
    #[test]
    fn rules_are_scoped_and_fail_closed() {
        let rules = policy(3).rules();
        assert!(rules.contains("elements = { 8000, 8001, 8002 }"));
        assert!(rules.contains("iifname \"lo\" ip saddr 127.0.0.1 ip daddr 127.0.0.1 udp sport @ports udp dport @ports"));
        assert!(rules.contains(&format!("meta mark != {COPY_MARK}")));
        assert!(!rules.contains("bypass"));
        assert!(!rules.contains("flush ruleset"));
    }

    #[test]
    fn typesafe_exhaustively_matches_only_one_direction_and_protocol() {
        let mut p = Policy::new(
            (0..3)
                .map(|id| Node {
                    name: format!("node-{id}"),
                    ports: (0..9).map(|offset| 8000 + id * 100 + offset).collect(),
                })
                .collect(),
        )
        .unwrap();
        p.command("block 0 1").unwrap();
        p.command("delay 2 0 100").unwrap();
        p.command("duplicate 1 2 1").unwrap();
        p.command("typesafe-start").unwrap();
        assert!(p.links.iter().all(|link| *link == Link::default()));
        for fault in DropFault::all() {
            let command = format!(
                "typesafe-drop {} {} {} {}",
                p.instance,
                p.typesafe_session.unwrap(),
                p.generation,
                fault.id()
            );
            let response = p.command(&command).unwrap();
            assert!(response.contains("FAULT applied: drop node"));
            for src in 0..3 {
                for dst in 0..3 {
                    // All source/destination port combinations, including both
                    // client/server ports, reverse links, gossip and TPU.
                    for source_port in p.nodes[src].ports.clone() {
                        for (offset, (_, protocol)) in PORT_FIELDS.iter().enumerate() {
                            let packet = packet(source_port, p.nodes[dst].ports[offset]);
                            let should_drop = fault.matches(src, dst, *protocol);
                            assert_eq!(
                                p.accept(&packet),
                                !should_drop,
                                "{fault:?} {src}->{dst} {protocol:?}"
                            );
                        }
                    }
                }
            }
            assert_eq!(p.status().matches("\nactive:").count(), 1);
        }
        p.command("heal").unwrap();
        assert!(p.active_drop.is_none());
        assert!(p.typesafe_session.is_none());
        assert!(p.accept(&packet(8207, 8008)));
    }

    #[test]
    fn typesafe_rejects_stale_unknown_and_stacked_faults() {
        for n in [1, 2, 4] {
            assert!(policy(n).command("typesafe-start").is_err());
        }
        let mut p = policy(3);
        p.command("typesafe-start").unwrap();
        let prefix = format!(
            "typesafe-drop {} {}",
            p.instance,
            p.typesafe_session.unwrap()
        );
        let command = format!("{prefix} {} drop_0_1_repair", p.generation);
        for invalid in [
            format!("{prefix} {} drop_0_3_repair", p.generation),
            format!("{prefix} {} drop_0_1_gossip", p.generation),
            format!("{prefix} 0 drop_0_1_repair"),
            format!("typesafe-drop wrong 1 {} drop_0_1_repair", p.generation),
            "typesafe-start".into(),
            "block 1 0".into(),
            "allow 0 1".into(),
            "delay 0 1 20".into(),
            "duplicate 0 1 1".into(),
        ] {
            let before = p.status();
            assert!(p.command(&invalid).is_err(), "{invalid}");
            assert_eq!(p.status(), before);
        }
        p.command(&command).unwrap();
        assert!(p.command(&command).is_err()); // Already applied = stale generation.
        let end = format!(
            "typesafe-end {} {}",
            p.instance,
            p.typesafe_session.unwrap()
        );
        p.command("heal").unwrap();
        assert!(p.command(&command).is_err()); // In-flight API response after heal.
        p.command("typesafe-start").unwrap();
        let before = p.status();
        assert!(p.command(&end).is_err()); // Old worker cannot heal a newer worker.
        assert_eq!(p.status(), before);
        let end = format!(
            "typesafe-end {} {}",
            p.instance,
            p.typesafe_session.unwrap()
        );
        p.command(&end).unwrap();
        p.command("block 0 1").unwrap(); // Manual control restored.
    }
}
