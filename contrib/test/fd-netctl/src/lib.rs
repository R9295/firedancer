//! Local test-cluster configuration and directed packet-fault policy.

use std::collections::{HashMap, HashSet};
use std::fmt::Write;
use std::path::Path;
pub mod typesafe;
use typesafe::{PartitionFault, Protocol, Snapshot, MAX_PARTITION_NODES};

pub const QUEUE: u16 = 0;
// Absorb short validator bursts without making packet buffering unbounded.
// At the 2048-byte copy range, this is at most roughly 16 MiB of packet data.
pub const QUEUE_LEN: u32 = 8192;
// Delayed originals wait in the kernel queue. Hold at most half of it, so
// new traffic always has room.
pub const MAX_PENDING: usize = QUEUE_LEN as usize / 2;
// Controller-generated copies must not be queued (and duplicated) again.
pub const COPY_MARK: u32 = 0xfd01;
pub const MAX_DELAY_MS: u64 = 5000;
// One control command line, which an apply rule set can make long.
pub const MAX_COMMAND: usize = 64 * 1024;
const USAGE: &str = "expected: status | block FROM TO | allow FROM TO | delay FROM TO MS | duplicate FROM TO 0|1 | loss FROM TO PCT | apply [RULE, ...] | heal | stop";
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
    /// Percent of new packets dropped at random, 0..100.
    pub loss_pct: u8,
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
    active_partition: Option<PartitionFault>,
    pub accepted: u64,
    pub dropped: u64,
    pub unclassified: u64,
    pub generation: u64,
    pub duplicated: u64,
    pub delayed: u64,
    pub pending: usize,
    pub overruns: u64,
    pub lost: u64,
    // xorshift64 state for random loss; never zero.
    rng: u64,
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
            active_partition: None,
            accepted: 0,
            dropped: 0,
            unclassified: 0,
            generation: 0,
            duplicated: 0,
            delayed: 0,
            pending: 0,
            overruns: 0,
            lost: 0,
            rng: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| e.to_string())?
                .as_nanos() as u64
                | 1,
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
        if link.loss_pct != 0 && self.next_random() % 100 < u64::from(link.loss_pct) {
            self.dropped += 1;
            self.lost += 1;
            return None;
        }
        Some(delivery)
    }

    fn next_random(&mut self) -> u64 {
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        self.rng
    }

    pub fn is_blocked(&self, delivery: Delivery) -> bool {
        self.links[delivery.src * self.nodes.len() + delivery.dst].blocked
            || self
                .active_partition
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
                Some(&("block" | "allow" | "delay" | "duplicate" | "loss" | "apply"))
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
                if !(2..=MAX_PARTITION_NODES).contains(&self.nodes.len()) {
                    return Err(format!(
                        "TypeSafe partitions require between 2 and {MAX_PARTITION_NODES} node configs"
                    ));
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
            ["typesafe-partition", instance, session, generation, id] => {
                self.check_session(instance, session)?;
                if generation.parse::<u64>().ok() != Some(self.generation) {
                    return Err("stale TypeSafe selection; policy changed".into());
                }
                let fault = PartitionFault::parse(id, self.nodes.len())?;
                // One Option, never a list: replacement cannot stack partitions.
                self.active_partition = Some(fault);
                self.generation += 1;
                Ok(format!("OK {}\n", self.fault_message(fault)))
            }
            ["heal"] => {
                self.heal();
                Ok(format!("OK generation={}\n", self.generation))
            }
            ["block" | "allow" | "delay" | "duplicate" | "loss", ..] => {
                let mut links = self.links.clone();
                self.set_rule(&mut links, &words)?;
                self.links = links;
                self.generation += 1;
                Ok(format!("OK generation={}\n", self.generation))
            }
            ["apply", ..] => {
                // The rules are everything after the command word.
                let rules = &command.trim_start()["apply".len()..];
                let mut links = vec![Link::default(); self.links.len()];
                if !rules.trim().is_empty() {
                    for rule in rules.split(',') {
                        let words: Vec<_> = rule.split_whitespace().collect();
                        self.set_rule(&mut links, &words)
                            .map_err(|e| format!("rule `{}`: {e}", rule.trim()))?;
                    }
                }
                self.links = links;
                self.active_partition = None;
                self.generation += 1;
                Ok(format!("OK generation={}\n", self.generation))
            }
            _ => Err(USAGE.into()),
        }
    }

    /// Sets one directed link rule in links (one entry per ordered node
    /// pair), or returns why the rule is invalid.
    fn set_rule(&self, links: &mut [Link], words: &[&str]) -> Result<(), String> {
        match words {
            [action @ ("block" | "allow"), from, to] => {
                links[self.link_index(from, to)?].blocked = *action == "block";
            }
            ["delay", from, to, millis] => {
                let index = self.link_index(from, to)?;
                let millis: u64 = millis.parse().map_err(|_| "delay must be milliseconds")?;
                if millis > MAX_DELAY_MS {
                    return Err(format!("delay must be in 0..{MAX_DELAY_MS} milliseconds"));
                }
                links[index].delay_ms = millis;
            }
            ["duplicate", from, to, copies @ ("0" | "1")] => {
                links[self.link_index(from, to)?].duplicate = *copies == "1";
            }
            ["loss", from, to, pct] => {
                let index = self.link_index(from, to)?;
                links[index].loss_pct = match pct.parse::<u8>() {
                    Ok(pct) if pct <= 100 => pct,
                    _ => return Err("loss must be a percent in 0..100".into()),
                };
            }
            _ => return Err(USAGE.into()),
        }
        Ok(())
    }

    fn heal(&mut self) {
        self.links.fill(Link::default());
        self.active_partition = None;
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
            active: self.active_partition,
            accepted: self.accepted,
            dropped: self.dropped,
        };
        format!("OK {}\n", serde_json::to_string(&snapshot).unwrap())
    }

    fn fault_message(&self, fault: PartitionFault) -> String {
        let connected: Vec<_> = (0..self.nodes.len())
            .filter(|node| *node != fault.isolated)
            .collect();
        format!(
            "FAULT applied: partition [{}] | {connected:?} protocols=[gossip,repair,shred,votor] generation={}",
            fault.isolated,
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
            "OK pid={} generation={} accepted={} dropped={} lost={} unclassified={} duplicated={} delayed={} pending={} overruns={}\n",
            std::process::id(),
            self.generation,
            self.accepted,
            self.dropped,
            self.lost,
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
            writeln!(out, "typesafe automatic (one network partition maximum)").unwrap();
        }
        if let Some(fault) = self.active_partition {
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
                if link.loss_pct != 0 {
                    writeln!(out, "loss {src} -> {dst} {}%", link.loss_pct).unwrap();
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
    fn loss_drops_about_its_share_of_one_directed_link() {
        let mut p = policy(2);
        p.command("loss 0 1 30").unwrap();
        let kept = (0..10_000).filter(|_| p.accept(&packet(8000, 8001))).count();
        assert!((6_500..7_500).contains(&kept), "kept {kept} of 10000 at 30% loss");
        assert_eq!(p.lost, 10_000 - kept as u64);
        assert!((0..1_000).all(|_| p.accept(&packet(8001, 8000))));
        p.command("apply loss 0 1 100").unwrap();
        assert!(!p.accept(&packet(8000, 8001)));
        assert!(p.command("loss 0 1 101").is_err());
        p.command("heal").unwrap();
        assert!(p.accept(&packet(8000, 8001)));
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
    fn apply_replaces_the_whole_policy_at_once() {
        let mut p = policy(4);
        p.command("block 0 1").unwrap();
        p.command("delay 1 2 100").unwrap();
        let generation = p.generation;
        p.command("apply block 2 3, block 3 2,delay 0 3 50 , duplicate 3 0 1\n")
            .unwrap();
        assert_eq!(p.generation, generation + 1);
        // The rules it does not list are gone.
        assert!(p.accept(&packet(8000, 8001)));
        assert_eq!(
            p.delivery(&packet(8001, 8002)).unwrap().link,
            Link::default()
        );
        assert!(!p.accept(&packet(8002, 8003)));
        assert!(!p.accept(&packet(8003, 8002)));
        assert_eq!(p.delivery(&packet(8000, 8003)).unwrap().link.delay_ms, 50);
        assert!(p.delivery(&packet(8003, 8000)).unwrap().link.duplicate);

        // One invalid rule anywhere changes nothing.
        for bad in [
            "apply block 0 1, delay 1 2 5001",
            "apply block 0 1,, block 1 0",
            "apply block 0 1,",
            "apply block 0 4",
            "apply block 0 1 delay 1 2 3",
            "apply heal",
            "apply wat 0 1",
            "applyblock 0 1",
        ] {
            assert!(p.command(bad).is_err(), "accepted {bad}");
        }
        assert_eq!(p.generation, generation + 1);
        assert!(!p.accept(&packet(8002, 8003)));

        // No rules heals every link.
        p.command("apply").unwrap();
        for (src, dst) in [(8002, 8003), (8003, 8002), (8000, 8003), (8003, 8000)] {
            assert_eq!(p.delivery(&packet(src, dst)).unwrap().link, Link::default());
        }

        // TypeSafe owns the policy until heal.
        p.command("typesafe-start").unwrap();
        assert!(p.command("apply block 0 1").is_err());
        p.command("heal").unwrap();
        p.command("apply block 0 1").unwrap();
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
    fn typesafe_partition_is_bidirectional_and_protocol_scoped() {
        let mut p = Policy::new(
            (0..10)
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
        for fault in PartitionFault::all(10) {
            let command = format!(
                "typesafe-partition {} {} {} {}",
                p.instance,
                p.typesafe_session.unwrap(),
                p.generation,
                fault.id()
            );
            let response = p.command(&command).unwrap();
            assert!(response.contains("FAULT applied: partition"));
            for src in 0..10 {
                for dst in 0..10 {
                    // All source/destination port combinations, including both
                    // directions, client/server ports, gossip and TPU.
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
        assert!(p.active_partition.is_none());
        assert!(p.typesafe_session.is_none());
        assert!(p.accept(&packet(8907, 8008)));
    }

    #[test]
    fn typesafe_rejects_stale_unknown_and_stacked_faults() {
        assert!(policy(1).command("typesafe-start").is_err());
        for n in [2, 4, 10, 128] {
            assert!(policy(n).command("typesafe-start").is_ok());
        }
        let mut p = policy(3);
        p.command("typesafe-start").unwrap();
        let prefix = format!(
            "typesafe-partition {} {}",
            p.instance,
            p.typesafe_session.unwrap()
        );
        let command = format!("{prefix} {} partition_node_1", p.generation);
        for invalid in [
            format!("{prefix} {} partition_node_3", p.generation),
            format!("{prefix} {} partition_1", p.generation),
            format!("{prefix} 0 partition_node_1"),
            format!(
                "typesafe-partition wrong 1 {} partition_node_1",
                p.generation
            ),
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
