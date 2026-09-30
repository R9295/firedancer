//! TypeSafe chooses one single-node network partition. Rust owns execution.
//! The API client runs in the caller's network namespace, never the packet loop.

use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::error::Error;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const API_URL: &str = "https://api.typesafe.ai/v1/systemone";
const MAX_RESPONSE: u64 = 64 * 1024;
pub const DEFAULT_INTERVAL_SECS: u64 = 1;
pub const MAX_PARTITION_NODES: usize = 128;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Gossip,
    Repair,
    Shred,
    Votor,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PartitionFault {
    pub isolated: usize,
}

impl PartitionFault {
    pub fn all(node_count: usize) -> impl Iterator<Item = Self> {
        (0..node_count).map(|isolated| Self { isolated })
    }

    pub fn id(self) -> String {
        format!("partition_node_{}", self.isolated)
    }

    pub fn parse(id: &str, node_count: usize) -> std::result::Result<Self, String> {
        Self::all(node_count)
            .find(|fault| fault.id() == id)
            .ok_or_else(|| "unknown network partition".into())
    }

    pub fn matches(self, src: usize, dst: usize, protocol: Option<Protocol>) -> bool {
        protocol.is_some() && src != dst && ((src == self.isolated) != (dst == self.isolated))
    }
}

/// Intentionally excludes config paths, node names, payloads, and logs.
#[derive(Debug, Deserialize, Serialize)]
pub struct Snapshot {
    pub instance: String,
    pub session: Option<u64>,
    pub generation: u64,
    pub node_count: usize,
    pub active: Option<PartitionFault>,
    pub accepted: u64,
    pub dropped: u64,
}

fn request(
    snapshot: &Snapshot,
    applications: &BTreeMap<String, u64>,
    interval: Duration,
    model: &str,
) -> Value {
    let criteria: BTreeMap<_, _> = PartitionFault::all(snapshot.node_count)
        .map(|fault| {
            let description = format!(
                "Isolate node {} from every other node. Drop Gossip, Repair, Shred, and Votor UDP traffic across the cut in both directions; preserve traffic among the other nodes and all transaction traffic.",
                fault.isolated
            );
            (fault.id(), description)
        })
        .collect();
    json!({
        "model": model,
        "state": {
            "environment": format!("Owned, isolated, {}-node loopback test cluster", snapshot.node_count),
            "purpose": "Exercise recovery from rotating single-node network partitions",
            "interval_seconds": interval.as_secs(),
            "active_partition": snapshot.active,
            "applications_this_session": applications,
            "packets": { "accepted": snapshot.accepted, "dropped": snapshot.dropped },
            "partitioned_protocols": ["gossip", "repair", "shred", "votor"],
            "preserved_protocols": ["transaction"]
        },
        "questions": { "partition": {
            "type": "choice",
            "instructions": "Choose the next single-node network partition for this local resilience test. Use `applications_this_session` to prefer less-exercised nodes, where a missing count means zero. Avoid repeating `active_partition` when another choice is available. Select exactly one node; its bidirectional partition replaces the previous partition. No additional faults or actions are permitted.",
            "criteria": criteria
        }}
    })
}

#[derive(Deserialize)]
struct Response {
    answers: Answers,
}
#[derive(Deserialize)]
struct Answers {
    partition: Answer,
}
#[derive(Deserialize)]
struct Answer {
    #[serde(rename = "type")]
    kind: String,
    choice: String,
    confidence: f64,
    probabilities: BTreeMap<String, f64>,
}

fn selection(body: &[u8], node_count: usize) -> Result<PartitionFault> {
    let response: Response =
        serde_json::from_slice(body).map_err(|_| "invalid TypeSafe response schema")?;
    let answer = response.answers.partition;
    let fault = PartitionFault::parse(&answer.choice, node_count)?;
    if answer.kind != "choice"
        || !(0.0..=1.0).contains(&answer.confidence)
        || answer.probabilities.len() != node_count
        || PartitionFault::all(node_count).any(|f| {
            !answer
                .probabilities
                .get(&f.id())
                .is_some_and(|p| (0.0..=1.0).contains(p))
        })
        || (answer.probabilities.values().sum::<f64>() - 1.0).abs() > 0.02
        || answer
            .probabilities
            .values()
            .any(|p| *p > answer.probabilities[&answer.choice] + 1e-6)
    {
        return Err("invalid TypeSafe choice distribution".into());
    }
    // Low confidence is not a veto: every candidate is an allowed, bounded
    // test case, and several equally useful next cases can split probability.
    Ok(fault)
}

struct Api {
    client: Client,
    authorization: reqwest::header::HeaderValue,
    model: String,
}

impl Api {
    fn new(key: &str, model: String) -> Result<Self> {
        if key.trim().is_empty() {
            return Err("set TYPESAFE_API_KEY".into());
        }
        let mut authorization = reqwest::header::HeaderValue::from_str(&format!("Bearer {key}"))
            .map_err(|_| "invalid TYPESAFE_API_KEY")?;
        authorization.set_sensitive(true);
        Ok(Self {
            client: Client::builder()
                .timeout(Duration::from_secs(10))
                .connect_timeout(Duration::from_secs(5))
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            authorization,
            model,
        })
    }

    fn choose(
        &self,
        snapshot: &Snapshot,
        applications: &BTreeMap<String, u64>,
        interval: Duration,
    ) -> Result<PartitionFault> {
        self.post(
            API_URL,
            &request(snapshot, applications, interval, &self.model),
            snapshot.node_count,
        )
    }

    fn post(&self, url: &str, body: &Value, node_count: usize) -> Result<PartitionFault> {
        let response = self
            .client
            .post(url)
            .header(reqwest::header::AUTHORIZATION, self.authorization.clone())
            .json(body)
            .send()
            .map_err(|_| "TypeSafe request failed (network/TLS/timeout)")?;
        if !response.status().is_success() {
            // Never print service bodies or credentials.
            return Err(format!("TypeSafe HTTP {}", response.status().as_u16()).into());
        }
        let mut body = Vec::new();
        response
            .take(MAX_RESPONSE + 1)
            .read_to_end(&mut body)
            .map_err(|_| "could not read TypeSafe response")?;
        if body.len() as u64 > MAX_RESPONSE {
            return Err("TypeSafe response too large".into());
        }
        selection(&body, node_count)
    }
}

fn exchange(socket: &str, command: &str) -> Result<String> {
    let mut stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    writeln!(stream, "{command}")?;
    let mut response = String::new();
    stream
        .take(MAX_RESPONSE + 1)
        .read_to_string(&mut response)?;
    if response.len() as u64 > MAX_RESPONSE {
        return Err("controller response too large".into());
    }
    response
        .strip_prefix("OK ")
        .map(str::to_owned)
        .ok_or_else(|| format!("controller: {}", response.trim()).into())
}

struct Session<'a> {
    socket: &'a str,
    instance: String,
    token: u64,
}
impl Drop for Session<'_> {
    fn drop(&mut self) {
        // A stopped/restarted controller or a newer session must not be healed.
        let _ = exchange(
            self.socket,
            &format!("typesafe-end {} {}", self.instance, self.token),
        );
    }
}

pub fn interval(text: Option<&str>) -> Result<Duration> {
    let seconds = text
        .map(str::parse::<u64>)
        .transpose()
        .map_err(|_| "TypeSafe interval must be whole seconds in 1..3600")?
        .unwrap_or(DEFAULT_INTERVAL_SECS);
    if !(1..=3600).contains(&seconds) {
        return Err("TypeSafe interval must be in 1..3600 seconds".into());
    }
    Ok(Duration::from_secs(seconds))
}

/// Foreground host-side worker; Ctrl-C/SIGTERM heals only its own session.
pub fn run(socket: &str, interval: Duration) -> Result<()> {
    let key = std::env::var("TYPESAFE_API_KEY").map_err(|_| "set TYPESAFE_API_KEY")?;
    let api = Api::new(
        &key,
        std::env::var("TYPESAFE_MODEL").unwrap_or_else(|_| "jev-latest".into()),
    )?;
    let stop = Arc::new(AtomicBool::new(false));
    let signal_stop = Arc::clone(&stop);
    ctrlc::set_handler(move || signal_stop.store(true, Ordering::Relaxed))?;
    run_session(socket, interval, &stop, |snapshot, applications| {
        api.choose(snapshot, applications, interval)
    })
}

fn run_session(
    socket: &str,
    interval: Duration,
    stop: &AtomicBool,
    mut choose: impl FnMut(&Snapshot, &BTreeMap<String, u64>) -> Result<PartitionFault>,
) -> Result<()> {
    let snapshot: Snapshot = serde_json::from_str(&exchange(socket, "typesafe-start")?)?;
    let node_count = snapshot.node_count;
    let session = Session {
        socket,
        instance: snapshot.instance,
        token: snapshot.session.ok_or("missing TypeSafe session")?,
    };
    if !(2..=MAX_PARTITION_NODES).contains(&node_count) {
        return Err(format!("TypeSafe partitions require 2..={MAX_PARTITION_NODES} nodes").into());
    }
    println!("TypeSafe: {node_count} single-node partition choices, one active partition, interval={}s; Ctrl-C or netctl heal stops injection.", interval.as_secs());
    let mut applications: BTreeMap<_, _> = PartitionFault::all(node_count)
        .map(|fault| (fault.id(), 0))
        .collect();
    let mut deadline = Instant::now();
    while !stop.load(Ordering::Relaxed) {
        // Fixed cadence, one outstanding request, no catch-up bursts. Poll the
        // session while waiting so stop/heal/controller exit ends this worker.
        let snapshot: Snapshot = serde_json::from_str(&exchange(socket, "typesafe-state")?)?;
        if snapshot.instance != session.instance || snapshot.session != Some(session.token) {
            break;
        }
        if Instant::now() < deadline {
            std::thread::sleep(
                Duration::from_millis(100).min(deadline.saturating_duration_since(Instant::now())),
            );
            continue;
        }
        match choose(&snapshot, &applications) {
            Ok(fault) if !stop.load(Ordering::Relaxed) => {
                let response = exchange(
                    socket,
                    &format!(
                        "typesafe-partition {} {} {} {}",
                        session.instance,
                        session.token,
                        snapshot.generation,
                        fault.id()
                    ),
                )?;
                *applications.get_mut(&fault.id()).unwrap() += 1;
                print!("{response}"); // Controller acknowledgement, not a prediction.
            }
            Ok(_) => break,
            Err(e) => {
                eprintln!("TypeSafe: {e}; keeping current partition, retrying next interval")
            }
        }
        deadline += interval;
        while deadline <= Instant::now() {
            deadline += interval;
        }
    }
    drop(session);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::net::TcpListener;
    use std::os::unix::net::UnixListener;
    use std::sync::Mutex;

    fn snapshot() -> Snapshot {
        Snapshot {
            instance: "local-instance".into(),
            session: Some(1),
            generation: 1,
            node_count: 10,
            active: None,
            accepted: 100,
            dropped: 0,
        }
    }

    fn response(fault: PartitionFault, node_count: usize) -> Value {
        let probabilities: BTreeMap<_, _> = PartitionFault::all(node_count)
            .map(|f| (f.id(), if f == fault { 1.0 } else { 0.0 }))
            .collect();
        json!({ "answers": { "partition": { "type": "choice", "choice": fault.id(),
            "confidence": 1.0, "probabilities": probabilities }}})
    }

    #[test]
    fn one_closed_partition_choice_per_node() {
        let faults: Vec<_> = PartitionFault::all(10).collect();
        let ids: std::collections::HashSet<_> = faults.iter().map(|f| f.id()).collect();
        assert_eq!(ids.len(), 10);
        assert_eq!(faults[0].id(), "partition_node_0");
        assert_eq!(faults[9].id(), "partition_node_9");
        assert!(faults[3].matches(3, 7, Some(Protocol::Votor)));
        assert!(faults[3].matches(7, 3, Some(Protocol::Gossip)));
        assert!(!faults[3].matches(7, 8, Some(Protocol::Repair)));
        assert!(!faults[3].matches(3, 7, None));
        let body = request(
            &snapshot(),
            &BTreeMap::new(),
            Duration::from_secs(10),
            "jev-latest",
        );
        assert_eq!(body["questions"].as_object().unwrap().len(), 1);
        assert_eq!(body["questions"]["partition"]["type"], "choice");
        assert_eq!(
            body["questions"]["partition"]["criteria"]
                .as_object()
                .unwrap()
                .len(),
            10
        );
        assert!(
            body["questions"]["partition"]["criteria"]["partition_node_1"]
                .as_str()
                .unwrap()
                .contains("both directions")
        );
        assert!(!body.to_string().contains("local-instance"));
        for fault in faults {
            assert!(body["questions"]["partition"]["criteria"]
                .get(fault.id())
                .is_some());
            assert_eq!(
                selection(&serde_json::to_vec(&response(fault, 10)).unwrap(), 10).unwrap(),
                fault
            );
        }
    }

    #[test]
    fn rejects_invalid_responses_but_accepts_uncertain_valid_choices() {
        let fault = PartitionFault::all(10).next().unwrap();
        let valid = response(fault, 10);
        for (key, value) in [
            ("choice", json!("partition_node_10")),
            ("choice", json!([fault.id()])),
            ("type", json!("score")),
            ("confidence", json!(-1)),
            ("probabilities", json!({})),
        ] {
            let mut bad = valid.clone();
            bad["answers"]["partition"][key] = value;
            assert!(selection(&serde_json::to_vec(&bad).unwrap(), 10).is_err());
        }
        for bad in [b"{}".as_slice(), b"not json", b"{\"answers\":{}}"] {
            assert!(selection(bad, 10).is_err());
        }
        let mut uniform = valid;
        uniform["answers"]["partition"]["confidence"] = json!(0.0);
        for probability in uniform["answers"]["partition"]["probabilities"]
            .as_object_mut()
            .unwrap()
            .values_mut()
        {
            *probability = json!(0.1);
        }
        assert_eq!(
            selection(&serde_json::to_vec(&uniform).unwrap(), 10).unwrap(),
            fault
        );
    }

    #[test]
    fn interval_is_bounded() {
        assert_eq!(interval(None).unwrap().as_secs(), 1);
        for invalid in ["0", "-1", "1.5", "3601", "18446744073709551616"] {
            assert!(interval(Some(invalid)).is_err());
        }
        assert_eq!(interval(Some("1")).unwrap().as_secs(), 1);
        assert_eq!(interval(Some("3600")).unwrap().as_secs(), 3600);
        assert!(Api::new("", "jev-latest".into()).is_err());
        assert!(Api::new("key\nheader", "jev-latest".into()).is_err());
    }

    #[test]
    fn http_contract_errors_redirects_and_response_limit() {
        let fault = PartitionFault::all(10).next().unwrap();
        let mut api = Api::new("test-key", "jev-latest".into()).unwrap();
        api.client = Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(2))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        for (case, (status, body)) in [
            (200, response(fault, 10).to_string()),
            (401, "test-key".into()),
            (429, "rate limited".into()),
            (302, "redirect".into()),
            (200, "bad json".into()),
            (200, " ".repeat(MAX_RESPONSE as usize + 1)),
        ]
        .into_iter()
        .enumerate()
        {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let url = format!("http://{}/v1/systemone", listener.local_addr().unwrap());
            let expected = request(
                &snapshot(),
                &BTreeMap::new(),
                Duration::from_secs(10),
                "jev-latest",
            );
            let sent = expected.clone();
            let worker = std::thread::spawn(move || {
                let (mut socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut reader = BufReader::new(&socket);
                let mut header = String::new();
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" {
                        break;
                    }
                    assert!(!line.is_empty());
                    header.push_str(&line);
                }
                assert!(header.starts_with("POST /v1/systemone HTTP/1.1\r\n"));
                let lower = header.to_ascii_lowercase();
                assert!(lower.contains("authorization: bearer test-key\r\n"));
                assert!(lower.contains("content-type: application/json\r\n"));
                let len: usize = lower
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length: "))
                    .unwrap()
                    .trim()
                    .parse()
                    .unwrap();
                let mut bytes = vec![0; len];
                reader.read_exact(&mut bytes).unwrap();
                assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap(), sent);
                write!(socket, "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nLocation: http://127.0.0.1:1/never-follow\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            });
            let result = api.post(&url, &expected, 10);
            worker.join().unwrap();
            assert_eq!(result.is_ok(), case == 0, "case {case}: {result:?}");
            if let Ok(selected) = result {
                assert_eq!(selected, fault);
                assert_eq!(status, 200);
            } else {
                assert!(!result.unwrap_err().to_string().contains("test-key"));
            }
        }
    }

    #[test]
    fn automatic_ticks_replace_keep_on_error_and_heal_on_stop() {
        use crate::{Node, Policy};
        let socket = format!(
            "/tmp/fd-typesafe-{}-{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        let policy = Arc::new(Mutex::new(
            Policy::new(
                (0..3)
                    .map(|id| Node {
                        name: format!("node-{id}"),
                        ports: vec![8000 + id],
                    })
                    .collect(),
            )
            .unwrap(),
        ));
        let server_done = Arc::new(AtomicBool::new(false));
        let done = Arc::clone(&server_done);
        let shared = Arc::clone(&policy);
        let server = std::thread::spawn(move || {
            while !done.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut client, _)) => {
                        client
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        let mut line = String::new();
                        BufReader::new(&client).read_line(&mut line).unwrap();
                        let response = shared
                            .lock()
                            .unwrap()
                            .command(&line)
                            .unwrap_or_else(|e| format!("ERR {e}\n"));
                        client.write_all(response.as_bytes()).unwrap();
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(1))
                    }
                    Err(e) => panic!("{e}"),
                }
            }
        });
        let stop = AtomicBool::new(false);
        let faults: Vec<_> = PartitionFault::all(3).collect();
        let mut ticks = Vec::new();
        let result = run_session(
            &socket,
            Duration::from_millis(20),
            &stop,
            |state, applications| {
                ticks.push(Instant::now());
                match ticks.len() {
                    1 => {
                        assert!(state.active.is_none());
                        Ok(faults[0])
                    }
                    2 => {
                        assert_eq!(state.active, Some(faults[0]));
                        Err("mock timeout".into())
                    }
                    3 => {
                        assert_eq!(state.active, Some(faults[0]));
                        assert_eq!(applications[&faults[0].id()], 1);
                        Ok(faults[1])
                    }
                    4 => {
                        assert_eq!(state.active, Some(faults[1]));
                        stop.store(true, Ordering::Relaxed);
                        Ok(faults[2])
                    }
                    _ => panic!("worker did not stop"),
                }
            },
        );
        server_done.store(true, Ordering::Relaxed);
        server.join().unwrap();
        std::fs::remove_file(&socket).unwrap();
        result.unwrap();
        assert_eq!(ticks.len(), 4);
        assert!(ticks[3].duration_since(ticks[0]) >= Duration::from_millis(55));
        let mut policy = policy.lock().unwrap();
        let state: Snapshot = serde_json::from_str(
            policy
                .command("typesafe-state")
                .unwrap()
                .strip_prefix("OK ")
                .unwrap(),
        )
        .unwrap();
        assert!(state.active.is_none());
        assert!(state.session.is_none());
        assert_eq!(state.generation, 4); // start, two selections, end; no post-stop apply.
    }
}
