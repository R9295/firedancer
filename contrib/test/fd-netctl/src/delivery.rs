//! Bounded delayed verdicts and loopback-only copies. Payloads stay encrypted.
use fd_netctl::{Delivery, Policy, COPY_MARK};
use nfq::{Message, Queue, Verdict};
use std::collections::BTreeMap;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

use crate::Result;

// Matches the socket tile's FD_NET_MTU. Larger packets can pass or wait, but
// cannot be duplicated from a truncated copy. Leave room in the kernel queue
// (1024) for new traffic while holding at most this many delayed originals.
pub const COPY_RANGE: u16 = 2048;
const MAX_PENDING: usize = 512;

struct Held {
    message: Message,
    delivery: Delivery,
}

#[derive(Default)]
pub struct Deliveries {
    pending: BTreeMap<(Instant, u64), Held>,
    sequence: u64,
    copier: Option<OwnedFd>,
}

impl Deliveries {
    pub fn receive(
        &mut self,
        mut message: Message,
        queue: &mut Queue,
        policy: &mut Policy,
    ) -> Result<()> {
        let Some(delivery) = policy.delivery(message.get_payload()) else {
            message.set_verdict(Verdict::Drop);
            queue.verdict(message)?;
            return Ok(());
        };
        if delivery.link.duplicate && message.get_payload().len() != message.get_original_len() {
            return Err("duplicate packet exceeds 2048-byte copy limit (test invalid)".into());
        }
        let held = Held { message, delivery };
        if delivery.link.delay_ms == 0 {
            return self.deliver(held, queue, policy);
        }
        if self.pending.len() >= MAX_PENDING {
            return Err("delay buffer full (512 packets; test invalid)".into());
        }
        let deadline = Instant::now() + Duration::from_millis(delivery.link.delay_ms);
        self.pending.insert((deadline, self.sequence), held);
        self.sequence += 1;
        policy.delayed += 1;
        policy.pending = self.pending.len();
        Ok(())
    }

    pub fn release_due(&mut self, queue: &mut Queue, policy: &mut Policy) -> Result<()> {
        let now = Instant::now();
        while self
            .pending
            .first_key_value()
            .is_some_and(|(key, _)| key.0 <= now)
        {
            let (_, held) = self.pending.pop_first().unwrap();
            self.deliver(held, queue, policy)?;
        }
        policy.pending = self.pending.len();
        Ok(())
    }

    // A newly blocked link cannot leak its previously delayed packets. heal
    // releases originals once, suppressing copies scheduled under old policy.
    pub fn policy_changed(
        &mut self,
        heal: bool,
        queue: &mut Queue,
        policy: &mut Policy,
    ) -> Result<()> {
        for (key, mut held) in std::mem::take(&mut self.pending) {
            if heal {
                held.delivery.link.duplicate = false;
                self.deliver(held, queue, policy)?;
            } else if policy.is_blocked(held.delivery) {
                held.message.set_verdict(Verdict::Drop);
                queue.verdict(held.message)?;
                policy.dropped += 1;
            } else {
                self.pending.insert(key, held);
            }
        }
        policy.pending = self.pending.len();
        Ok(())
    }

    fn deliver(&mut self, mut held: Held, queue: &mut Queue, policy: &mut Policy) -> Result<()> {
        let copy = if held.delivery.link.duplicate {
            Some(copy_packet(held.message.get_payload())?)
        } else {
            None
        };
        held.message.set_verdict(Verdict::Accept);
        queue.verdict(held.message)?;
        policy.accepted += 1;
        if let Some(copy) = copy {
            self.send_copy(&copy)?;
            policy.duplicated += 1;
        }
        Ok(())
    }

    fn send_copy(&mut self, packet: &[u8]) -> Result<()> {
        if self.copier.is_none() {
            let fd = unsafe {
                libc::socket(
                    libc::AF_INET,
                    libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                    libc::IPPROTO_RAW,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error().into());
            }
            let fd = unsafe { OwnedFd::from_raw_fd(fd) };
            // nft excludes this mark, so a copy cannot duplicate itself.
            if unsafe {
                libc::setsockopt(
                    fd.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_MARK,
                    (&COPY_MARK as *const u32).cast(),
                    std::mem::size_of::<u32>() as libc::socklen_t,
                )
            } < 0
            {
                return Err(io::Error::last_os_error().into());
            }
            self.copier = Some(fd);
        }
        // The only destination this socket is ever asked to send to is lo.
        let destination = libc::sockaddr_in {
            sin_family: libc::AF_INET as _,
            sin_port: 0,
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes([127, 0, 0, 1]),
            },
            sin_zero: [0; 8],
        };
        let n = unsafe {
            libc::sendto(
                self.copier.as_ref().unwrap().as_raw_fd(),
                packet.as_ptr().cast(),
                packet.len(),
                0,
                (&destination as *const libc::sockaddr_in).cast(),
                std::mem::size_of_val(&destination) as libc::socklen_t,
            )
        };
        if n < 0 {
            return Err(format!(
                "duplicate send failed (test invalid): {}",
                io::Error::last_os_error()
            )
            .into());
        }
        if n as usize != packet.len() {
            return Err("short duplicate send (test invalid)".into());
        }
        Ok(())
    }
}

fn copy_packet(packet: &[u8]) -> Result<Vec<u8>> {
    // Defense in depth: never turn this local test copier into a remote sender.
    if packet.len() < 28
        || packet[0] >> 4 != 4
        || packet[9] != 17
        || packet[12..16] != [127, 0, 0, 1]
        || packet[16..20] != [127, 0, 0, 1]
    {
        return Err("only complete loopback IPv4 UDP packets can be copied".into());
    }
    let header = usize::from(packet[0] & 15) * 4;
    let total = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if header < 20
        || total > packet.len()
        || total < header + 8
        || u16::from_be_bytes([packet[6], packet[7]]) & 0x3fff != 0
    {
        return Err("cannot copy a truncated or fragmented packet".into());
    }
    let udp_len = u16::from_be_bytes([packet[header + 4], packet[header + 5]]) as usize;
    if udp_len < 8 || udp_len > total - header {
        return Err("invalid UDP length".into());
    }
    let mut copy = packet[..total].to_vec();
    // Loopback NFQUEUE data may carry a partial offloaded checksum. Compute the
    // final UDP checksum (RFC 768) without changing the encrypted payload.
    copy[header + 6..header + 8].fill(0);
    let mut sum = 17 + udp_len as u32;
    for pair in copy[12..20].chunks_exact(2) {
        sum += u16::from_be_bytes([pair[0], pair[1]]) as u32;
    }
    for pair in copy[header..header + udp_len].chunks(2) {
        sum += u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let checksum = !(sum as u16);
    copy[header + 6..header + 8]
        .copy_from_slice(&if checksum == 0 { 0xffffu16 } else { checksum }.to_be_bytes());
    // IP_HDRINCL (implicit for IPPROTO_RAW) lets Linux recompute the IP checksum.
    copy[10..12].fill(0);
    Ok(copy)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(payload_len: usize) -> Vec<u8> {
        let mut p = vec![42u8; 28 + payload_len];
        p[..28].fill(0);
        p[0] = 0x45;
        p[2..4].copy_from_slice(&((28 + payload_len) as u16).to_be_bytes());
        p[8] = 64;
        p[9] = 17;
        p[12..16].copy_from_slice(&[127, 0, 0, 1]);
        p[16..20].copy_from_slice(&[127, 0, 0, 1]);
        p[20..22].copy_from_slice(&8001u16.to_be_bytes());
        p[22..24].copy_from_slice(&8101u16.to_be_bytes());
        p[24..26].copy_from_slice(&((8 + payload_len) as u16).to_be_bytes());
        p[26..28].copy_from_slice(&123u16.to_be_bytes()); // partial/offloaded checksum
        p
    }

    #[test]
    fn copies_payload_and_finishes_udp_checksum() {
        for n in [0, 1, 512, 513] {
            let p = packet(n);
            let copy = copy_packet(&p).unwrap();
            assert_eq!(&copy[28..], &p[28..]);
            assert_eq!(&copy[12..26], &p[12..26]);
            let mut pseudo = copy[12..20].to_vec();
            pseudo.extend_from_slice(&[0, 17]);
            pseudo.extend_from_slice(&copy[24..26]);
            pseudo.extend_from_slice(&copy[20..]);
            if pseudo.len() % 2 == 1 {
                pseudo.push(0);
            }
            let mut sum: u32 = pseudo
                .chunks_exact(2)
                .map(|pair| u16::from_be_bytes([pair[0], pair[1]]) as u32)
                .sum();
            while sum > 65535 {
                sum = (sum & 65535) + (sum >> 16);
            }
            assert_eq!(sum, 65535);
        }
    }

    #[test]
    fn refuses_remote_fragmented_and_truncated_copies() {
        let p = packet(10);
        for n in 0..p.len() {
            assert!(copy_packet(&p[..n]).is_err());
        }
        let mut remote = p.clone();
        remote[12] = 10;
        assert!(copy_packet(&remote).is_err());
        let mut remote = p.clone();
        remote[16] = 10;
        assert!(copy_packet(&remote).is_err());
        let mut fragment = p.clone();
        fragment[6] = 0x20;
        assert!(copy_packet(&fragment).is_err());
        let mut bad = p.clone();
        bad[0] = 0x4f;
        assert!(copy_packet(&bad).is_err());
        let mut bad = p;
        bad[25] = 7;
        assert!(copy_packet(&bad).is_err());
    }
}
