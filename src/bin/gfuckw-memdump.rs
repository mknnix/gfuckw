use std::net::SocketAddr;
use smol::net::UdpSocket;
use fastrand;

const LETTERS: &[u8; 52] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

struct Payload;
impl Payload {
    pub fn short() -> Vec<u8> {
        let mut p = vec![];
        p.extend(fastrand::u16(..).to_ne_bytes());
        p.extend(b"\x00\x00\x01\x00\x00\x02\x00\x00\x00\x00\x00\x00\x014\xfftt");
        p
    }

    pub fn co() -> Vec<u8> {
        let mut p = vec![];
        p.extend(fastrand::u16(..).to_ne_bytes());
        p.extend(b"\x01\x00\x00\x02\x00\x00\x00\x00\x00\x00");
        p.extend(b"\x09google.co\xff");
        if fastrand::bool() {
            for _ in 0..2 {
                p.push(LETTERS[ fastrand::usize(..) % 52 ]);
            }
        }
        p.push(0x00);

        p
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum DumpKind {
    DNS,
}

#[derive(Debug, Clone)]
struct Dumper {
    socket: UdpSocket,
    interval: Option<Duration>,
}
impl Dumper {
    pub fn new(kind: DumpKind) {
        if kind != DumpKind::DNS {
            panic!("sorry, for now this program does not support any dump mode other than UDP DNS.");
        }

        Self {
            socket: UdpSocket::bind("[::]:0"),
            interval: None,
        }
    }

    pub fn is_running(&self) -> bool {
        true
    }

    pub fn set_interval(&mut self, time: Duration) {
        self.interval = Some(time);
    }

    pub fn send(&self) -> Option<(SocketAddr, usize)> {
        let n = fastrand::u128(..) % 100;
        if n < 10 { return None; }

        let msg = if fastrand::bool() {
            Payload::short()
        } else {
            Payload::co()
        };

        assert!(msg.len() > 0);
    }
}

async fn amain() {
    println!("{:?}\n\n{:?}", Payload::short(), Payload::co());
}

fn main() { smol::block_on(amain()) }

