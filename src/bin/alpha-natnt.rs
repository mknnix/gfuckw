use std::net::{SocketAddr, UdpSocket};

fn rand() -> u64 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};

    RandomState::new().build_hasher().finish()
}

const UDPN: u64 = 16;

fn udps_new() -> Vec<UdpSocket> {
    let mut a = vec![];
    for _ in 0..UDPN {
        a.push(UdpSocket::bind("0.0.0.0:0").unwrap());
    }
    a
}

fn main() {
    let mut count: u128 = 0;
    let mut udps: Vec<UdpSocket> = udps_new();

    loop {
        count += 1;
        if count >= 234567 {
            count = 0;
            udps = udps_new();
        }

        let i = (rand() as usize) % udps.len();
        let tmp = rand().to_ne_bytes();
        println!("{:?}", udps[i].send_to(
            &[ tmp[6] ], // msg
            format!("{}.{}.{}.{}:{}",
                    tmp[0], tmp[1], tmp[2], tmp[3],

                    u16::from_ne_bytes(
                        [ tmp[4], tmp[5] ]
                    )
                )
        ) );
    }
}

