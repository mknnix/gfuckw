use std::net::{SocketAddr, IpAddr, Ipv4Addr, UdpSocket};
use std::thread;

fn rand() -> u64 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};

    RandomState::new().build_hasher().finish()
}

const THREADS: u64 = 60000;

/*fn udps_new() -> Vec<UdpSocket> {
    let mut a = vec![];
    for _ in 0..UDPN {
        a.push(UdpSocket::bind("0.0.0.0:0").unwrap());
    }
}*/

fn rand_sendto() -> (Vec<u8>, SocketAddr) {
    loop {
        let r = rand().to_ne_bytes();
        let ip = Ipv4Addr::new(r[0], r[1], r[2], r[3]);
        if ip.is_unspecified() || ip.is_loopback() || ip.is_private() || ip.is_link_local() {
            continue;
        }

        #[cfg(feature = "nightly")]
        if ! ip.is_global() {
            continue;
        }

        let port = u16::from_ne_bytes([ r[4], r[5] ]);
        let addr = SocketAddr::new(IpAddr::V4(ip), port);

        return (vec![ r[6] ], addr);
    }
}

fn main() {
    let mut thrs = vec![];
    for n in 0..THREADS {
        thrs.push( thread::spawn(move ||{
            println!("thread {} started", n);
            loop {
                let s = UdpSocket::bind("0.0.0.0:0").unwrap();

                for _ in 0..1000 {
                    let tmp = rand_sendto();
                    let result = s.send_to(&tmp.0, tmp.1);
                    //println!("{:?} => {:?}", result, tmp.1);
                }
            }
        }) );
    }

    for thr in thrs {
        println!("{:?}", thr.join());
    }
}

/*
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
}*/

