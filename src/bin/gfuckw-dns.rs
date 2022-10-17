/// A DNS anti-filtering tool that automatically determines whether a domain is being censored by GFW and triages it based on the results. This keeps local websites from being slowed down (with CDN-friendly results), and prevents other international domains from being interfered with by GFW.

//use std::net::UdpSocket;
use std::net::SocketAddr;
use std::collections::HashMap;
use smol::net::{UdpSocket, TcpListener, TcpStream};
use smol::io::{AsyncReadExt, AsyncWriteExt};
use dns_parser::Packet as DNSPacket;

use anyhow;

use clap::Parser;

#[derive(clap::Parser, Debug, Clone)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Where is this program will receive DNS request
    #[clap(long)]
    listen: SocketAddr,

    /// Any resolver inside China or any other Internet-censored countries: these resolver returns censored/hijacking Result but it CDN-friendly for local websites.
    #[clap(long)]
    local_resolver: SocketAddr,

    /// Any resolver that returns True results without any DNS censorship/hijackjng.
    /// maybe a local forwarder such as dnscrypt-proxy.
    /// or maybe a plaintext dns resolver with UDP Non-53 port? (Warning: this is not secure)
    #[clap(long)]
    true_resolver: SocketAddr,

    #[clap(long)]
    /// For now it accepts value of "tcp-rst" or "root-ns".
    detect_mode: String,
}

#[derive(Copy, Clone)]
enum DetectMode {
    TCP_RST,
    ROOT_NS,
}
impl DetectMode {
    pub fn from(a: &str) -> Self {
        match a {
            "tcp-rst" => Self::TCP_RST,
            "root-ns" => Self::ROOT_NS,
            _ => {
                panic!("invalid detect-mode!");
            }
        }
    }
}

struct Detector {
    cache: HashMap<String, bool>,
    mode: DetectMode,
}
impl Detector {
    pub fn new(mode: DetectMode) -> Self {
        Self {
            cache: HashMap::new(),
            mode,
        }
    }

    // detect cached
    pub async fn is_censored(&mut self, name: &str) -> anyhow::Result<bool> {
        if let Some(ret) = self.cache.get(name) {
            Ok(*ret)
        } else {
            let start = std::time::Instant::now();
            let ret = self._detect(name).await?;
            println!("detected {}(censored={:?}) used time {:?}", name, ret, start.elapsed());
            self.cache.insert(name.to_string(), ret);
            Ok(ret)
        }
    }

    // uncached detect
    async fn _detect(&self, name: &str) -> anyhow::Result<bool> {
        let mut censored: Option<bool> = None;
        let query: Vec<u8> = {
            let mut b = dns_parser::Builder::new_query(0u16, true);
            b.add_question(name,
                true,
                dns_parser::QueryType::TXT,
                dns_parser::QueryClass::CH);
            b.build().unwrap()
        };

        match self.mode {
            DetectMode::TCP_RST => {
                let servers: Vec<SocketAddr>=
                vec![
                    "101.102.103.104:53"
                        .parse().unwrap(),
                    "8.8.4.4:53"
                        .parse().unwrap(),
                    "80.80.80.80:53"
                        .parse().unwrap(),
                ];
                let mut det = smol::net::TcpStream::connect(&servers[..]).await?;

                let mut msg: Vec<u8> = vec![];
                msg.extend( (query.len() as u16).to_be_bytes() ); // length encoded as big endian

                msg.extend(query);
                det.write_all(&msg).await?;

                let mut recv: [u8; 1] = [0u8];
                match det.read(&mut recv).await {
                    Ok(size) => {
                        if size <= 0 {
                            censored = Some(true);
                        } else {
                            censored = Some(false);
                        }
                    },
                    Err(_) => {
                        censored = Some(true);
                    }
                }
            },
            DetectMode::ROOT_NS => {
                panic!("RootNS mode TODO");
            }
        }

        Ok( censored.unwrap() )
    }

}

async fn _main() {
    use std::io::Write;

    let args = Args::parse();
    let mode = DetectMode::from(&args.detect_mode);
    let mut detector = Detector::new(mode);

    let listen_socket = smol::net::UdpSocket::bind(args.listen).await.unwrap();
    let listen_socket = std::sync::Arc::new(listen_socket);

    let mut buf: Vec<u8> = Vec::from([0u8; 65535]);
    loop {
        let (len, peer) = (&listen_socket).recv_from(&mut buf).await.unwrap();
        let msg = (&buf[..len]).to_vec();
        //println!("DEBUG recved {:?} from {:?}", msg, peer);

        let pkt = match DNSPacket::parse(&msg) {
            Ok(v) => v,
            Err(_) => { continue; }
        };
        if pkt.questions.len() <= 0 {
            continue;
        }

        if pkt.questions.len() != 1 {
            println!("INFO cannot handle questions field more than one!");
        }

        let domain = pkt.questions[0].qname.to_string();
        let censored: bool = match detector.is_censored(&domain).await {
            Ok(v) => v,
            Err(err) => {
                eprintln!("ERROR (domain:{}) cannot detect the status of censorship! discard UDP packet... / ERROR: {:?}", domain, err);
                continue;
            }
        };

        let listen_socket = listen_socket.clone();

        smol::spawn(async move {
            let client_socket = smol::net::UdpSocket::bind("[::]:0").await.unwrap();
            println!("DEBUG client socket binded address: {:?}", client_socket.local_addr() );

            let resolver = if censored {
                args.true_resolver
            } else {
                args.local_resolver
            };
            client_socket.connect(resolver).await.unwrap();
            for _ in 0..3 {                                             client_socket.send(&msg).await.unwrap();             }

            let mut buf = [0u8; 65599];
            let len = client_socket.recv(&mut buf).await.unwrap();
            listen_socket.send_to(&buf[..len], &peer).await.unwrap();
        }).detach();
    }
}

fn main(){
    smol::block_on(_main());
}
