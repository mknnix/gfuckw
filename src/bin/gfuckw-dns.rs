use std::collections::HashMap;
//use std::io::{Error, ErrorKind};
use std::net::SocketAddr;
//use std::str::FromStr;
use std::time::{Duration, SystemTime};

use dns_parser::Packet as DNSPacket;
use smol::io::{AsyncReadExt, AsyncWriteExt};
use smol::net::{TcpListener, TcpStream, UdpSocket};
use smol_timeout::TimeoutExt;

use anyhow;
use clap::Parser;
use fastrand;

use rusqlite;
use rusqlite::OptionalExtension;

const DB_EXEC_SQL_TABLE: &str = "CREATE TABLE IF NOT EXISTS stat (name TEXT NOT NULL UNIQUE, censored INT NOT NULL, timestamp INT NOT NULL);";
const DB_EXEC_SQL_SELECT: &str = "SELECT * FROM stat WHERE name = ? LIMIT 1;";

const STATE_TTL_SEC: usize = 86400;

#[derive(Clone, Debug, PartialEq, Eq)]
struct State {
    name: String, censored: bool,
    time: SystemTime,
}

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

    #[clap(long)]
    /// Path to the optional Sqlite 3.x Database file.
    /// if does not specify one, then in-memory db will be used.
    /// if you provide one, then try to open that file with read-write access (abort and exit process if open fails).
    database: Option<String>,
}

#[derive(Debug, Copy, Clone)]
pub enum DetectMode {
    TcpReset,
    RootNS,
}

impl DetectMode {
    pub fn from(a: &str) -> Self {
        match a {
            "tcp-rst" => Self::TcpReset,
            "root-ns" => Self::RootNS,
            _ => {
                panic!("invalid detect-mode!");
            }
        }
    }
}

#[derive(Debug)]
pub struct Detector {
    mode: DetectMode,
    timeout: Duration,
    db: rusqlite::Connection,
}
impl Detector {
    pub fn new(db_path: &str, mode: DetectMode, timeout: Duration) -> Self {
        let db = if db_path.len() <= 0 {
            rusqlite::Connection::open_in_memory().unwrap()
        } else {
            rusqlite::Connection::open(db_path).unwrap()
        };
        db.execute( DB_EXEC_SQL_TABLE, () ).unwrap();

        Self {
            //cache: HashMap::new(),
            mode,
            timeout,
            db,
        }
    }

    fn db_cached(&self, name: &str) -> Option<State> {
        let state: Option<State> = self.db.query_row(
            DB_EXEC_SQL_SELECT,
            [ name ],
            |line| Ok(State {
                    name: line[0],
                    censored: line[1],
                    time: SystemTime::UNIX_EPOCH + Duration::from_secs(line[2])
                })
        ).optional().unwrap();
        if res.is_none() {
            println!("INFO sqlite3.db: getting {:?} is not hit");
        } else {
            println!("DEBUG sqlite3.db: get domain {:?} is hit! :)");
        }

        res
    }

    // Cache-able and Paraell-able Censoring detect method, based on SQLite
    pub async fn db_censored(&self, name: &str) -> anyhow::Result<State> {
        if let Some(st) = db_cached(name) {
            return Ok(st);
        }

        let r = self._detect();
        self.db
    }

    // detect cached
    /*
    pub async fn is_censored(&mut self, name: &str) -> anyhow::Result<State> {
        let mut name = name.to_string();
        name.make_ascii_lowercase();

        if let Some(wether) = self.cache.get(&name) {
            Ok(*wether)
        } else {
            let start = std::time::Instant::now();

            let result = match self._detect(&name, self.mode).timeout(self.timeout).await {
                Some(r) => r,
                None => Err(anyhow::Error::msg(format!(
                    "ERROR Timed out ({:?}) in Detecting (domain={})!",
                    self.timeout, &name
                ))),
            };

            let wether = result?;

            println!(
                "DEBUG detected {:?}(censored={:?}) used time {:?}",
                &name,
                wether,
                start.elapsed()
            );
            self.cache.insert(name.to_string(), wether);
            Ok(wether)
        }
    }
    */

    // uncached detect
    async fn _detect(&self, name: &str, mode: DetectMode) -> anyhow::Result<State> {
        let mut state = State {
            name: name.to_string(),
            censored: fastrand::bool(),
            time: SystemTime::now()
        };

        let query: Vec<u8> = {
            use dns_parser::QueryType;
            let mut b = dns_parser::Builder::new_query(fastrand::u16(..), fastrand::bool());
            b.add_question(
                name,
                fastrand::bool(),
                if fastrand::bool() {
                    QueryType::AAAA
                } else {
                    QueryType::A
                },
                dns_parser::QueryClass::CH,
            );
            b.build().unwrap()
        };
        if query.len() > 2000 {
            return Err(anyhow::Error::msg(
                "unexcepted domain name length too long!",
            ));
        }

        match mode {
            DetectMode::TcpReset => {
                let servers: Vec<SocketAddr> = vec![
                    "101.102.103.104:53".parse().unwrap(),
                    "8.8.8.8:53".parse().unwrap(),
                    "1.0.0.1:53".parse().unwrap(),
                    "8.8.4.4:53".parse().unwrap(),
                    "80.80.80.80:53".parse().unwrap(),
                    "101.101.101.101:53".parse().unwrap(),
                ];
                let mut det = TcpStream::connect(&servers[..]).await?;
                det.set_nodelay(true)?;

                let mut msg: Vec<u8> = vec![];
                msg.extend((query.len() as u16).to_be_bytes()); // length encoded as big endian

                msg.extend(query);
                det.write_all(&msg).await?;

                let mut recv: [u8; 1] = [0u8];
                match det.read(&mut recv).await {
                    Ok(size) => {
                        if size <= 0 {
                            state.censored = true;
                        } else {
                            state.censored = false;
                        }
                   }
                    Err(error) => {
                        println!("DEBUG detecting tcp mode: tcp socket error: {:?}", error);
                        state.censored = true;
                    }
                }
            }
            DetectMode::RootNS => {
                let servers = vec![
                    //"199.9.14.201:53",
                    "192.33.4.12:53",
                    "199.7.91.13:53",
                    //"192.203.230.10:53",
                    "192.5.5.241:53",
                    //"192.112.36.4:53",
                    "198.97.190.53:53",
                    //"192.36.148.17:53",
                    "192.58.128.30:53",
                    //"202.12.27.33:53",
                ];

                let det = UdpSocket::bind("[::]:0").await?;
                for ip in servers {
                    det.send_to(&query, ip).await?;
                }

                let mut msg = [0u8; 2000];
                if let Some(res) = det
                    .recv_from(&mut msg)
                    .timeout(Duration::from_secs_f64(1.0))
                    .await
                {
                    let (len, _) = res.unwrap();
                    if let Ok(pkt) = DNSPacket::parse(&msg[..len]) {
                        use dns_parser::{rdata::RData, Class};
                        if pkt.answers.len() <= 0 {
                            state.censored = false;
                        }
                        if pkt.answers[0].cls != Class::CH {
                            state.censored = true;
                        }

                        state.censored = 
                            match pkt.answers[0].data {
                                RData::A(_) => true,
                                RData::AAAA(_) => true,
                                _ => {
                                    return Err(anyhow::Error::msg(format!("unsure wether domain {:?} censored... {:?}", name, pkt)))
                                },
                            };
                    } else {
                        state.censored = false;
                    }
                } else {
                    return Err(anyhow::Error::msg(
                        "cannot detect (mode: root-ns), UDP receiving timed out",
                    ));
                }

                panic!("RootNS mode TODO");
            }
        }

        Ok(state)
    }
}

/// A DNS anti-filtering tool that automatically determines whether a domain is being censored by GFW and triages it based on the results. This keeps local websites from being slowed down (with CDN-friendly results), and prevents other international domains from being interfered with by GFW.
async fn async_main() {
    let args = Args::parse();

    let mode = DetectMode::from(&args.detect_mode);
    let mut detector = Detector::new(mode, Duration::from_secs(2));

    let listen_socket = UdpSocket::bind(args.listen).await.unwrap();
    //let listen_socket = std::sync::Arc::new(listen_socket);

    let mut buf = [0u8; 65599];
    loop {
        let (len, from) = (&listen_socket).recv_from(&mut buf).await.unwrap();
        let msg = buf[..len].to_vec();

        let listen_socket = listen_socket.clone();

        let pkt = match DNSPacket::parse(&msg) {
            Ok(v) => v,
            Err(_) => {
                continue;
            }
        };

        if pkt.questions.len() <= 0 {
            continue;
        }
        if pkt.questions.len() != 1 {
            println!("INFO cannot handle questions field more than one!");
            continue;
        }

        let domain = pkt.questions[0].qname.to_string();
        let censored: bool = match detector.is_censored(&domain).await {
            Ok(v) => v,
            Err(err) => {
                eprintln!("ERROR (domain:{}) cannot detect the status of censorship! discard UDP packet... / ERROR: {:?}", &domain, err);
                continue;
            }
        };

        let msg = msg.clone();
        //println!("DEBUG recved {:?} from {:?}", msg, peer);
        smol::spawn(async move {
            let resolver = if censored {
                args.true_resolver
            } else {
                args.local_resolver
            };

            let client_socket = UdpSocket::bind({
                if censored {
                    let id = pkt.header.id.to_ne_bytes();
                    format!("127.64.{}.{}:0", id[0], id[1])
                } else {
                    format!("[::]:0")
                }
            })
            .await
            .unwrap();
            println!(
                "DEBUG client socket binded address: {:?}",
                client_socket.local_addr()
            );

            client_socket.connect(resolver).await.unwrap();

            for _ in 0..3 {
                client_socket.send(&msg).await.unwrap();
                if censored {
                    break;
                }
                smol::Timer::after(Duration::from_secs_f64(0.05)).await;
            }

            let mut buf = [0u8; 2000];
            let recv_timeout = Duration::from_secs_f64(5.0);
            let len: usize = match client_socket
                .recv(&mut buf)
                .timeout(recv_timeout)
                .await
                .expect("Timed out in reading DNS response from upstream UDP")
            {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("ERROR {:?}", e);
                    0
                }
            };

            if len > 0 {
                listen_socket.send_to(&buf[..len], &from).await.unwrap();
            }
        })
        .detach();
    }
}

fn main() {
    smol::block_on(async_main())
}
