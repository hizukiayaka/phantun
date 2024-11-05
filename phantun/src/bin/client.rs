use clap::{crate_version, Arg, ArgAction, Command};
use fake_tcp::packet::MAX_PACKET_LEN;
use fake_tcp::{Socket, Stack};
use log::{debug, error, info};
use phantun::utils::{assign_ipv6_address, bring_link_up, new_udp_reuseport};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::sync::{Notify, RwLock};
use tokio::time;
use tokio_tun::TunBuilder;
use tokio_util::sync::CancellationToken;

use phantun::UDP_TTL;

#[tokio::main]
async fn main() -> io::Result<()> {
    pretty_env_logger::init();

    let matches = Command::new("Phantun Client")
        .version(crate_version!())
        .author("Datong Sun (github.com/dndx)")
        .arg(
            Arg::new("local")
                .short('l')
                .long("local")
                .required(true)
                .value_name("IP:PORT")
                .help("Sets the IP and port where Phantun Client listens for incoming UDP datagrams, IPv6 address need to be specified as: \"[IPv6]:PORT\"")
        )
        .arg(
            Arg::new("remote")
                .short('r')
                .long("remote")
                .required(true)
                .value_name("IP or HOST NAME:PORT")
                .help("Sets the address or host name and port where Phantun Client connects to Phantun Server, IPv6 address need to be specified as: \"[IPv6]:PORT\"")
        )
        .arg(
            Arg::new("tun")
                .long("tun")
                .required(false)
                .value_name("tunX")
                .help("Sets the Tun interface name, if absent, pick the next available name")
                .default_value("")
        )
        .arg(
            Arg::new("tun_local")
                .long("tun-local")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface IPv4 local address (O/S's end)")
                .default_value("169.254.1.0")
        )
        .arg(
            Arg::new("tun_peer")
                .long("tun-peer")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface IPv4 destination (peer) address (Phantun Client's end). \
                       You will need to setup SNAT/MASQUERADE rules on your Internet facing interface \
                       in order for Phantun Client to connect to Phantun Server")
        )
        .arg(
            Arg::new("ipv4_only")
                .long("ipv4-only")
                .short('4')
                .required(false)
                .help("Only use IPv4 address when connecting to remote")
                .action(ArgAction::SetTrue)
                .conflicts_with_all(["tun_local6", "tun_peer6"]),
        )
        .arg(
            Arg::new("tun_local6")
                .long("tun-local6")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface IPv6 local address (O/S's end)")
                .default_value("fea0::1")
        )
        .arg(
            Arg::new("tun_peer6")
                .long("tun-peer6")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface IPv6 destination (peer) address (Phantun Client's end). \
                       You will need to setup SNAT/MASQUERADE rules on your Internet facing interface \
                       in order for Phantun Client to connect to Phantun Server")
        )
        .arg(
            Arg::new("handshake_packet")
                .long("handshake-packet")
                .required(false)
                .value_name("PATH")
                .help("Specify a file, which, after TCP handshake, its content will be sent as the \
                      first data packet to the server.\n\
                      Note: ensure this file's size does not exceed the MTU of the outgoing interface. \
                      The content is always sent out in a single packet and will not be further segmented")
        )
        .arg(
            Arg::new("xor")
                .long("xor")
                .required(false)
                .value_name("start offset,end offset:xor values")
                .help("Sets the start and end offsets and the XOR values in the format: <start offset>,<end offset>:<xor values>")
        )
        .get_matches();

    let ipv4_only = matches.get_flag("ipv4_only");
    let local_arg = matches.get_one::<String>("local").unwrap();

    let local_addr: SocketAddr = if local_arg.chars().all(|c| c.is_numeric()) {
        let port: u16 = local_arg.parse().expect("invalid port number");
        let ip = if ipv4_only {
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
        } else {
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))
        };
        SocketAddr::new(ip, port)
    } else {
        local_arg.parse().expect("bad local address")
    };

    let remote_addr = tokio::net::lookup_host(matches.get_one::<String>("remote").unwrap())
        .await
        .expect("bad remote address or host")
        .find(|addr| !ipv4_only || addr.is_ipv4())
        .expect("unable to resolve remote host name");
    info!("Remote address is: {}", remote_addr);

    let tun_local: Ipv4Addr = matches
        .get_one::<String>("tun_local")
        .unwrap()
        .parse()
        .expect("bad local address for Tun interface");

    let tun_peer: Ipv4Addr = match matches.get_one::<String>("tun_peer") {
        Some(peer) if !peer.is_empty() => peer.parse().expect("bad peer address for Tun interface"),
        _ => {
            let octets = tun_local.octets();
            Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3] + 1)
        }
    };

    let (tun_local6, tun_peer6) = if remote_addr.is_ipv4() {
        (None, None)
    } else {
        let tun_local6 = matches
            .get_one::<String>("tun_local6")
            .map(|v| v.parse().expect("bad local address for Tun interface"));

        let tun_peer6 = match matches.get_one::<String>("tun_peer6") {
            Some(peer) if !peer.is_empty() => {
                Some(peer.parse().expect("bad peer address for Tun interface"))
            }
            _ => tun_local6.map(|local: Ipv6Addr| {
                let segments = local.segments();
                Ipv6Addr::new(
                    segments[0],
                    segments[1],
                    segments[2],
                    segments[3],
                    segments[4],
                    segments[5],
                    segments[6],
                    segments[7] + 1,
                )
            }),
        };

        (tun_local6, tun_peer6)
    };

    let tun_name = matches.get_one::<String>("tun").unwrap();
    let handshake_packet: Option<Vec<u8>> = matches
        .get_one::<String>("handshake_packet")
        .map(fs::read)
        .transpose()?;

    let mut start_offset = 0;
    let mut end_offset = usize::MAX;
    let mut xor_values: Option<Vec<u8>> = None;
    let mut perform_xor = false;

    if let Some(xor) = matches.get_one::<String>("xor") {
        let parts: Vec<&str> = xor.split(':').collect();
        if parts.len() == 2 {
            let offsets: Vec<&str> = parts[0].split(',').collect();
            if offsets.len() == 2 {
                start_offset = offsets[0].parse().unwrap_or(0);
                end_offset = offsets[1].parse().unwrap_or(usize::MAX);
            } else if offsets.len() == 1 {
                end_offset = offsets[0].parse().unwrap_or(usize::MAX);
            }
            xor_values = Some(
                parts[1]
                    .chars()
                    .map(|c| c as u8)
                    .collect(),
            );
            if let Some(ref values) = xor_values {
                perform_xor = !values.iter().all(|&x| x == 0);
            }
        } else {
            eprintln!("Invalid XOR argument format");
        }
    }

    let num_cpus = num_cpus::get();
    info!("{} cores available", num_cpus);

    let tun = if remote_addr.is_ipv4() {
        let tun = TunBuilder::new()
        // if name is empty, then it is set by kernel.
        .name(tun_name)
        .address(tun_local)
        .destination(tun_peer)
        .netmask(Ipv4Addr::new(255, 255, 255, 255))
        .queues(num_cpus)
        .up()
        .build()
        .unwrap();
        tun
    } else {
        let tun = TunBuilder::new()
        // if name is empty, then it is set by kernel.
        .name(tun_name)
        .queues(num_cpus)
        .build()
        .unwrap();

        assign_ipv6_address(tun[0].name(), tun_local6.unwrap(), tun_peer6.unwrap());
        bring_link_up(tun[0].name());
        tun
    };

    info!("Created TUN device {}", tun[0].name());

    let udp_sock = Arc::new(new_udp_reuseport(local_addr));
    let connections = Arc::new(RwLock::new(HashMap::<SocketAddr, Arc<Socket>>::new()));

    let mut stack = Stack::new(tun, Some(tun_peer), tun_peer6);

    let main_loop = tokio::spawn(async move {
        let mut buf_r = [0u8; MAX_PACKET_LEN];

        loop {
            let (size, addr) = udp_sock.recv_from(&mut buf_r).await?;
            // seen UDP packet to listening socket, this means:
            // 1. It is a new UDP connection, or
            // 2. It is some extra packets not filtered by more specific
            //    connected UDP socket yet
            if let Some(sock) = connections.read().await.get(&addr) {
                sock.send(&buf_r[..size]).await;
                continue;
            }

            info!("New UDP client from {}", addr);
            let sock = stack.connect(remote_addr).await;
            if sock.is_none() {
                error!("Unable to connect to remote {}", remote_addr);
                continue;
            }

            let sock = Arc::new(sock.unwrap());
            if let Some(ref p) = handshake_packet {
                if sock.send(p).await.is_none() {
                    error!("Failed to send handshake packet to remote, closing connection.");
                    continue;
                }

                debug!("Sent handshake packet to: {}", sock);
            }

            // send first packet
            if sock.send(&buf_r[..size]).await.is_none() {
                continue;
            }

            assert!(connections
                .write()
                .await
                .insert(addr, sock.clone())
                .is_none());
            debug!("inserted fake TCP socket into connection table");

            // spawn "fastpath" UDP socket and task, this will offload main task
            // from forwarding UDP packets

            let packet_received = Arc::new(Notify::new());
            let quit = CancellationToken::new();

            for i in 0..num_cpus {
                let sock = sock.clone();
                let quit = quit.clone();
                let packet_received = packet_received.clone();
                let xor_values = xor_values.clone();

                tokio::spawn(async move {
                    let mut buf_udp = [0u8; MAX_PACKET_LEN];
                    let mut buf_tcp = [0u8; MAX_PACKET_LEN];
                    let udp_sock = new_udp_reuseport(local_addr);
                    udp_sock.connect(addr).await.unwrap();

                    loop {
                        tokio::select! {
                            Ok(size) = udp_sock.recv(&mut buf_udp) => {
                                // XOR processing before sending
                                if perform_xor {
                                    if let Some(ref xor_values) = xor_values {
                                        for i in start_offset..end_offset.min(size) {
                                            buf_udp[i] ^= xor_values[i % xor_values.len()];
                                        }
                                    }
                                }
                                if sock.send(&buf_udp[..size]).await.is_none() {
                                    debug!("removed fake TCP socket from connections table");
                                    quit.cancel();
                                    return;
                                }

                                packet_received.notify_one();
                            },
                            res = sock.recv(&mut buf_tcp) => {
                                match res {
                                    Some(size) => {
                                        if size > 0 {
                                            // XOR processing after receiving
                                            if perform_xor {
                                                if let Some(ref xor_values) = xor_values {
                                                    for i in start_offset..end_offset.min(size) {
                                                        buf_tcp[i] ^= xor_values[i % xor_values.len()];
                                                    }
                                                }
                                            }
                                            if let Err(e) = udp_sock.send(&buf_tcp[..size]).await {
                                                error!("Unable to send UDP packet to {}: {}, closing connection", e, addr);
                                                quit.cancel();
                                                return;
                                            }
                                        }
                                    },
                                    None => {
                                        debug!("removed fake TCP socket from connections table");
                                        quit.cancel();
                                        return;
                                    },
                                }

                                packet_received.notify_one();
                            },
                            _ = quit.cancelled() => {
                                debug!("worker {} terminated", i);
                                return;
                            },
                        };
                    }
                });
            }

            let connections = connections.clone();
            tokio::spawn(async move {
                loop {
                    let read_timeout = time::sleep(UDP_TTL);
                    let packet_received_fut = packet_received.notified();

                    tokio::select! {
                        _ = read_timeout => {
                            info!("No traffic seen in the last {:?}, closing connection", UDP_TTL);
                            connections.write().await.remove(&addr);
                            debug!("removed fake TCP socket from connections table");

                            quit.cancel();
                            return;
                        },
                        _ = quit.cancelled() => {
                            connections.write().await.remove(&addr);
                            debug!("removed fake TCP socket from connections table");
                            return;
                        },
                        _ = packet_received_fut => {},
                    }
                }
            });
        }
    });

    tokio::join!(main_loop).0.unwrap()
}
