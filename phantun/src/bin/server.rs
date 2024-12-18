use clap::{crate_version, Arg, ArgAction, Command};
use fake_tcp::packet::MAX_PACKET_LEN;
use fake_tcp::Stack;
use log::{debug, error, info};
use phantun::utils::{assign_ipv6_address, bring_link_up, new_udp_reuseport};
use std::fs;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Notify;
use tokio::time;
use tokio_tun::TunBuilder;
use tokio_util::sync::CancellationToken;

use phantun::UDP_TTL;

#[tokio::main]
async fn main() -> io::Result<()> {
    pretty_env_logger::init();

    let matches = Command::new("Phantun Server")
        .version(crate_version!())
        .author("Datong Sun (github.com/dndx)")
        .arg(
            Arg::new("local")
                .short('l')
                .long("local")
                .required(true)
                .value_name("PORT")
                .help("Sets the port where Phantun Server listens for incoming Phantun Client TCP connections")
        )
        .arg(
            Arg::new("remote")
                .short('r')
                .long("remote")
                .required(true)
                .value_name("IP and PORT or PORT only for the localhost")
                .help("Sets the address or host name and port where Phantun Server forwards UDP packets to, IPv6 address need to be specified as: \"[IPv6]:PORT\"")
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
                .help("Sets the Tun interface local address (O/S's end)")
                .default_value("169.254.1.0")
        )
        .arg(
            Arg::new("tun_peer")
                .long("tun-peer")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface destination (peer) address (Phantun Server's end). \
                       You will need to setup DNAT rules to this address in order for Phantun Server \
                       to accept TCP traffic from Phantun Client")
        )
        .arg(
            Arg::new("ipv4_only")
                .long("ipv4-only")
                .short('4')
                .required(false)
                .help("Do not assign IPv6 addresses to Tun interface")
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
                      first data packet to the client.\n\
                      Note: ensure this file's size does not exceed the MTU of the outgoing interface. \
                      The content is always sent out in a single packet and will not be further segmented")
        )
        .get_matches();

    let local_port: u16 = matches
        .get_one::<String>("local")
        .unwrap()
        .parse()
        .expect("bad local port");

    let remote_arg = matches.get_one::<String>("remote").unwrap();
    let remote_addr: SocketAddr = if let Ok(port) = remote_arg.parse::<u16>() {
        // If the argument is a number, connect to localhost with the given port
        if matches.get_flag("ipv4_only") {
            format!("127.0.0.1:{}", port)
                .parse()
                .expect("bad port number")
        } else {
            format!("[::1]:{}", port)
                .parse()
                .expect("bad port number")
        }
    } else {
        // Otherwise, resolve the remote host name
        tokio::net::lookup_host(remote_arg)
            .await
            .expect("bad remote address or host")
            .next()
            .expect("unable to resolve remote host name")
    };

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

    let (tun_local6, tun_peer6) = if matches.get_flag("ipv4_only") {
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

    let num_cpus = num_cpus::get();
    info!("{} cores available", num_cpus);

    let tun = if matches.get_flag("ipv4_only") {
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

    let tun_name = tun[0].name().to_string();
    info!("Created TUN device {}", tun_name);

    //thread::sleep(time::Duration::from_secs(5));
    let mut stack = Stack::new(tun, Some(tun_local), tun_local6);
    stack.listen(local_port);
    info!("Monitoring port {} on incoming of {}", local_port, tun_name);

    let main_loop = tokio::spawn(async move {
        let mut buf_udp = [0u8; MAX_PACKET_LEN];
        let mut buf_tcp = [0u8; MAX_PACKET_LEN];

        loop {
            let sock = Arc::new(stack.accept().await);
            info!("New connection: {}", sock);
            if let Some(ref p) = handshake_packet {
                if sock.send(p).await.is_none() {
                    error!("Failed to send handshake packet to remote, closing connection.");
                    continue;
                }

                debug!("Sent handshake packet to: {}", sock);
            }

            let packet_received = Arc::new(Notify::new());
            let quit = CancellationToken::new();
            let udp_sock = UdpSocket::bind(if remote_addr.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            })
            .await?;
            let local_addr = udp_sock.local_addr()?;
            drop(udp_sock);

            for i in 0..num_cpus {
                let sock = sock.clone();
                let quit = quit.clone();
                let packet_received = packet_received.clone();
                let udp_sock = new_udp_reuseport(local_addr);

                tokio::spawn(async move {
                    udp_sock.connect(remote_addr).await.unwrap();

                    loop {
                        tokio::select! {
                            Ok(size) = udp_sock.recv(&mut buf_udp) => {
                                if sock.send(&buf_udp[..size]).await.is_none() {
                                    quit.cancel();
                                    return;
                                }

                                packet_received.notify_one();
                            },
                            res = sock.recv(&mut buf_tcp) => {
                                match res {
                                    Some(size) => {
                                        if size > 0 {
                                            if let Err(e) = udp_sock.send(&buf_tcp[..size]).await {
                                                error!("Unable to send UDP packet to {}: {}, closing connection", e, remote_addr);
                                                quit.cancel();
                                                return;
                                            }
                                        }
                                    },
                                    None => {
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

            tokio::spawn(async move {
                loop {
                    let read_timeout = time::sleep(UDP_TTL);
                    let packet_received_fut = packet_received.notified();

                    tokio::select! {
                        _ = read_timeout => {
                            info!("No traffic seen in the last {:?}, closing connection", UDP_TTL);

                            quit.cancel();
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
