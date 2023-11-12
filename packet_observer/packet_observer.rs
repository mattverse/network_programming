use pcap::Capture;
use pnet::packet::tcp::TcpFlags;
use pnet::packet::{ethernet::EthernetPacket, ipv4::Ipv4Packet, tcp::TcpPacket, Packet};
use std::collections::HashMap;
use std::env;
use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Hash, Eq, PartialEq, Debug, Clone)]
struct TcpFlow {
    src_port: u16,
    src_ip: IpAddr,
    dst_port: u16,
    dst_ip: IpAddr,
}

#[derive(Clone)]
struct TcpPacketInfo {
    sequence: u32,
    acknowledgement: u32,
    window: u16,
    timestamp: SystemTime,
    size: usize,
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <filename>", args[0]);
        std::process::exit(1);
    }

    // Use the provided filename
    let file = &args[1];

    let sender_ip: IpAddr = "130.245.145.12".parse().expect("Invalid IP address format");
    let receiver_ip: IpAddr = "128.208.2.198".parse().expect("Invalid IP address format");

    let mut cap = Capture::from_file(file).unwrap();

    let mut tcp_flows: HashMap<TcpFlow, Vec<TcpPacketInfo>> = HashMap::new();
    let mut first_timestamp: HashMap<TcpFlow, SystemTime> = HashMap::new();
    let mut last_ack_timestamp: HashMap<TcpFlow, SystemTime> = HashMap::new();

    let mut duplicate_ack_count: HashMap<TcpFlow, u32> = HashMap::new();
    let mut last_ack: HashMap<TcpFlow, u32> = HashMap::new();
    let mut triple_dup_ack_retransmissions: HashMap<TcpFlow, u32> = HashMap::new();
    let mut timeout_retransmissions: HashMap<TcpFlow, u32> = HashMap::new();

    let mut cwnd_estimation: HashMap<TcpFlow, Vec<u32>> = HashMap::new();
    let mut max_unacked: HashMap<TcpFlow, u32> = HashMap::new();

    while let Ok(packet) = cap.next() {
        if let Some(ethernet) = EthernetPacket::new(&packet.data) {
            if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
                if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                    if ipv4.get_source() == sender_ip && ipv4.get_destination() == receiver_ip {
                        let flow = TcpFlow {
                            src_port: tcp.get_source(),
                            src_ip: IpAddr::V4(ipv4.get_source()),
                            dst_port: tcp.get_destination(),
                            dst_ip: IpAddr::V4(ipv4.get_destination()),
                        };

                        let seq = tcp.get_sequence();
                        let ack = tcp.get_acknowledgement();
                        let timestamp = UNIX_EPOCH
                            + Duration::from_secs(packet.header.ts.tv_sec as u64)
                            + Duration::from_micros(packet.header.ts.tv_usec as u64);

                        if tcp.get_flags() & TcpFlags::ACK != 0 {
                            last_ack_timestamp.insert(flow.clone(), timestamp);
                        }
                        let tcp_header_size = (tcp.get_data_offset() * 4) as usize;
                        let tcp_payload_size = ipv4.get_total_length() as usize
                            - (ipv4.get_header_length() as usize * 4)
                            - tcp_header_size;
                        let packet_size = tcp_header_size + tcp_payload_size;

                        let tcp_info = TcpPacketInfo {
                            sequence: seq,
                            acknowledgement: ack,
                            window: tcp.get_window(),
                            timestamp,
                            size: packet_size,
                        };

                        first_timestamp.entry(flow.clone()).or_insert(timestamp);

                        tcp_flows
                            .entry(flow.clone())
                            .or_default()
                            .push(tcp_info.clone());

                        if tcp.get_flags() & TcpFlags::ACK != 0 {
                            if let Some(max_seq) = max_unacked.get(&flow) {
                                let cwnd = seq.wrapping_sub(*max_seq);
                                let cwnds =
                                    cwnd_estimation.entry(flow.clone()).or_insert_with(Vec::new);
                                if cwnd > *max_seq {
                                    cwnds.push(cwnd);
                                }
                                max_unacked.insert(flow.clone(), std::cmp::max(*max_seq, seq));
                            } else {
                                max_unacked.insert(flow.clone(), seq);
                            }
                        }

                        if let Some(prev_ack) = last_ack.get(&flow) {
                            if ack == *prev_ack {
                                let count = duplicate_ack_count.entry(flow.clone()).or_insert(0);
                                *count += 1;
                                if *count == 3 {
                                    *triple_dup_ack_retransmissions
                                        .entry(flow.clone())
                                        .or_insert(0) += 1;
                                    // reset duplicate ACK count
                                    *count = 0;
                                }
                            } else {
                                duplicate_ack_count.insert(flow.clone(), 0);
                            }
                        }
                        last_ack.insert(flow.clone(), ack);

                        if let Some(packets) = tcp_flows.get_mut(&flow) {
                            if let Some(last_packet) = packets.last() {
                                if seq == last_packet.sequence
                                    && timestamp.duration_since(last_packet.timestamp).unwrap()
                                        > Duration::from_secs(1)
                                {
                                    *timeout_retransmissions.entry(flow.clone()).or_insert(0) += 1;
                                }
                            }
                            packets.push(tcp_info);
                        } else {
                            tcp_flows.insert(flow.clone(), vec![tcp_info]);
                        }
                    }
                }
            }
        }
    }

    println!("\n\n\n");
    println!(
        "Total number of TCP flows initiated by the sender: {}\n",
        tcp_flows.len()
    );
    for (flow, packets) in &tcp_flows {
        println!("=============================================FLOW===================================================");
        println!("Flow: {:?}", flow);

        for (i, packet) in packets.iter().enumerate().take(2) {
            println!(
                "Packet {}: Sequence: {}, Ack: {}, Window: {}",
                i + 1,
                packet.sequence,
                packet.acknowledgement,
                packet.window
            );
        }

        if let Some(first_packet) = packets.first() {
            if let Some(last_packet) = packets.last() {
                // duration in seconds
                let duration = last_packet
                    .timestamp
                    .duration_since(first_packet.timestamp)
                    .expect("Could not calculate duration")
                    .as_secs_f64();

                // Sum of all packet sizes
                let total_bytes: usize = packets.iter().map(|p| p.size).sum();

                // bytes per seconds
                let throughput = if duration > 0.0 {
                    total_bytes as f64 / duration
                } else {
                    0.0
                };

                println!("Throughput: {:.2} Bytes/sec", throughput);
            }
        }

        if let Some(cwnds) = cwnd_estimation.get(&flow) {
            let mut sorted_cwnds = cwnds.clone();
            sorted_cwnds.sort_by(|a, b| b.cmp(a));
            // Take the top three elements
            let top_3_cwnds = sorted_cwnds.iter().take(3);

            println!(
                "Top 3 CWND estimations: {:?}",
                top_3_cwnds.collect::<Vec<_>>()
            );
        }

        let triple_dup_ack_retrans = triple_dup_ack_retransmissions.get(&flow).unwrap_or(&0);
        let timeout_retrans = timeout_retransmissions.get(&flow).unwrap_or(&0);
        println!(
            "Triple duplicate ACK retransmissions: {}, Timeout retransmissions: {}",
            triple_dup_ack_retrans, timeout_retrans
        );
        println!("")
    }
}
