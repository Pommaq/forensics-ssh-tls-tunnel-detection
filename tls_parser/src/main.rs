mod ethparse;
mod rulegen;

use crate::rulegen::*;
use std::cmp::max;
extern crate pcap_parser;

use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::{Block, EnhancedPacketBlock, PcapBlockOwned, PcapError};
use pktparse::tcp;
use std::collections::{BTreeSet, HashMap};
use std::fs::File;

const SERVER_PORT: u16 = 8889;

#[derive(Eq, Hash, PartialEq, Debug)]
struct SesKey {
    internal: BTreeSet<u16>,
}

impl SesKey {
    fn new(data: &[u16; 2]) -> Self {
        Self {
            internal: data.to_owned().into_iter().collect(),
        }
    }
}
impl Default for SesKey {
    fn default() -> Self {
        return Self {
            internal: Default::default(),
        };
    }
}

fn extract_headers(
    packet: &ethparse::ParsedPacket,
) -> (Option<&tcp::TcpHeader>, Option<&ethparse::TlsType>) {
    let mut tcpheader: Option<&tcp::TcpHeader> = None;
    let mut tlsheader: Option<&ethparse::TlsType> = None;

    for header in &packet.headers {
        match header {
            ethparse::PacketHeader::Tls(type_) => {
                tlsheader = Some(type_);
            }
            ethparse::PacketHeader::Tcp(header) => {
                tcpheader = Some(header);
            }
            _ => continue,
        }
    }
    (tcpheader, tlsheader)
}

fn extract_tcp_sessions(
    mut sessions: HashMap<SesKey, Vec<ethparse::ParsedPacket>>,
    packet: EnhancedPacketBlock,
    ts_offset: u64,
    resolution: u64,
) -> HashMap<SesKey, Vec<ethparse::ParsedPacket>> {
    let parser: ethparse::PacketParse = ethparse::PacketParse::new();
    let parsed_packet: ethparse::ParsedPacket = parser
        .parse_packet(
            Vec::from((&packet).data),
            (&packet).data.len() as u32,
            packet.decode_ts_f64(ts_offset, resolution),
        )
        .unwrap();
    // Find the TCP header

    let (tcp, _) = extract_headers(&parsed_packet);
    match tcp {
        None => {
            // eprintln!(
            //     "Didn't get a TCP packet, or something is wrong... Got {:?}",
            //     parsed_packet
            // );
        }
        Some(tcp) => {
            let key = SesKey::new(&[tcp.source_port, tcp.dest_port]);
            sessions.entry(key).or_default().push(parsed_packet);
        }
    }
    sessions
}

fn extract_sessions<T: std::io::Read>(
    reader: &mut pcap_parser::PcapNGReader<T>,
) -> HashMap<SesKey, Vec<ethparse::ParsedPacket>> {
    // keys are src/dst ports.
    let mut sessions: HashMap<SesKey, Vec<ethparse::ParsedPacket>> = HashMap::new();

    let mut values: Option<(u64, u64)> = None;
    loop {
        match reader.next() {
            Ok((offset, block)) => {
                match block {
                    PcapBlockOwned::NG(Block::EnhancedPacket(epb)) => {
                        // cool
                        let (offset, res) = values.unwrap_or((0, 1000000000));
                        sessions = extract_tcp_sessions(sessions, epb, offset, res);
                    }
                    PcapBlockOwned::NG(Block::InterfaceDescription(ref epb)) => {
                        values = Some((epb.ts_offset(), epb.ts_resolution().unwrap()));
                    }
                    _ => {
                        // Not interested.
                    }
                }
                reader.consume(offset);
            }
            Err(PcapError::Eof) => {
                break;
            }
            Err(PcapError::Incomplete) => {
                reader.refill().unwrap();
            }
            Err(e) => panic!("Error while reading: {:?}", e),
        }
    }

    sessions
}

/// Analyzes data inside pcap and returns true if its determined to contain
/// ssh tunneled over TLS using given rules.
fn perform_analysis(file: File, rules: &[Box<dyn Rule>], server_port: u16) -> bool {
    let mut reader = pcap_parser::PcapNGReader::new(65536, file).expect("Unable to create reader");

    let sessions = extract_sessions(&mut reader);
    let mut found = false;
    // We can now find the sessions we think are interesting.
    'ses: for (key, store) in sessions {
        if key.internal.contains(&server_port) {
            // Begin analysis.
            let transactions = extract_transactions(&store, server_port);
            if transactions.len() < rules.len() {
                continue 'ses;
            }
            for (reqresp, rule) in transactions.into_iter().zip(rules.iter()) {
                // ugly but it works
                let req = &reqresp[0];
                let resp = &reqresp[1];
                if !rule.validate_size(req, resp) {
                    // !(rule.validate_time(req, resp) || rule.validate_size(req, resp)) {
                    continue 'ses;
                }
            }
            // It's positive
            println!(
                "Found SSH connection. Entire conversation:\r\n{:?}\r\n",
                store
            );
            found = true;
        }
    }

    found
}

fn extend(
    mut target: Option<RuleData>,
    srcport: u16,
    dstport: u16,
    packet: &ethparse::ParsedPacket,
) -> Option<RuleData> {
    if target.is_none() {
        target = Some(RuleData::init(srcport, dstport, packet));
    } else {
        target.as_mut().unwrap().extend(packet);
    }

    target
}

fn extract_transactions(all: &Vec<ethparse::ParsedPacket>, serverport: u16) -> Vec<[RuleData; 2]> {
    let mut conversations: Vec<[RuleData; 2]> = Vec::new();

    let iter = all.iter();

    let mut request: Option<RuleData> = None;
    let mut response: Option<RuleData> = None;

    for packet in iter {
        if request.is_some() && response.is_some() {
            let req = request.unwrap();
            let resp = response.unwrap();
            conversations.push([req, resp]);
            request = None;
            response = None;
        }

        let (tcpheader, tlsheader) = extract_headers(&packet);
        if tcpheader.is_none() || tlsheader.is_none() {
            continue;
        }

        let tcpheader = tcpheader.unwrap();
        let tlstype = tlsheader.unwrap();
        if tcpheader.flag_psh {
            match tlstype {
                ethparse::TlsType::ApplicationData => {
                    if tcpheader.dest_port == serverport {
                        request =
                            extend(request, tcpheader.source_port, tcpheader.dest_port, packet);
                    } else if tcpheader.source_port == serverport {
                        response =
                            extend(response, tcpheader.source_port, tcpheader.dest_port, packet);
                    } // else not interesting
                }
                // ethparse::TlsType::EncryptedData => {
                //     println!("Wtf is this?? {:?}", packet);
                // }
                _ => continue,
            }
        }
    }

    conversations
}

fn generate_rules(file: File, serverport: u16) -> Vec<Box<dyn Rule>> {
    let mut reader = pcap_parser::PcapNGReader::new(65536, file).expect("Unable to create reader");
    let sessions = extract_sessions(&mut reader);

    let mut rules: [Option<TCPRule>; 3] = [None; 3];

    // One ssh handshake is 7 packets total.
    // Client->server, server->client, (For banner)
    // client->server, server->client, (key exchange)
    // client->server, server->client (chosen exchange)
    // client->server (New Keys).

    for (_, store) in sessions {
        let transactions = extract_transactions(&store, serverport);
        for (rule, reqresp) in rules.iter_mut().zip(transactions.iter()) {
            let request = &reqresp[0];
            let response = &reqresp[1];
            // set smallest to 1 to avoid divisions by zero.
            let reqz = max(request.payload.len(), 1);
            let respz = max(response.payload.len(), 1);
            let timedelay = response.start_ts - request.start_ts;

            let stored_rule = &mut rule.get_or_insert(TCPRule {
                expected_request_size: reqz,
                expected_response_size: respz,
                allowed_size_deviation: 0,
                time_delay: timedelay,
                allowed_time_deviation: 0.0,
            });

            // Calculate size deviation from data.
            let resp_dev = respz.abs_diff(stored_rule.expected_response_size);
            let req_dev = reqz.abs_diff(stored_rule.expected_request_size);
            stored_rule.allowed_size_deviation =
                max(stored_rule.allowed_size_deviation, max(resp_dev, req_dev));

            let delta = (timedelay - stored_rule.time_delay).abs();
            let mut deviation;
            if delta != 0.0 {
                deviation = timedelay / delta;
            } else {
                deviation = 0.0;
            }

            if deviation >= stored_rule.allowed_time_deviation {
                stored_rule.allowed_time_deviation = deviation
            }
        }
    }

    // Last response will not be related to key exchange. Let's ignore it.
    let rule = &mut rules.last_mut().unwrap().unwrap();
    // Set to 1 to allow under/overflows.
    rule.expected_response_size = 1;
    rule.time_delay = 1.0;
    rule.allowed_size_deviation = usize::MAX;
    rule.allowed_time_deviation = f64::MAX;

    let mut ret: Vec<Box<dyn Rule>> = Vec::new();
    for item in rules {
        ret.push(Box::new(item.unwrap()));
    }
    ret
}

///  We can stay dumb, we assume any PSH back is a response to previous PSH. Especially since
/// we focus on SSH handshakes, which mandate this behavior.
fn main() {
    let trainingfile = File::open("./training.pcapng").unwrap();
    let rules = generate_rules(trainingfile, 8889);

    let truefile = File::open("./testdata.pcapng").unwrap();
    perform_analysis(truefile, &rules, 8889);
}
