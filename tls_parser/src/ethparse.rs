/*
 * first version  from snoopy,  https://github.com/kanishkarj/snoopy
 * packet parse include eth,tcp,udp
 */

use pktparse::arp::ArpPacket;
use pktparse::ethernet::{EtherType, EthernetFrame};
use pktparse::ip::IPProtocol;
use pktparse::ipv4::IPv4Header;
use pktparse::ipv6::IPv6Header;
use pktparse::tcp::TcpHeader;
use pktparse::udp::UdpHeader;
use pktparse::*;
use std::string::ToString;
use tls_parser::TlsMessage;

use serde::{Deserialize, Serialize};

pub struct PacketParse {}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum PacketHeader {
    Tls(TlsType),
    Tcp(TcpHeader),
    Udp(UdpHeader),
    Ipv4(IPv4Header),
    Ipv6(IPv6Header),
    Ether(EthernetFrame),
    Arp(ArpPacket),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ParsedPacket {
    pub len: u32,
    pub timestamp: f64,
    pub headers: Vec<PacketHeader>,
    pub payload: Vec<u8>,
}

impl ParsedPacket {
    pub fn new() -> ParsedPacket {
        ParsedPacket {
            len: 0,
            timestamp: 0.0,
            headers: vec![],
            payload: vec![],
        }
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum TlsType {
    Handshake,
    ChangeCipherSpec,
    Alert,
    ApplicationData,
    Heartbeat,
    EncryptedData,
}

impl ToString for PacketHeader {
    fn to_string(&self) -> String {
        match self {
            PacketHeader::Ipv4(_) => String::from("Ipv4"),
            PacketHeader::Ipv6(_) => String::from("Ipv6"),
            PacketHeader::Tls(_) => String::from("Tls"),
            PacketHeader::Tcp(_) => String::from("Tcp"),
            PacketHeader::Udp(_) => String::from("Udp"),
            PacketHeader::Ether(_) => String::from("Ether"),
            PacketHeader::Arp(_) => String::from("Arp"),
        }
    }
}

impl PacketParse {
    pub fn new() -> PacketParse {
        PacketParse {}
    }

    pub fn parse_packet(&self, data: Vec<u8>, len: u32, ts: f64) -> Result<ParsedPacket, String> {
        let mut parsed_packet = self.parse_link_layer(&data)?;
        parsed_packet.len = len;
        parsed_packet.timestamp = ts;
        Ok(parsed_packet)
    }

    pub fn parse_link_layer(&self, content: &[u8]) -> Result<ParsedPacket, String> {
        let mut pack = ParsedPacket::new();
        match ethernet::parse_ethernet_frame(content) {
            Ok((content, headers)) => {
                match headers.ethertype {
                    EtherType::IPv4 => {
                        self.parse_ipv4(content, &mut pack)?;
                    }
                    EtherType::IPv6 => {
                        self.parse_ipv6(content, &mut pack)?;
                    }
                    EtherType::ARP => {
                        self.parse_arp(content, &mut pack)?;
                    }
                    _ => {
                        pack.payload = content.to_owned();
                    }
                }
                pack.headers.push(PacketHeader::Ether(headers));
            }
            Err(_) => {
                pack.payload = content.to_owned();
            }
        }
        Ok(pack)
    }

    pub fn parse_ipv4(
        &self,
        content: &[u8],
        parsed_packet: &mut ParsedPacket,
    ) -> Result<(), String> {
        match ipv4::parse_ipv4_header(content) {
            Ok((content, headers)) => {
                self.parse_transport_layer(&headers.protocol, content, parsed_packet)?;
                parsed_packet.headers.push(PacketHeader::Ipv4(headers));
                Ok(())
            }
            Err(err) => {
                parsed_packet.payload = content.to_owned();
                Err(err.to_string())
            }
        }
    }

    pub fn parse_ipv6(
        &self,
        content: &[u8],
        parsed_packet: &mut ParsedPacket,
    ) -> Result<(), String> {
        match ipv6::parse_ipv6_header(content) {
            Ok((content, headers)) => {
                self.parse_transport_layer(&headers.next_header, content, parsed_packet)?;
                parsed_packet.headers.push(PacketHeader::Ipv6(headers));
                Ok(())
            }
            Err(err) => {
                parsed_packet.payload = content.to_owned();
                Err(err.to_string())
            }
        }
    }

    fn parse_transport_layer(
        &self,
        protocol: &ip::IPProtocol,
        content: &[u8],
        parsed_packet: &mut ParsedPacket,
    ) -> Result<(), String> {
        match protocol {
            IPProtocol::UDP => Err("Udp not implemented".to_string()),
            IPProtocol::TCP => {
                self.parse_tcp(content, parsed_packet)?;
                Ok(())
            }
            _ => {
                parsed_packet.payload = content.to_owned();
                Err("Neither TCP nor UDP".to_string())
            }
        }
    }

    fn parse_tcp(&self, content: &[u8], parsed_packet: &mut ParsedPacket) -> Result<(), String> {
        match tcp::parse_tcp_header(content) {
            Ok((content, headers)) => {
                self.parse_tls(content, parsed_packet);
                parsed_packet.headers.push(PacketHeader::Tcp(headers));
                Ok(())
            }
            Err(err) => {
                parsed_packet.payload = content.to_owned();
                Err(err.to_string())
            }
        }
    }

    fn parse_arp(&self, content: &[u8], parsed_packet: &mut ParsedPacket) -> Result<(), String> {
        match arp::parse_arp_pkt(content) {
            Ok((_content, headers)) => {
                parsed_packet.headers.push(PacketHeader::Arp(headers));
                Ok(())
            }
            Err(err) => {
                parsed_packet.payload = content.to_owned();
                Err(err.to_string())
            }
        }
    }

    fn parse_tls(&self, content: &[u8], parsed_packet: &mut ParsedPacket) {
        if let Ok((_content, headers)) = tls_parser::parse_tls_plaintext(content) {
            if let Some(msg) = headers.msg.get(0) {
                match msg {
                    TlsMessage::Handshake(_) => {
                        parsed_packet
                            .headers
                            .push(PacketHeader::Tls(TlsType::Handshake));
                    }
                    TlsMessage::ApplicationData(app_data) => {
                        parsed_packet
                            .headers
                            .push(PacketHeader::Tls(TlsType::ApplicationData));
                        parsed_packet.payload = app_data.blob.to_owned();
                    }
                    TlsMessage::Heartbeat(_) => {
                        parsed_packet
                            .headers
                            .push(PacketHeader::Tls(TlsType::Heartbeat));
                    }
                    TlsMessage::ChangeCipherSpec => {
                        parsed_packet
                            .headers
                            .push(PacketHeader::Tls(TlsType::ChangeCipherSpec));
                    }
                    TlsMessage::Alert(_) => {
                        parsed_packet
                            .headers
                            .push(PacketHeader::Tls(TlsType::Alert));
                    }
                }
            }
        } else if let Ok((_content, headers)) = tls_parser::parse_tls_encrypted(content) {
            parsed_packet
                .headers
                .push(PacketHeader::Tls(TlsType::EncryptedData));
            parsed_packet.payload = headers.msg.blob.to_owned();
        } else {
            parsed_packet.payload = content.to_owned();
        }
    }
}
