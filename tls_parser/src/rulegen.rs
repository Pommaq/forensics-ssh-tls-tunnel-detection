use crate::ethparse;



#[derive(Debug, Clone)]
pub struct RuleData {
    pub srcport: u16,
    pub dstport: u16,
    pub payload: Vec<u8>,
    pub start_ts: f64,
    pub final_ts: f64,
}

impl RuleData {
    pub fn init(srcport: u16, dstport: u16, packet: &ethparse::ParsedPacket) -> Self {
        RuleData {
            srcport,
            dstport,
            payload: packet.payload.clone(),
            start_ts: packet.timestamp,
            final_ts: packet.timestamp,
        }
    }
    pub fn extend(&mut self, packet: &ethparse::ParsedPacket) {
        self.payload.extend_from_slice(packet.payload.as_slice());
        self.final_ts = packet.timestamp;
    }
}

pub trait Rule {
    fn validate_size(
        &self,
        first: &RuleData,
        second: &RuleData,
    ) -> bool;

    fn validate_time(
        &self,
        first: &RuleData,
        second: &RuleData,
    ) -> bool;
}

#[derive(Clone, Copy)]
pub struct TCPRule {
    pub expected_request_size: usize,
    pub expected_response_size: usize,
    pub allowed_size_deviation: usize,

    pub time_delay: f64,
    pub allowed_time_deviation: f64,
}

fn calculate_bounds(expected: usize, allowed_deviation: usize) -> (usize, usize) {
    let lower: usize = expected.abs_diff(allowed_deviation);
    let upper: usize = expected + allowed_deviation;
    (lower, upper)
}

impl Rule for TCPRule {
    fn validate_size(
        &self,
        first: &RuleData,
        second: &RuleData,
    ) -> bool {
        let (req_lower_sz, req_upper_sz) =
            calculate_bounds(self.expected_request_size, self.allowed_size_deviation);
        let (resp_lower_sz, resp_upper_sz) =
            calculate_bounds(self.expected_response_size, self.allowed_size_deviation);

        let first_ok = req_lower_sz <= first.payload.len() && first.payload.len() <= req_upper_sz;
        let second_ok = resp_lower_sz <= second.payload.len() && second.payload.len() <= resp_upper_sz;
        return  first_ok && second_ok;
    }

    fn validate_time(
        &self,
        first: &RuleData,
        second: &RuleData,
    ) -> bool {
        let first_ts = first.final_ts;
        let second_ts = second.start_ts;


        let delta = second_ts - first_ts;
        let delta_lower = self.time_delay * (1.0 - self.allowed_time_deviation);
        let delta_upper = self.time_delay * (1.0 + self.allowed_time_deviation);

        delta_lower <= delta && delta <= delta_upper
    }
}

