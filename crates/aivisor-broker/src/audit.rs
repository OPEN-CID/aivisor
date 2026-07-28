use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct BrokerEvent {
    pub sandbox_id: String,
    pub turn_id: String,
    pub method: String,
    pub host: String,
    pub path: String,
    pub status: u16,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub ts: String,
}
