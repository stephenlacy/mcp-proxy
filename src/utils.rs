// Constants
pub const DEFAULT_CALLBACK_PORT: u16 = 9292;
pub const DEFAULT_COORDINATION_TIMEOUT: u64 = 30;

pub fn hash_server_url(server_url: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    server_url.hash(&mut hasher);
    format!("{:x}", hasher.finish())
}
