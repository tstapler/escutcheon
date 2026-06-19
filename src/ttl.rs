use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub fn should_knock(host: &str, ttl_secs: u64) -> bool {
    if ttl_secs == 0 {
        return true;
    }
    match last_knock_age(host) {
        Some(age) => age > Duration::from_secs(ttl_secs),
        None => true,
    }
}

pub fn record_knock(host: &str) -> anyhow::Result<()> {
    let path = state_path(host)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    std::fs::write(&path, now.to_string())?;
    Ok(())
}

fn last_knock_age(host: &str) -> Option<Duration> {
    let path = state_path(host).ok()?;
    let contents = std::fs::read_to_string(&path).ok()?;
    let ts: u64 = contents.trim().parse().ok()?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    Some(Duration::from_secs(now.saturating_sub(ts)))
}

fn state_path(host: &str) -> anyhow::Result<PathBuf> {
    let base = dirs::state_dir()
        .or_else(|| dirs::data_local_dir())
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    // sanitize host so it's safe as a filename
    let safe = host.replace(['/', '\\', ':'], "_");
    Ok(base.join("escutcheon").join(format!("{safe}.knock")))
}
