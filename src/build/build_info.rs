use once_cell::sync::Lazy;
use std::env;
use std::sync::Mutex;

include!(concat!(env!("OUT_DIR"), "/shuffle_generated.rs"));

#[derive(Debug, Clone)]
pub struct BuildInfo {
    pub version: String,
    pub build_time: u64,
    pub build_rand: u64,
    pub build_seed: u64,
    pub build_seed2: u64,
    pub build_epoch: i64,
    pub build_hk: String,
    pub shuffled_order: String,
}

fn load_from_env() -> BuildInfo {
    let shuffled = SHUFFLED_ORDER.join(",");

    BuildInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        build_time: env!("BUILD_TIME").parse().unwrap_or(0),
        build_rand: env!("BUILD_RAND").parse().unwrap_or(0),
        build_seed: env!("BUILD_SEED").parse().unwrap_or(0),
        build_seed2: env!("BUILD_SEED2").parse().unwrap_or(0),
        build_epoch: env!("BUILD_EPOCH_DATE").parse().unwrap_or(0),
        build_hk: env!("BUILD_HK").to_string(),
        shuffled_order: shuffled,
    }
}

pub static BUILD_INFO: Lazy<Mutex<BuildInfo>> = Lazy::new(|| Mutex::new(load_from_env()));

pub fn get() -> BuildInfo {
    BUILD_INFO.lock().unwrap().clone()
}

pub fn update(new_info: BuildInfo) {
    let mut info = BUILD_INFO.lock().unwrap();
    *info = new_info;
}

pub fn update_build_info(input: &str) -> Result<(), String> {
    let parts: Vec<&str> = input.split('|').collect();

    if parts.len() != 8 {
        return Err("Invalid input shuffle format. Expected 8 fields.".into());
    }

    let build_info = BuildInfo {
        version: parts[0].to_string(),
        build_time: parts[1].parse().map_err(|_| "Invalid build_time")?,
        build_rand: parts[2].parse().map_err(|_| "Invalid build_rand")?,
        build_seed: parts[3].parse().map_err(|_| "Invalid build_seed")?,
        build_seed2: parts[4].parse().map_err(|_| "Invalid build_seed2")?,
        build_epoch: parts[5].parse().map_err(|_| "Invalid build_epoch")?,
        build_hk: parts[6].to_string(),
        shuffled_order: parts[7].to_string(),
    };

    // Checked after the field parsing so that a malformed build_time
    // still reports build_time rather than being masked by this guard.
    //
    // The build secret is key material: it is the HKDF salt in
    // the zerocrypt vault's key derivation and signature. A keystore
    // produced before the 256-bit change carries a 26-character value,
    // and importing it would silently drop the deployment back to ~70
    // bits. Fail loudly instead.
    if build_info.build_hk.len() < 64 {
        return Err(
            "build_hk too short: this keystore predates the 256-bit build secret. \
             Re-run the export on an upgraded instance."
                .into(),
        );
    }

    update(build_info);
    Ok(())
}

impl BuildInfo {
    pub fn to_string(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}|{}|{}|{}",
            self.version,
            self.build_time,
            self.build_rand,
            self.build_seed,
            self.build_seed2,
            self.build_epoch,
            self.build_hk,
            self.shuffled_order
        )
    }

    /// The build's field ordering, as a list.
    ///
    /// The token signature no longer uses it — the vault has its own
    /// construction — but it is folded into the vault's key at startup,
    /// so it still binds a deployment to its own build constants.
    pub fn shuffled_order_list(&self) -> Vec<String> {
        self.shuffled_order
            .split(',')
            .map(|s| s.trim().to_string())
            .collect()
    }
}
