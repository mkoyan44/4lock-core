// 4lock-core is Linux-only
fn main() {
    if !std::env::var("CARGO_CFG_TARGET_OS").map_or(false, |v| v == "linux") {
        eprintln!("error: 4lock-core is Linux-only. Build on Linux or use 4lock-agent's cross-compilation (Docker/nerdctl).");
        std::process::exit(1);
    }
}
