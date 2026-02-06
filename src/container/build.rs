fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 4lock-core is Linux-only
    if !std::env::var("CARGO_CFG_TARGET_OS").map_or(false, |v| v == "linux") {
        eprintln!("error: 4lock-core is Linux-only. Build on Linux or use 4lock-agent's cross-compilation (Docker/nerdctl).");
        std::process::exit(1);
    }
    // Compile CRI protos
    #[cfg(target_os = "linux")]
    {
        tonic_build::configure()
            .build_server(true)
            .build_client(true)
            .protoc_arg("--experimental_allow_proto3_optional")
            .compile_protos(&["proto/cri/api.proto"], &["proto/cri"])?;
    }
    Ok(())
}
