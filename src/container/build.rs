fn main() -> Result<(), Box<dyn std::error::Error>> {
    // CRI protos only needed on Linux (container runtime). Allow building lib (intent types) on all platforms for vappc client.
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
