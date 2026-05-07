fn main() -> std::io::Result<()> {
    let fds =
        protox::compile(["proto/envelope.proto", "proto/manifest.proto"], ["proto/"]).unwrap();
    prost_build::Config::new()
        .type_attribute(".", "#[allow(dead_code)]")
        .compile_fds(fds)
        .unwrap();
    Ok(())
}
