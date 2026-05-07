fn main() -> std::io::Result<()> {
    let fds = protox::compile(["proto/envelope.proto"], ["proto/"]).unwrap();
    prost_build::Config::new().compile_fds(fds).unwrap();
    Ok(())
}
