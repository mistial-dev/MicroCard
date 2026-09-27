fn main() {
    let source = std::path::Path::new("../../vendor/tiny-crypto-c/src");
    cc::Build::new()
        .include(source)
        .file(source.join("ec.c"))
        .file(source.join("common.c"))
        .file(source.join("sha512.c"))
        .file("src/bridge.c")
        .file("src/hash_bridge.c")
        .flag_if_supported("-std=c11")
        .define("TC_ENABLE_EC", "1")
        .define("TC_EC_ENABLE_P192", "1")
        .define("TC_EC_ENABLE_P256", "0")
        .define("TC_EC_ENABLE_P384", "1")
        .define("TC_ENABLE_SHA384", "1")
        .define("TC_ENABLE_SHA512", "1")
        .define("TC_ENABLE_HMAC", "0")
        .define("TC_ZEROIZE", "1")
        .define("TC_STRICT", "1")
        .compile("microcard_tiny_crypto");
    for path in ["src/bridge.c", "src/hash_bridge.c", "../../vendor/tiny-crypto-c/src"] {
        println!("cargo:rerun-if-changed={path}");
    }
}
