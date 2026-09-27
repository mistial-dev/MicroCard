fn main() {
    let source = std::path::Path::new("../../vendor/tiny-crypto-c/src");
    let mut build = cc::Build::new();
    build
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
        .define("TC_STRICT", "1");
    if std::env::var_os("CARGO_FEATURE_DES_LEGACY").is_some() {
        build
            .file(source.join("des.c"))
            .file("src/des_bridge.c")
            .define("TC_ENABLE_DES", "1")
            .define("TC_DES_ENABLE_ECB", "1")
            .define("TC_DES_ENABLE_CBC", "1")
            .define("TC_DES_ENABLE_CTR", "0")
            .define("TC_DES_ENABLE_OFB", "0")
            .define("TC_DES_ENABLE_CFB1", "0")
            .define("TC_DES_ENABLE_CFB8", "0")
            .define("TC_DES_ENABLE_CFB64", "0")
            .define("TC_DES_ENABLE_TDES", "1")
            .define("TC_DES_ENABLE_CMAC", "0")
            .define("TC_DES_ENABLE_ISO9797", "1")
            .define("TC_DES_REJECT_WEAK_KEYS", "0");
    }
    build.compile("microcard_tiny_crypto");
    for path in [
        "src/bridge.c",
        "src/hash_bridge.c",
        "src/des_bridge.c",
        "../../vendor/tiny-crypto-c/src",
    ] {
        println!("cargo:rerun-if-changed={path}");
    }
}
