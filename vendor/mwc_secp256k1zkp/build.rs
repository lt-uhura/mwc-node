// Bitcoin secp256k1-zkp bindings
// Written in 2015 by
//   Andrew Poelstra
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! # Build script

// Coding conventions
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![warn(missing_docs)]

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-env-changed=MWC_SECP_BACKEND");
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH")?;
    let target_vendor = std::env::var("CARGO_CFG_TARGET_VENDOR")?;
    let backend = std::env::var("MWC_SECP_BACKEND").unwrap_or_else(|_| "auto".into());
    let supported = target_arch == "aarch64" && target_vendor == "apple";
    let wide = match backend.as_str() {
        "auto" => supported,
        "32" => false,
        "64" if supported => true,
        _ => return Err("MWC_SECP_BACKEND must be auto or 32; 64 requires Apple aarch64".into()),
    };
    println!("cargo:warning=MWC secp backend={} target={}-{}", if wide { "64 (5x52/4x64)" } else { "32 (10x26/8x32)" }, target_arch, target_vendor);
    let mut base_config = cc::Build::new();
    if wide {
        base_config.define("USE_FIELD_5X52", Some("1"))
                   .define("USE_SCALAR_4X64", Some("1"))
                   .define("HAVE___INT128", Some("1"));
    } else {
        base_config.define("USE_FIELD_10X26", Some("1"))
                   .define("USE_SCALAR_8X32", Some("1"));
    }
    base_config.include("depend/secp256k1-zkp/")
               .include("depend/secp256k1-zkp/include")
               .include("depend/secp256k1-zkp/src")
                // -g is for debug. Removing for release build
                //.flag("-g")
               // TODO these three should be changed to use libgmp, at least until secp PR 290 is merged
               .define("USE_NUM_NONE", Some("1"))
               .define("USE_FIELD_INV_BUILTIN", Some("1"))
               .define("USE_SCALAR_INV_BUILTIN", Some("1"))
               .define("USE_ENDOMORPHISM", Some("1"))
               // These all are OK.
               .define("ENABLE_MODULE_ECDH", Some("1"))
               .define("ENABLE_MODULE_GENERATOR", Some("1"))
               .define("ENABLE_MODULE_RECOVERY", Some("1"))
               .define("ENABLE_MODULE_RANGEPROOF", Some("1"))
               .define("ENABLE_MODULE_BULLETPROOF", Some("1"))
               .define("ENABLE_MODULE_AGGSIG", Some("1"))
               .define("ENABLE_MODULE_SCHNORRSIG", Some("1"));

    // secp256k1-zkp
    base_config.file("depend/secp256k1-zkp/contrib/lax_der_parsing.c")
               .file("depend/secp256k1-zkp/src/secp256k1.c");

    let compiler = base_config.try_get_compiler()?;
    if compiler.is_like_gnu() || compiler.is_like_clang() {
        base_config.flag("-Wno-unused-function");
    }

    base_config.try_compile("libsecp256k1.a")?;
    Ok(())
}
