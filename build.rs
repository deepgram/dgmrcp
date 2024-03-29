use std::env;
use std::path::PathBuf;

/// Where our native code is stored.
fn native() -> PathBuf {
    // TODO: I think this should come from a cargo env var.
    let mut absolute = env::current_dir().unwrap();
    absolute.push("native");
    absolute
}

/// Where our generated code is stored.
fn output() -> PathBuf {
    PathBuf::from(env::var("OUT_DIR").unwrap())
}

fn main() {
    println!("cargo:rerun-if-changed=native/dgmrcp.h");

    // Links for testing
    println!("cargo:rustc-link-lib=apr-1");
    println!("cargo:rustc-link-lib=unimrcpserver");
    println!("cargo:rustc-link-search=/opt/unimrcp/lib");

    let mut builder = bindgen::Builder::default();
    builder = builder
        .header(native().join("dgmrcp.h").to_string_lossy())
        .constified_enum_module("*")
        .prepend_enum_name(false)
        // The autogenerated type is u32, but we want it to be
        // apt_bool_t, so we'll manually define this.
        .blacklist_item("FALSE")
        .derive_eq(true);

    let bindings = builder.generate().expect("Unable to generate bindings.");
    bindings
        .write_to_file(output().join("bindings.rs"))
        .expect("Unable to write bindings.");
}
