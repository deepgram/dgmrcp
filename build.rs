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
    println!("cargo:rerun-if-env-changed=MRCP_INCLUDE_PATH");

    let mut includes = env::var("MRCP_INCLUDE_PATH")
        .map(|x| {
            x.split(':')
                .filter(|x| !x.is_empty())
                .map(|x| x.to_string())
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|_| {
            ["/usr/local/unimrcp/include", "/usr/local/apr/include/apr-1"]
                .iter()
                .map(|&x| x.to_string())
                .collect::<Vec<_>>()
        });

    includes.push(native().to_string_lossy().to_string());

    let mut builder = bindgen::Builder::default();
    builder = builder
        .clang_args(
            &includes
                .into_iter()
                .map(|x| format!("-I{}", x))
                .collect::<Vec<_>>(),
        )
        .header(native().join("dgmrcp.h").to_string_lossy())
        .constified_enum_module("*")
        .prepend_enum_name(false)
        .derive_eq(true);

    let bindings = builder.generate().expect("Unable to generate bindings.");
    bindings
        .write_to_file(output().join("bindings.rs"))
        .expect("Unable to write bindings.");
}
