use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=k210-sentinel.ld");
    println!("cargo:rerun-if-changed=k210-runtime.ld");
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let sentinel_enabled = env::var_os("CARGO_FEATURE_SAFE_IDLE_SENTINEL").is_some();
    let phase_a_enabled = env::var_os("CARGO_FEATURE_PHASE_A").is_some();
    let renode_console_enabled = env::var_os("CARGO_FEATURE_RENODE_CONSOLE").is_some();
    if target_arch != "riscv64" {
        return;
    }

    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    if sentinel_enabled {
        let linker_script = manifest_dir.join("k210-sentinel.ld");
        println!(
            "cargo:rustc-link-arg-bin=dcent-k210-safe-idle-sentinel=-T{}",
            linker_script.display()
        );
    }
    let runtime_linker = manifest_dir.join("k210-runtime.ld");
    if phase_a_enabled {
        println!(
            "cargo:rustc-link-arg-bin=dcent-k210-safe-idle-runtime=-T{}",
            runtime_linker.display()
        );
    }
    if renode_console_enabled {
        println!(
            "cargo:rustc-link-arg-bin=dcent-k210-renode-console=-T{}",
            runtime_linker.display()
        );
    }
}
