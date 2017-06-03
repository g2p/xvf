#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[macro_use]
extern crate clap;

use std::process::Command;
use std::os::unix::process::CommandExt;

fn setup_seccomp() -> Result<(), std::io::Error> {
    unsafe {
        let ctx0 = seccomp_init(SCMP_ACT_TRAP);
        assert!(!ctx0.is_null());
        assert!(seccomp_rule_add_array(ctx0, SCMP_ACT_ALLOW, __NR_execve as i32, 0, std::ptr::null()) == 0);
        assert!(seccomp_load(ctx0) == 0);
    }
    return Ok(());
}


fn main() {
    let matches = clap_app!(myapp =>
        (@arg ARCHIVE: +required ... "Archives to extract")
    ).get_matches();

    for arch in matches.values_of("ARCHIVE").unwrap() {
        println!("Extract {}", arch);
        if
            arch.ends_with(".tgz")
            || arch.ends_with(".tar.gz")
            || arch.ends_with(".tar.Z")
            || arch.ends_with(".tbz2")
            || arch.ends_with(".tar.bz2")
            || arch.ends_with(".tlz")
            || arch.ends_with(".tar.lz")
            || arch.ends_with(".tar.lzma")
            || arch.ends_with(".tar.lzo")
            || arch.ends_with(".tar.xz")
        {
            let status = Command::new("tar")
                .arg("-xf")
                .arg(arch)
                .before_exec(setup_seccomp)
                .status()
                .expect("Failed to launch tar");
            assert!(status.success(), "tar wasn't successful");
        } else {
            println!("Can't handle {}", arch);
        }
    }
}
