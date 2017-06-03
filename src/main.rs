#[macro_use]
extern crate clap;
extern crate seccomp;

use std::process::Command;
use std::os::unix::process::CommandExt;

fn setup_seccomp() -> Result<(), std::io::Error> {
    let mut ctx = seccomp::Context::default(seccomp::Action::Trap).unwrap();
    ctx.add_rule(
        seccomp::Rule::new(59, seccomp::Action::Allow)
        ).unwrap();
    ctx.load().unwrap();
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
