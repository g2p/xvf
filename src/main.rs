#[macro_use]
extern crate clap;

use std::process::Command;


fn main() {
    let matches = clap_app!(myapp =>
        (@arg ARCHIVE: +required ... "Archives to extract")
    ).get_matches();

    for arch in matches.values_of("ARCHIVE").unwrap() {
        println!("Extract {}", arch);
        if arch.ends_with(".tgz") {
            let status = Command::new("tar")
                .arg("-xf")
                .arg(arch)
                .status()
                .expect("Failed to launch tar");
            assert!(status.success(), "tar wasn't successful");
        } else {
            println!("Can't handle {}", arch);
        }
    }
}
