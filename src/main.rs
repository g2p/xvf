#[macro_use]
extern crate clap;

fn main() {
    let matches = clap_app!(myapp =>
        (@arg ARCHIVE: +required ... "Archives to extract")
    ).get_matches();

	for arch in matches.values_of("ARCHIVE").unwrap() {
		println!("Extract {}", arch);
    }
}
