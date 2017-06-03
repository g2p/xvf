#[macro_use]
extern crate clap;
#[macro_use]
extern crate lazy_static;

extern crate scmp;
extern crate tempdir;

use std::process::Command;
use std::os::unix::process::CommandExt;
use scmp::*;

fn setup_seccomp() -> Result<(), std::io::Error> {
    unsafe {
        let ctx0 = seccomp_init(SCMP_ACT_TRAP);
        assert!(!ctx0.is_null());
        assert!(seccomp_rule_add_array(ctx0, SCMP_ACT_ALLOW, __NR_execve as i32, 0, std::ptr::null()) == 0);
        assert!(seccomp_rule_add_array(ctx0, SCMP_ACT_ALLOW, __NR_brk as i32, 0, std::ptr::null()) == 0);
        assert!(seccomp_rule_add_array(ctx0, SCMP_ACT_ALLOW, __NR_access as i32, 0, std::ptr::null()) == 0);
        assert!(seccomp_rule_add_array(ctx0, SCMP_ACT_ALLOW, __NR_mmap as i32, 0, std::ptr::null()) == 0);
        assert!(seccomp_rule_add_array(ctx0, SCMP_ACT_ALLOW, __NR_open as i32, 0, std::ptr::null()) == 0);
        assert!(seccomp_rule_add_array(ctx0, SCMP_ACT_ALLOW, __NR_read as i32, 0, std::ptr::null()) == 0);
        assert!(seccomp_rule_add_array(ctx0, SCMP_ACT_ALLOW, __NR_write as i32, 0, std::ptr::null()) == 0);
        assert!(seccomp_rule_add_array(ctx0, SCMP_ACT_ALLOW, __NR_stat as i32, 0, std::ptr::null()) == 0);
        assert!(seccomp_rule_add_array(ctx0, SCMP_ACT_ALLOW, __NR_fstat as i32, 0, std::ptr::null()) == 0);
        assert!(seccomp_rule_add_array(ctx0, SCMP_ACT_ALLOW, __NR_close as i32, 0, std::ptr::null()) == 0);
        assert!(seccomp_rule_add_array(ctx0, SCMP_ACT_ALLOW, __NR_mprotect as i32, 0, std::ptr::null()) == 0);
        assert!(seccomp_rule_add_array(ctx0, SCMP_ACT_ALLOW, __NR_arch_prctl as i32, 0, std::ptr::null()) == 0);
        assert!(seccomp_rule_add_array(ctx0, SCMP_ACT_ALLOW, __NR_munmap as i32, 0, std::ptr::null()) == 0);
        assert!(seccomp_rule_add_array(ctx0, SCMP_ACT_ALLOW, __NR_set_tid_address as i32, 0, std::ptr::null()) == 0);
        assert!(seccomp_rule_add_array(ctx0, SCMP_ACT_ALLOW, __NR_set_robust_list as i32, 0, std::ptr::null()) == 0);
        assert!(seccomp_rule_add_array(ctx0, SCMP_ACT_ALLOW, __NR_rt_sigaction as i32, 0, std::ptr::null()) == 0);
        assert!(seccomp_rule_add_array(ctx0, SCMP_ACT_ALLOW, __NR_rt_sigprocmask as i32, 0, std::ptr::null()) == 0);
        assert!(seccomp_rule_add_array(ctx0, SCMP_ACT_ALLOW, __NR_getrlimit as i32, 0, std::ptr::null()) == 0);
        assert!(seccomp_rule_add_array(ctx0, SCMP_ACT_ALLOW, __NR_statfs as i32, 0, std::ptr::null()) == 0);
        assert!(seccomp_rule_add_array(ctx0, SCMP_ACT_ALLOW, __NR_fcntl as i32, 0, std::ptr::null()) == 0);
        assert!(seccomp_rule_add_array(ctx0, SCMP_ACT_ALLOW, __NR_geteuid as i32, 0, std::ptr::null()) == 0);
        assert!(seccomp_rule_add_array(ctx0, SCMP_ACT_ALLOW, __NR_umask as i32, 0, std::ptr::null()) == 0);
        assert!(seccomp_rule_add_array(ctx0, SCMP_ACT_ALLOW, __NR_pipe as i32, 0, std::ptr::null()) == 0);
        assert!(seccomp_rule_add_array(ctx0, SCMP_ACT_ALLOW, __NR_clone as i32, 0, std::ptr::null()) == 0);
        assert!(seccomp_rule_add_array(ctx0, SCMP_ACT_ALLOW, __NR_wait4 as i32, 0, std::ptr::null()) == 0);
        assert!(seccomp_rule_add_array(ctx0, SCMP_ACT_ALLOW, __NR_exit_group as i32, 0, std::ptr::null()) == 0);
        assert!(seccomp_rule_add_array(ctx0, SCMP_ACT_ALLOW, __NR_dup as i32, 0, std::ptr::null()) == 0);
        assert!(seccomp_rule_add_array(ctx0, SCMP_ACT_ALLOW, __NR_ioctl as i32, 0, std::ptr::null()) == 0);
        assert!(seccomp_rule_add_array(ctx0, SCMP_ACT_ALLOW, __NR_getpid as i32, 0, std::ptr::null()) == 0);
        assert!(seccomp_rule_add_array(ctx0, SCMP_ACT_ALLOW, __NR_gettid as i32, 0, std::ptr::null()) == 0);
        assert!(seccomp_rule_add_array(ctx0, SCMP_ACT_ALLOW, __NR_tgkill as i32, 0, std::ptr::null()) == 0);
        assert!(seccomp_rule_add_array(ctx0, SCMP_ACT_ALLOW, __NR_rt_sigreturn as i32, 0, std::ptr::null()) == 0);
        assert!(seccomp_rule_add_array(ctx0, SCMP_ACT_ALLOW, __NR_socket as i32, 0, std::ptr::null()) == 0);
        assert!(seccomp_rule_add_array(ctx0, SCMP_ACT_ALLOW, __NR_connect as i32, 0, std::ptr::null()) == 0);
        assert!(seccomp_rule_add_array(ctx0, SCMP_ACT_ALLOW, __NR_lseek as i32, 0, std::ptr::null()) == 0);
        assert!(seccomp_rule_add_array(ctx0, SCMP_ACT_ALLOW, __NR_openat as i32, 0, std::ptr::null()) == 0);
        assert!(seccomp_rule_add_array(ctx0, SCMP_ACT_ALLOW, __NR_unlinkat as i32, 0, std::ptr::null()) == 0);
        assert!(seccomp_rule_add_array(ctx0, SCMP_ACT_ALLOW, __NR_utimensat as i32, 0, std::ptr::null()) == 0);
        assert!(seccomp_rule_add_array(ctx0, SCMP_ACT_ALLOW, __NR_lstat as i32, 0, std::ptr::null()) == 0);
        assert!(seccomp_rule_add_array(ctx0, SCMP_ACT_ALLOW, __NR_fchmod as i32, 0, std::ptr::null()) == 0);
        assert!(seccomp_rule_add_array(ctx0, SCMP_ACT_ALLOW, __NR_unlink as i32, 0, std::ptr::null()) == 0);
        assert!(seccomp_rule_add_array(ctx0, SCMP_ACT_ALLOW, __NR_utime as i32, 0, std::ptr::null()) == 0);
        assert!(seccomp_load(ctx0) == 0);
    }
    return Ok(());
}


struct ArchiveType {
    extensions: Vec<&'static str>,
    extract_cmd: Vec<&'static str>,
}

lazy_static! {
    static ref ARCHIVE_TYPES : Vec<ArchiveType> = vec![
        ArchiveType {
            extensions: vec![
                ".tgz",
                ".tar.gz",
                ".tar.Z",
                ".tbz2",
                ".tar.bz2",
                ".tlz",
                ".tar.lz",
                ".tar.lzma",
                ".tar.lzo",
                ".tar.xz",
            ],
            extract_cmd: vec!["tar", "-xf"],
        },
        ArchiveType {
            extensions: vec![
                ".zip",
            ],
            extract_cmd: vec!["unzip", "--"],
        },
    ];
}


fn main() {
    let matches = clap_app!(myapp =>
        (@arg ARCHIVE: +required ... "Archives to extract")
    ).get_matches();

    let mut found = false;

    for arch in matches.values_of("ARCHIVE").unwrap() {
        println!("Extract {}", arch);
        for at in ARCHIVE_TYPES.iter() {
            for &ext in &at.extensions {
                if !arch.ends_with(ext) {
                    continue;
                }
                found = true;

                let stripped = &arch[..arch.len()-ext.len()];
                let cmd = at.extract_cmd[0];
                let tmpdir = tempdir::TempDir::new_in(".", (stripped.to_owned() + ".").as_str()).expect("Unable to create temporary directory");
                let status = Command::new(cmd)
                    .args(&at.extract_cmd[1..])
                    .arg(arch)
                    .current_dir(tmpdir)
                    .before_exec(setup_seccomp)
                    .status()
                    .expect(format!("Failed to launch {}", cmd).as_str());
                assert!(status.success(), format!("{} wasn't successful", cmd));
                break;
            }
        }
        if !found {
            println!("Can't handle {}", arch);
        }
    }
}

