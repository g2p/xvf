#[macro_use]
extern crate clap;
#[macro_use]
extern crate lazy_static;

extern crate libc;
extern crate scmp;
extern crate tempdir;

use std::fs;
use std::env;
use std::ffi::OsStr;
use std::ffi::CString;
use std::io::Error;
use std::os::unix::process::CommandExt;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use scmp::*;

fn setup_seccomp() -> Result<(), Error> {
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

const RENAME_NOREPLACE : u64 = 1;

fn rename_noreplace(path0 : &Path, path1 : &Path) -> Result<(), Error> {
    unsafe {
        if libc::syscall(__NR_renameat2 as i64, libc::AT_FDCWD, CString::new(path0.as_os_str().as_bytes()).unwrap().as_ptr(), libc::AT_FDCWD, CString::new(path1.as_os_str().as_bytes()).unwrap().as_ptr(), RENAME_NOREPLACE, 0) == 0 {
            return Ok(());
        } else {
            return Err(Error::last_os_error());
        }
    }
}

fn rename_or_suffix(path0 : &Path, path1 : &Path) -> Result<PathBuf, Error> {
    let rv = rename_noreplace(path0, path1);
    if let Err(err) = rv {
        if err.raw_os_error().expect("Error fails to wrap errno") != libc::EEXIST {
            return Err(err);
        }
        for suffix in 1.. {
            let mut builder = path1.as_os_str().to_os_string();
            builder.push(format!(".{}", suffix));
            let rv = rename_noreplace(path0, Path::new(&builder));
            if let Err(err) = rv {
                if err.raw_os_error().expect("Error fails to wrap errno") != libc::EEXIST {
                    return Err(err);
                }
                continue;
            }
            return Ok(Path::new(&builder).to_path_buf());
        }
        return Ok(PathBuf::new()); // XXX Unreachable
    } else {
        return Ok(path1.to_path_buf());
    }
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

    for arch in matches.values_of_os("ARCHIVE").unwrap() {
        let arch = Path::new(arch);
        println!("Extract {:?}", arch);
        for at in ARCHIVE_TYPES.iter() {
            for &ext in &at.extensions {
                if !arch.as_os_str().as_bytes().ends_with(ext.as_bytes()) {
                    continue;
                }
                found = true;

                let noext : &OsStr = OsStrExt::from_bytes(&arch.as_os_str().as_bytes()[0..arch.as_os_str().as_bytes().len()-ext.as_bytes().len()]);
                let stripped =
                    if let Some(noext) = Path::new(noext).file_name() {
                        noext
                    } else {
                        OsStr::new("extracted")
                    };
                let cmd = at.extract_cmd[0];
                let tmpdir = tempdir::TempDir::new_in(
                    env::current_dir().expect("Unable to get the current directory"),
                    stripped.to_string_lossy().to_mut().as_str()).expect("Unable to create temporary directory");
                let status = Command::new(cmd)
                    .args(&at.extract_cmd[1..])
                    .arg(&arch)
                    .current_dir(&tmpdir)
                    .before_exec(setup_seccomp)
                    .status()
                    .expect(format!("Failed to launch {}", cmd).as_str());
                assert!(status.success(), format!("{} wasn't successful", cmd));
                let extracted_path = tmpdir.into_path();
                let mut dir_list = fs::read_dir(&extracted_path).expect("Unable to read the extraction directory");
                if let Some(path) = dir_list.next() {
                    let path = path.expect("Unable to iterate the extraction directory");
                    if let Some(path1) = dir_list.next() {
                        path1.expect("Unable to iterate the extraction directory");
                        rename_or_suffix(&extracted_path, Path::new(stripped)).expect("Failed to rename");
                    } else {
                        rename_or_suffix(&path.path(), Path::new(stripped)).expect("Failed to rename");
                        fs::remove_dir(&extracted_path).expect("Failed to remove empty extraction directory");
                    }
                } else {
                    println!("No files were extracted");
                }
                break;
            }
        }
        if !found {
            println!("Can't handle {:?}", arch);
        }
    }
}

