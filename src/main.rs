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
use std::os::raw::c_void;
use std::os::unix::process::CommandExt;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use scmp::*;

unsafe fn allow_syscall(ctx : *mut c_void, nr : u32) {
    assert!(seccomp_rule_add_array(ctx, SCMP_ACT_ALLOW, nr as i32, 0, std::ptr::null()) == 0);
}

fn setup_seccomp() -> Result<(), Error> {
    unsafe {
        let ctx0 = seccomp_init(SCMP_ACT_TRAP);
        assert!(!ctx0.is_null());
        allow_syscall(ctx0, __NR_execve);
        allow_syscall(ctx0, __NR_brk);
        allow_syscall(ctx0, __NR_access);
        allow_syscall(ctx0, __NR_mmap);
        allow_syscall(ctx0, __NR_open);
        allow_syscall(ctx0, __NR_read);
        allow_syscall(ctx0, __NR_write);
        allow_syscall(ctx0, __NR_stat);
        allow_syscall(ctx0, __NR_fstat);
        allow_syscall(ctx0, __NR_close);
        allow_syscall(ctx0, __NR_mprotect);
        allow_syscall(ctx0, __NR_arch_prctl);
        allow_syscall(ctx0, __NR_munmap);
        allow_syscall(ctx0, __NR_set_tid_address);
        allow_syscall(ctx0, __NR_set_robust_list);
        allow_syscall(ctx0, __NR_rt_sigaction);
        allow_syscall(ctx0, __NR_rt_sigprocmask);
        allow_syscall(ctx0, __NR_getrlimit);
        allow_syscall(ctx0, __NR_statfs);
        allow_syscall(ctx0, __NR_fcntl);
        allow_syscall(ctx0, __NR_geteuid);
        allow_syscall(ctx0, __NR_umask);
        allow_syscall(ctx0, __NR_pipe);
        allow_syscall(ctx0, __NR_clone);
        allow_syscall(ctx0, __NR_wait4);
        allow_syscall(ctx0, __NR_exit_group);
        allow_syscall(ctx0, __NR_dup);
        allow_syscall(ctx0, __NR_ioctl);
        allow_syscall(ctx0, __NR_getpid);
        allow_syscall(ctx0, __NR_gettid);
        allow_syscall(ctx0, __NR_tgkill);
        allow_syscall(ctx0, __NR_rt_sigreturn);
        allow_syscall(ctx0, __NR_socket);
        allow_syscall(ctx0, __NR_connect);
        allow_syscall(ctx0, __NR_lseek);
        allow_syscall(ctx0, __NR_openat);
        allow_syscall(ctx0, __NR_unlinkat);
        allow_syscall(ctx0, __NR_utimensat);
        allow_syscall(ctx0, __NR_lstat);
        allow_syscall(ctx0, __NR_fchmod);
        allow_syscall(ctx0, __NR_unlink);
        allow_syscall(ctx0, __NR_utime);
        allow_syscall(ctx0, __NR_futex);
        allow_syscall(ctx0, __NR_chmod);
        allow_syscall(ctx0, __NR_getuid);
        allow_syscall(ctx0, __NR_getgid);
        allow_syscall(ctx0, __NR_getppid);
        allow_syscall(ctx0, __NR_getcwd);
        allow_syscall(ctx0, __NR_getegid);
        allow_syscall(ctx0, __NR_getdents);
        allow_syscall(ctx0, __NR_readlink);
        allow_syscall(ctx0, __NR_mkdirat);
        allow_syscall(ctx0, __NR_mkdir);
        assert!(seccomp_load(ctx0) == 0);
    }
    return Ok(());
}

const RENAME_NOREPLACE : u64 = 1;

fn path_to_cstring(path : &Path) -> CString {
    return CString::new(path.as_os_str().as_bytes()).unwrap();
}

fn rename_noreplace(path0 : &Path, path1 : &Path) -> Result<(), Error> {
    unsafe {
        if libc::syscall(__NR_renameat2 as i64, libc::AT_FDCWD, path_to_cstring(path0).as_ptr(), libc::AT_FDCWD, path_to_cstring(path1).as_ptr(), RENAME_NOREPLACE, 0) == 0 {
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
        ArchiveType {
            extensions: vec![
                ".part1.rar",
                ".rar",
            ],
            extract_cmd: vec!["unrar", "x", "--"],
        },
        ArchiveType {
            extensions: vec![
                ".7z",
            ],
            extract_cmd: vec!["7z", "x", "--"],
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
        let arch_bytes = arch.as_os_str().as_bytes();
        println!("Extract {:?}", arch);
        for at in ARCHIVE_TYPES.iter() {
            for &ext in &at.extensions {
                let ext_bytes = ext.as_bytes();
                if !arch_bytes.ends_with(ext_bytes) {
                    continue;
                }
                found = true;

                let noext : &OsStr = OsStrExt::from_bytes(&arch_bytes[0..arch_bytes.len()-ext_bytes.len()]);
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
                    .arg(fs::canonicalize(&arch).expect("Unable to find archive"))
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
                        let newname = rename_or_suffix(&extracted_path, Path::new(stripped)).expect("Failed to rename");
                        println!("Extracted to {:?}", newname);
                    } else {
                        let newname = rename_or_suffix(&path.path(), Path::new(stripped)).expect("Failed to rename");
                        println!("Extracted to {:?}", newname);
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

