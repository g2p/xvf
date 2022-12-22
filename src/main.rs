extern crate bpaf;
#[macro_use]
extern crate lazy_static;

extern crate libc;
extern crate scmp;
extern crate tempfile;

use scmp::*;
use std::env;
use std::ffi::CString;
use std::ffi::OsStr;
use std::fs;
use std::io::Error;
use std::os::raw::c_void;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

unsafe fn allow_syscall(ctx: *mut c_void, nr: u32) {
    assert_eq!(
        seccomp_rule_add_array(ctx, SCMP_ACT_ALLOW, nr as i32, 0, std::ptr::null()),
        0
    );
}

fn setup_seccomp() -> Result<(), Error> {
    unsafe {
        let ctx = seccomp_init(SCMP_ACT_TRAP);
        assert!(!ctx.is_null());
        allow_syscall(ctx, __NR_execve);
        allow_syscall(ctx, __NR_brk);
        allow_syscall(ctx, __NR_access);
        allow_syscall(ctx, __NR_mmap);
        allow_syscall(ctx, __NR_open);
        allow_syscall(ctx, __NR_read);
        allow_syscall(ctx, __NR_write);
        allow_syscall(ctx, __NR_stat);
        allow_syscall(ctx, __NR_fstat);
        allow_syscall(ctx, __NR_newfstatat);
        allow_syscall(ctx, __NR_close);
        allow_syscall(ctx, __NR_mprotect);
        allow_syscall(ctx, __NR_arch_prctl);
        allow_syscall(ctx, __NR_munmap);
        allow_syscall(ctx, __NR_set_tid_address);
        allow_syscall(ctx, __NR_set_robust_list);
        allow_syscall(ctx, __NR_rt_sigaction);
        allow_syscall(ctx, __NR_rt_sigprocmask);
        allow_syscall(ctx, __NR_getrlimit);
        allow_syscall(ctx, __NR_prlimit64);
        allow_syscall(ctx, __NR_gettimeofday);
        allow_syscall(ctx, __NR_clock_gettime);
        allow_syscall(ctx, __NR_recvmsg);
        allow_syscall(ctx, __NR_statfs);
        allow_syscall(ctx, __NR_fcntl);
        allow_syscall(ctx, __NR_geteuid);
        allow_syscall(ctx, __NR_umask);
        allow_syscall(ctx, __NR_pipe);
        allow_syscall(ctx, __NR_clone);
        allow_syscall(ctx, __NR_wait4);
        allow_syscall(ctx, __NR_exit_group);
        allow_syscall(ctx, __NR_dup);
        assert_eq!(
            seccomp_rule_add(
                ctx,
                SCMP_ACT_ALLOW,
                __NR_ioctl as i32,
                1,
                scmp_arg_cmp {
                    arg: 1,
                    op: scmp_compare_SCMP_CMP_EQ,
                    datum_a: libc::FIOCLEX,
                    datum_b: 0,
                }
            ),
            0
        );
        assert_eq!(
            seccomp_rule_add(
                ctx,
                SCMP_ACT_ALLOW,
                __NR_ioctl as i32,
                1,
                scmp_arg_cmp {
                    arg: 1,
                    op: scmp_compare_SCMP_CMP_EQ,
                    datum_a: libc::FIONBIO,
                    datum_b: 0,
                }
            ),
            0
        );
        assert_eq!(
            seccomp_rule_add(
                ctx,
                SCMP_ACT_ALLOW,
                __NR_ioctl as i32,
                1,
                scmp_arg_cmp {
                    arg: 1,
                    op: scmp_compare_SCMP_CMP_EQ,
                    datum_a: libc::TCGETS,
                    datum_b: 0,
                }
            ),
            0
        );
        assert_eq!(
            seccomp_rule_add(
                ctx,
                SCMP_ACT_ALLOW,
                __NR_ioctl as i32,
                1,
                scmp_arg_cmp {
                    arg: 1,
                    op: scmp_compare_SCMP_CMP_EQ,
                    datum_a: libc::TIOCGWINSZ,
                    datum_b: 0,
                }
            ),
            0
        );
        allow_syscall(ctx, __NR_getpid);
        allow_syscall(ctx, __NR_gettid);
        allow_syscall(ctx, __NR_tgkill);
        allow_syscall(ctx, __NR_rt_sigreturn);
        allow_syscall(ctx, __NR_socket);
        allow_syscall(ctx, __NR_connect);
        allow_syscall(ctx, __NR_sendto);
        allow_syscall(ctx, __NR_poll);
        allow_syscall(ctx, __NR_lseek);
        allow_syscall(ctx, __NR_openat);
        allow_syscall(ctx, __NR_unlinkat);
        allow_syscall(ctx, __NR_utimensat);
        allow_syscall(ctx, __NR_lstat);
        allow_syscall(ctx, __NR_fchmod);
        allow_syscall(ctx, __NR_unlink);
        allow_syscall(ctx, __NR_utime);
        allow_syscall(ctx, __NR_futex);
        allow_syscall(ctx, __NR_chmod);
        allow_syscall(ctx, __NR_getuid);
        allow_syscall(ctx, __NR_getgid);
        allow_syscall(ctx, __NR_getppid);
        allow_syscall(ctx, __NR_getcwd);
        allow_syscall(ctx, __NR_getegid);
        allow_syscall(ctx, __NR_getdents);
        allow_syscall(ctx, __NR_readlink);
        allow_syscall(ctx, __NR_mkdirat);
        allow_syscall(ctx, __NR_mkdir);
        allow_syscall(ctx, __NR_madvise);
        allow_syscall(ctx, __NR_exit);
        assert_eq!(seccomp_load(ctx), 0);
    }
    Ok(())
}

const RENAME_NOREPLACE: u64 = 1;

fn path_to_cstring(path: &Path) -> CString {
    CString::new(path.as_os_str().as_bytes()).unwrap()
}

fn rename_noreplace(path0: &Path, path1: &Path) -> Result<(), Error> {
    unsafe {
        if libc::syscall(
            __NR_renameat2 as i64,
            libc::AT_FDCWD,
            path_to_cstring(path0).as_ptr(),
            libc::AT_FDCWD,
            path_to_cstring(path1).as_ptr(),
            RENAME_NOREPLACE,
            0,
        ) == 0
        {
            Ok(())
        } else {
            Err(Error::last_os_error())
        }
    }
}

fn rename_or_suffix(path0: &Path, path1: &Path) -> Result<PathBuf, Error> {
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
        Ok(PathBuf::new()) // XXX Unreachable
    } else {
        Ok(path1.to_path_buf())
    }
}

struct ArchiveType {
    extensions: Vec<&'static str>,
    extract_cmd: Vec<&'static str>,
}

lazy_static! {
    static ref ARCHIVE_TYPES: Vec<ArchiveType> = vec![
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
            extensions: vec![".zip",],
            extract_cmd: vec!["unzip", "--"],
        },
        ArchiveType {
            extensions: vec![".part1.rar", ".rar",],
            extract_cmd: vec!["unrar", "x", "--"],
        },
        ArchiveType {
            extensions: vec![".7z",],
            extract_cmd: vec!["7z", "x", "--"],
        },
    ];
}

fn main() {
    let parser = bpaf::positional("ARCHIVE").some("At least one archive is required");
    let archives = bpaf::Info::default()
        .descr("Extract archives")
        .for_parser(parser)
        .run();

    let mut found = false;

    for arch in &archives {
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

                let noext: &OsStr =
                    OsStrExt::from_bytes(&arch_bytes[0..arch_bytes.len() - ext_bytes.len()]);
                let stripped = if let Some(noext) = Path::new(noext).file_name() {
                    noext
                } else {
                    OsStr::new("extracted")
                };
                let cmd = at.extract_cmd[0];
                let tmpdir = tempfile::Builder::new()
                    .prefix(stripped)
                    .tempdir_in(env::current_dir().expect("Unable to get the current directory"))
                    .expect("Unable to create temporary directory");
                let status = unsafe {
                    Command::new(cmd)
                        .args(&at.extract_cmd[1..])
                        .arg(fs::canonicalize(arch).expect("Unable to find archive"))
                        .current_dir(&tmpdir)
                        .pre_exec(setup_seccomp)
                        .status()
                        .unwrap_or_else(|_| panic!("Failed to launch {}", cmd))
                };
                assert!(status.success(), "{} wasn't successful", cmd);
                let extracted_path = tmpdir.into_path();
                let mut dir_list =
                    fs::read_dir(&extracted_path).expect("Unable to read the extraction directory");
                if let Some(path) = dir_list.next() {
                    let path = path.expect("Unable to iterate the extraction directory");
                    if let Some(path1) = dir_list.next() {
                        path1.expect("Unable to iterate the extraction directory");
                        let newname = rename_or_suffix(&extracted_path, Path::new(stripped))
                            .expect("Failed to rename");
                        println!("Extracted to {:?}", newname);
                    } else {
                        let newname = rename_or_suffix(&path.path(), Path::new(stripped))
                            .expect("Failed to rename");
                        println!("Extracted to {:?}", newname);
                        fs::remove_dir(&extracted_path)
                            .expect("Failed to remove empty extraction directory");
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
