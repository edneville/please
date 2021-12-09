//    pleaseedit
//    Copyright (C) 2020-2021 ed neville
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU General Public License as published by
//    the Free Software Foundation, either version 3 of the License, or
//    (at your option) any later version.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU General Public License for more details.
//
//    You should have received a copy of the GNU General Public License
//    along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! please.rs a sudo-like clone that implements regex all over the place

use pleaser::*;

use std::convert::TryFrom;
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;

use std::io::{self, Write};
use std::os::unix::io::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};

use regex::Regex;
use std::collections::HashMap;

use getopts::Options;

use nix::sys::signal;
use nix::sys::signal::Signal;
use nix::sys::stat::fchmod;
use nix::sys::wait::WaitStatus::Exited;
use nix::unistd::{fchown, fork, ForkResult};
use users::*;

/// return a path string to work on in /tmp
fn tmp_edit_file_name(source_file: &Path, service: &str, original_user: &str) -> String {
    format!(
        "/tmp/{}.{}.{}.{}",
        service,
        original_user,
        prng_alpha_num_string(8),
        source_file.to_str().unwrap().replace('/', "_"),
    )
}

/// return a path string that exitcmd can use adjacent in the source location
fn source_tmp_file_name(source_file: &Path, service: &str, original_user: &str) -> String {
    format!(
        "{}.{}.{}.{}",
        source_file.to_str().unwrap(),
        prng_alpha_num_string(8),
        service,
        original_user,
    )
}

/// copy the contents of source file into the tmp file with original user ownership
fn setup_temp_edit_file(
    service: &str,
    source_file: &Path,
    ro: &RunOptions,
    target_uid: nix::unistd::Uid,
    target_gid: nix::unistd::Gid,
) -> String {
    if !drop_privs(&ro) {
        std::process::exit(1);
    }

    let tmp_edit_file = tmp_edit_file_name(&source_file, &service, &ro.name);
    let tmp_edit_file_path = Path::new(&tmp_edit_file);

    if tmp_edit_file_path.exists() && std::fs::remove_file(tmp_edit_file_path).is_err() {
        println!("Could not remove {}", tmp_edit_file_path.to_str().unwrap());
        std::process::exit(1);
    }

    if !esc_privs() {
        std::process::exit(1);
    }
    if !set_eprivs(target_uid, target_gid) {
        std::process::exit(1);
    }
    let mut file_data: Result<String, std::io::Error> = Ok("".to_string());

    if source_file.exists() {
        file_data = std::fs::read_to_string(source_file);
        if file_data.is_err() {
            println!(
                "Could not read source file {}",
                source_file.to_str().unwrap(),
            );
            std::process::exit(1);
        }
    }

    if !drop_privs(&ro) {
        std::process::exit(1);
    }

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    options.custom_flags(libc::O_NOFOLLOW);
    let file = options.open(tmp_edit_file_path);

    if file.is_err() {
        println!("Could not create {}", tmp_edit_file_path.to_str().unwrap());
        std::process::exit(1);
    }

    if fchown(
        file.as_ref().unwrap().as_raw_fd(),
        Some(ro.original_uid),
        Some(ro.original_gid),
    )
    .is_err()
    {
        println!("Could not chown {}", tmp_edit_file_path.to_str().unwrap());
    }

    if fchmod(
        file.as_ref().unwrap().as_raw_fd(),
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    )
    .is_err()
    {
        println!("Could not chmod {}", tmp_edit_file_path.to_str().unwrap());
        std::process::exit(1);
    }

    if file_data.is_ok()
        && file
            .unwrap()
            .write(file_data.as_ref().unwrap().as_bytes())
            .is_err()
    {
        println!("Could not write data to {}", &tmp_edit_file);
        std::process::exit(1);
    }

    tmp_edit_file
}

/// return the exitcmd string with %{OLD} and %{NEW} replaced
fn build_exitcmd(entry: &EnvOptions, source_file: &str, edit_file: &str) -> Command {
    let cmd_re = Regex::new(r"\s+").unwrap();

    let cmd_str = &entry.exitcmd.as_ref().unwrap();
    let cmd_parts: Vec<&str> = cmd_re.split(&cmd_str).collect();

    if cmd_parts.is_empty() {
        println!("exitcmd has too few arguments");
        std::process::exit(1);
    }

    let mut cmd = Command::new(cmd_parts[0]);
    for (pos, j) in cmd_parts.iter().enumerate() {
        if pos > 0 {
            cmd.arg(
                j.replace("%{OLD}", &source_file)
                    .replace("%{NEW}", edit_file),
            );
        }
    }
    cmd.stdin(Stdio::inherit());
    cmd.stdout(Stdio::inherit());
    cmd.stderr(Stdio::inherit());

    cmd
}

/// create options for parsing and --help
fn general_options(mut ro: &mut RunOptions, args: Vec<String>, service: &str) {
    let mut opts = Options::new();
    opts.parsing_style(getopts::ParsingStyle::StopAtFirstFree);
    opts.optflag("h", "help", "print usage help");
    opts.optflag("n", "noprompt", "do nothing if a password is required");
    opts.optflag("p", "purge", "purge access token");
    opts.optopt("r", "reason", "provide reason for edit", "REASON");
    opts.optopt("t", "target", "edit as target user", "USER");
    opts.optopt("u", "user", "edit as target user", "USER");
    opts.optflag("v", "version", "print version and exit");
    opts.optflag("w", "warm", "warm access token and exit");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => {
            println!("{}", f.to_string());
            std::process::exit(1);
        }
    };

    let header = format!("{} [arguments] </path/to/file>", &service);
    common_opt_arguments(&matches, &opts, &mut ro, &service, &header);

    if (ro.new_args.is_empty() || ro.new_args.len() > 1) && !ro.warm_token && !ro.purge_token {
        println!("You must provide one file to edit");
        print_usage(&opts, &header);
        print_version(&service);
        std::process::exit(1);
    }
}

fn write_target_tmp_file(
    dir_parent_tmp: &str,
    file_data: &Result<String, std::io::Error>,
    target_uid: nix::unistd::Uid,
    target_gid: nix::unistd::Gid,
) -> std::fs::File {
    if !esc_privs() {
        std::process::exit(1);
    }
    if !set_eprivs(target_uid, target_gid) {
        std::process::exit(1);
    }

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    options.custom_flags(libc::O_NOFOLLOW);

    let file = options.open(dir_parent_tmp);
    if file.is_err()
        || file
            .as_ref()
            .unwrap()
            .write(&file_data.as_ref().unwrap().as_bytes())
            .is_err()
    {
        println!("Could not write data to {}", &dir_parent_tmp);
        std::process::exit(1);
    }
    file.unwrap()
}

fn remove_tmp_edit(ro: &RunOptions, edit_file: &str) {
    if !drop_privs(&ro) {
        std::process::exit(1);
    }
    if std::fs::remove_file(edit_file).is_err() {
        println!("Could not remove {}", edit_file);
        std::process::exit(1);
    }
}

/// rename the edit in the source directory, return false if exitcmd failed
fn rename_to_source(
    dir_parent_tmp: &str,
    source_file: &Path,
    entry: &EnvOptions,
    lookup_name: &User,
    dir_parent_tmp_file: &std::fs::File,
    target_uid: nix::unistd::Uid,
    target_gid: nix::unistd::Gid,
) -> bool {
    if !esc_privs() {
        std::process::exit(1);
    }

    if !set_eprivs(target_uid, target_gid) {
        std::process::exit(1);
    }

    fchown(
        dir_parent_tmp_file.as_raw_fd(),
        Some(nix::unistd::Uid::from_raw(lookup_name.uid())),
        Some(nix::unistd::Gid::from_raw(lookup_name.primary_group_id())),
    )
    .unwrap();

    let edit_mode = if entry.edit_mode.is_some() {
        match entry.edit_mode.as_ref().unwrap() {
            EditMode::Mode(x) => nix::sys::stat::Mode::from_bits(*x as u32).unwrap(),
            EditMode::Keep(_x) => match nix::sys::stat::stat(source_file) {
                Ok(m) => nix::sys::stat::Mode::from_bits_truncate(m.st_mode),
                _ => nix::sys::stat::Mode::from_bits(0o600).unwrap(),
            },
        }
    } else {
        nix::sys::stat::Mode::from_bits(0o600).unwrap()
    };

    fchmod(dir_parent_tmp_file.as_raw_fd(), edit_mode).unwrap();

    if entry.exitcmd.is_some() {
        let mut cmd = build_exitcmd(&entry, &source_file.to_str().unwrap(), &dir_parent_tmp);
        match cmd.output() {
            Err(x) => {
                println!("Aborting as exitcmd was non-zero when executing, removing tmp file:");
                println!("{}", x);
                if nix::unistd::unlink(dir_parent_tmp).is_err() {
                    println!("Could not remove tmp file either, giving up");
                }
                std::process::exit(1);
            }
            Ok(out) => {
                io::stdout().write_all(&out.stdout).unwrap();
                io::stderr().write_all(&out.stderr).unwrap();
                if !out.status.success() {
                    println!("Aborting as exitcmd was non-zero, removing tmp file");
                    if nix::unistd::unlink(dir_parent_tmp).is_err() {
                        println!("Could not remove tmp file either, giving up");
                    }
                    std::process::exit(1);
                }
            }
        }
    }

    if std::fs::rename(&dir_parent_tmp, source_file).is_err() {
        println!(
            "Could not rename {} to {}",
            &dir_parent_tmp,
            source_file.to_str().unwrap()
        );
        std::process::exit(1);
    }
    true
}

/// read edit file into memory or exit 1
fn edit_file_to_memory(source_file: &Path, edit_file: &str) -> Result<String, std::io::Error> {
    let file_data = std::fs::read_to_string(edit_file);
    if file_data.is_err() {
        println!(
            "Could not read {}: {}",
            source_file.to_str().unwrap(),
            file_data.err().unwrap()
        );
        std::process::exit(1);
    }
    file_data
}

extern "C" fn handle_sigtstp(
    child: libc::c_int,
    info: *mut libc::siginfo_t,
    _th: *mut libc::c_void,
) {
    let signal = Signal::try_from(child).unwrap();
    unsafe {
        // don't have a handy definition for "5" SI_MESGQ
        if signal == Signal::SIGCHLD && (*info).si_code == 5 {
            signal::kill(
                nix::unistd::Pid::from_raw(std::process::id() as i32),
                Signal::SIGTSTP,
            )
            .unwrap();
        }
    }
}

/// entry point
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let original_command = args.clone();
    let service = String::from("pleaseedit");
    let mut ro = RunOptions::new();
    let original_uid = get_current_uid();
    let original_user = get_user_by_uid(original_uid).unwrap();
    ro.name = original_user.name().to_string_lossy().to_string();
    ro.acl_type = Acltype::Edit;
    ro.syslog = true;
    let mut vec_eo: Vec<EnvOptions> = vec![];

    let root_uid = nix::unistd::Uid::from_raw(0);
    let root_gid = nix::unistd::Gid::from_raw(0);

    clean_environment(&mut ro);

    if !set_privs("root", root_uid, root_gid) {
        std::process::exit(1);
    }

    if !drop_privs(&ro) {
        std::process::exit(1);
    }

    general_options(&mut ro, args, &service);
    if ro.target.is_empty() {
        ro.target = "root".to_string();
    }
    ro.command = ro.new_args.join(" ");

    ro.groups = group_hash(original_user.groups().unwrap());
    if !esc_privs() {
        std::process::exit(1);
    }
    let mut bytes = 0;
    let mut ini_list: HashMap<String, bool> = HashMap::new();
    if read_ini_config_file(
        "/etc/please.ini",
        &mut vec_eo,
        &ro,
        true,
        &mut bytes,
        &mut ini_list,
    ) {
        println!("Exiting due to error, cannot fully process /etc/please.ini");
        std::process::exit(1);
    }

    if !drop_privs(&ro) {
        std::process::exit(1);
    }

    let entry = can(&vec_eo, &ro);

    ro.syslog = entry.syslog;
    if !entry.permit {
        log_action(&service, "deny", &ro, &original_command.join(" "));
        println!(
            "You may not edit \"{}\" on {} as {}",
            &ro.command, &ro.hostname, &ro.target
        );
        std::process::exit(1);
    }

    // check if a reason was given
    if !reason_ok(&entry, &ro, &service) {
        log_action(&service, "no_reason", &ro, &original_command.join(" "));
        std::process::exit(1);
    }

    if !challenge_password(&ro, &entry, &service) {
        log_action(&service, "deny", &ro, &original_command.join(" "));
        std::process::exit(1);
    }

    let lookup_name = get_user_by_name(&ro.target);
    if lookup_name.is_none() {
        println!("Could not lookup {}", &ro.target);
        std::process::exit(1);
    }
    let lookup_name = lookup_name.unwrap();

    let target_uid = nix::unistd::Uid::from_raw(lookup_name.uid());
    let target_gid = nix::unistd::Gid::from_raw(lookup_name.primary_group_id());

    let source_file = Path::new(&ro.new_args[0]);

    if !drop_privs(&ro) {
        std::process::exit(1);
    }

    set_environment(&ro, &entry, &original_user, original_uid, &lookup_name);
    let edit_file = &setup_temp_edit_file(&service, source_file, &ro, target_uid, target_gid);

    std::env::set_var("PLEASE_EDIT_FILE", edit_file.to_string());
    std::env::set_var("PLEASE_SOURCE_FILE", source_file.to_str().unwrap());

    let mut good_edit = false;

    let sig_action = signal::SigAction::new(
        signal::SigHandler::SigAction(handle_sigtstp),
        signal::SaFlags::SA_RESTART,
        signal::SigSet::all(),
    );

    match unsafe { fork() } {
        Ok(ForkResult::Parent { .. }) => {
            unsafe {
                signal::sigaction(signal::SIGCHLD, &sig_action).unwrap();
            };

            match nix::sys::wait::wait() {
                Ok(Exited(_pid, ret)) if ret == 0 => {
                    good_edit = true;
                }
                Ok(_) => {}
                Err(_x) => {}
            }
            unsafe {
                signal::signal(signal::SIGCHLD, signal::SigHandler::SigDfl).unwrap();
            };
        }
        Ok(ForkResult::Child) => {
            if !esc_privs() {
                std::process::exit(1);
            }
            if !set_privs(&ro.name, ro.original_uid, ro.original_gid) {
                std::process::exit(1);
            }

            let editor = get_editor();

            nix::sys::stat::umask(ro.old_umask.unwrap());

            if ro.old_envs.is_some() {
                for (key, _) in std::env::vars() {
                    std::env::remove_var(key);
                }
                for (key, val) in ro.old_envs.as_ref().unwrap().iter() {
                    std::env::set_var(key, val);
                }
            }

            let args: Vec<&str> = editor.as_str().split(' ').collect();
            if args.len() == 1 {
                Command::new(editor.as_str()).arg(&edit_file).exec();
            } else {
                Command::new(&args[0])
                    .args(&args[1..])
                    .arg(&edit_file)
                    .exec();
            }
            println!("Could not execute {}", editor.as_str());
            std::process::exit(1);
        }
        Err(_) => println!("Fork failed"),
    }

    if !good_edit {
        println!("Exiting as editor or child did not close cleanly.");
        std::process::exit(1);
    }

    // drop privs to original user and read into memory
    log_action(&service, "permit", &ro, &original_command.join(" "));
    let dir_parent_tmp =
        source_tmp_file_name(&source_file, format!("{}.copy", service).as_str(), &ro.name);

    let file_data = edit_file_to_memory(&source_file, &edit_file);

    // become the target user and create file
    let dir_parent_tmp_file =
        write_target_tmp_file(&dir_parent_tmp, &file_data, target_uid, target_gid);

    // original user, remove tmp edit file
    remove_tmp_edit(&ro, edit_file);

    // rename file to source if exitcmd is clean
    rename_to_source(
        &dir_parent_tmp,
        &source_file,
        &entry,
        &lookup_name,
        &dir_parent_tmp_file,
        target_uid,
        target_gid,
    );
}
