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

use pleaser::util::*;

use std::fs::*;
use std::io::{self, Write};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};

use regex::Regex;

use getopts::Options;

use nix::sys::stat::fchmodat;
use nix::sys::wait::WaitStatus::Exited;
use nix::unistd::{chown, fork, gethostname, ForkResult};

use users::*;

fn tmp_edit_file_name(source_file: &Path, service: &str, original_user: &str) -> String {
    format!(
        "/tmp/{}.{}.{}",
        service,
        original_user,
        source_file.to_str().unwrap().replace('/', "_"),
    )
}

fn source_tmp_file_name(source_file: &Path, service: &str, original_user: &str) -> String {
    format!(
        "{}.{}.{}",
        source_file.to_str().unwrap(),
        service,
        original_user,
    )
}

fn setup_temp_edit_file(
    service: &str,
    source_file: &Path,
    original_uid: u32,
    original_gid: u32,
    original_user: &str,
) -> String {
    let tmp_edit_file = tmp_edit_file_name(&source_file, &service, &original_user);
    let tmp_edit_file_path = Path::new(&tmp_edit_file);

    if tmp_edit_file_path.exists() && std::fs::remove_file(tmp_edit_file_path).is_err() {
        println!("Could not remove {}", tmp_edit_file_path.to_str().unwrap());
        std::process::exit(1);
    }

    if source_file.exists() {
        if std::fs::copy(source_file, tmp_edit_file_path).is_err() {
            println!(
                "Could not copy {} to {}",
                source_file.to_str().unwrap(),
                tmp_edit_file_path.to_str().unwrap()
            );
            std::process::exit(1);
        }
    } else if File::create(tmp_edit_file_path).is_err() {
        println!("Could not create {}", tmp_edit_file_path.to_str().unwrap());
        std::process::exit(1);
    }

    if chown(
        tmp_edit_file_path,
        Some(nix::unistd::Uid::from_raw(original_uid)),
        Some(nix::unistd::Gid::from_raw(original_gid)),
    )
    .is_err()
    {
        println!("Could not chown {}", tmp_edit_file_path.to_str().unwrap());
        std::process::exit(1);
    }

    if fchmodat(
        None,
        tmp_edit_file_path,
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        nix::sys::stat::FchmodatFlags::FollowSymlink,
    )
    .is_err()
    {
        println!("Could not chmod {}", tmp_edit_file_path.to_str().unwrap());
        std::process::exit(1);
    }

    tmp_edit_file
}

fn build_exitcmd(entry: &EnvOptions, source_file: &str, edit_file: &str) -> Command {
    let cmd_re = Regex::new(r"\s+").unwrap();

    let cmd_str = entry.exitcmd.clone().unwrap();
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

    ro.new_args = matches.free;

    if (ro.new_args.is_empty() || ro.new_args.len() > 1) && !ro.warm_token && !ro.purge_token {
        println!("You must provide one file to edit");
        print_usage(&opts, &header);
        print_version(&service);
        std::process::exit(1);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let original_command = args.clone();
    let service = String::from("pleaseedit");
    let mut ro = RunOptions::new();
    let original_uid = get_current_uid();
    let original_user = get_user_by_uid(original_uid).unwrap();
    let original_gid = original_user.primary_group_id();
    ro.name = original_user.name().to_string_lossy().to_string();
    ro.acl_type = ACLTYPE::EDIT;
    ro.syslog = true;
    let mut vec_eo: Vec<EnvOptions> = vec![];

    if !set_privs(
        "root",
        nix::unistd::Uid::from_raw(0),
        nix::unistd::Gid::from_raw(0),
    ) {
        println!("I cannot set privs. Exiting as not installed correctly.");
        std::process::exit(1);
    }

    general_options(&mut ro, args, &service);
    if ro.target == "" {
        ro.target = "root".to_string();
    }
    ro.command = ro.new_args.join(" ");

    ro.groups = group_hash(original_user.groups().unwrap());

    if read_ini_config_file("/etc/please.ini", &mut vec_eo, &ro.name, true) {
        println!("Exiting due to error, cannot fully process /etc/please.ini");
        std::process::exit(1);
    }

    let mut buf = [0u8; 64];
    ro.hostname = gethostname(&mut buf)
        .expect("Failed getting hostname")
        .to_str()
        .expect("Hostname wasn't valid UTF-8")
        .to_string();
    let entry = can(&vec_eo, &ro);

    match &entry {
        Err(_) => {
            log_action(&service, "deny", &ro, &original_command.join(" "));
            println!(
                "You may not edit \"{}\" on {} as {}",
                &ro.command, &ro.hostname, &ro.target
            );
            std::process::exit(1);
        }
        Ok(x) => {
            ro.syslog = x.syslog;
            if !x.permit {
                log_action(&service, "deny", &ro, &original_command.join(" "));
                println!(
                    "You may not edit \"{}\" on {} as {}",
                    &ro.command, &ro.hostname, &ro.target
                );
                std::process::exit(1);
            }
            // check if a reason was given
            if x.permit && x.reason && ro.reason.is_none() {
                log_action(&service, "no_reason", &ro, &original_command.join(" "));
                println!(
                    "Sorry but no reason was given to edit \"{}\" on {} as {}",
                    &ro.command, &ro.hostname, &ro.target
                );
                std::process::exit(1);
            }
        }
    }

    if std::fs::read_link(&ro.command).is_ok() {
        println!("You may not edit \"{}\" as it links elsewhere", &ro.command);
        std::process::exit(1);
    }

    if !challenge_password(&ro.name, entry.clone().unwrap(), &service, ro.prompt) {
        log_action(&service, "deny", &ro, &original_command.join(" "));
        std::process::exit(1);
    }

    let lookup_name = get_user_by_name(&ro.target);
    if lookup_name.is_none() {
        println!("Could not lookup {}", &ro.target);
        std::process::exit(1);
    }
    let lookup_name = lookup_name.unwrap();

    let source_file = Path::new(&ro.new_args[0]);

    let edit_file =
        &setup_temp_edit_file(&service, source_file, original_uid, original_gid, &ro.name);

    std::env::set_var("PLEASE_USER", original_user.name());
    std::env::set_var("PLEASE_UID", original_uid.to_string());
    std::env::set_var("PLEASE_GID", original_uid.to_string());
    std::env::set_var("PLEASE_EDIT_FILE", edit_file.to_string());
    std::env::set_var("PLEASE_SOURCE_FILE", source_file.to_str().unwrap());
    std::env::set_var("SUDO_USER", original_user.name());
    std::env::set_var("SUDO_UID", original_uid.to_string());
    std::env::set_var("SUDO_GID", original_user.primary_group_id().to_string());

    let mut good_edit = false;
    match unsafe { fork() } {
        Ok(ForkResult::Parent { .. }) => match nix::sys::wait::wait() {
            Ok(Exited(_pid, ret)) if ret == 0 => {
                good_edit = true;
            }
            Ok(_) => {}
            Err(_x) => {}
        },
        Ok(ForkResult::Child) => {
            // drop privileges and execute editor
            let editor = get_editor();

            if !set_privs(
                &ro.name,
                nix::unistd::Uid::from_raw(original_uid),
                nix::unistd::Gid::from_raw(original_gid),
            ) {
                println!("I cannot set privs. Exiting as not installed correctly.");
                std::process::exit(1);
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

    log_action(&service, "permit", &ro, &original_command.join(" "));

    let dir_parent_tmp =
        source_tmp_file_name(&source_file, format!("{}.copy", service).as_str(), &ro.name);
    if let Err(x) = std::fs::copy(edit_file, dir_parent_tmp.as_str()) {
        println!(
            "Could not copy {} to {}: {}",
            edit_file,
            dir_parent_tmp.as_str(),
            x
        );
        std::process::exit(1);
    }

    if std::fs::remove_file(edit_file).is_err() {
        println!("Could not remove {}", edit_file);
        std::process::exit(1);
    }

    chown(
        dir_parent_tmp.as_str(),
        Some(nix::unistd::Uid::from_raw(lookup_name.uid())),
        Some(nix::unistd::Gid::from_raw(lookup_name.primary_group_id())),
    )
    .unwrap();

    fchmodat(
        None,
        dir_parent_tmp.as_str(),
        if entry.clone().unwrap().edit_mode.is_some() {
            nix::sys::stat::Mode::from_bits(entry.clone().unwrap().edit_mode.unwrap() as u32)
                .unwrap()
        } else {
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR
        },
        nix::sys::stat::FchmodatFlags::FollowSymlink,
    )
    .unwrap();

    if entry.clone().unwrap().exitcmd.is_some() {
        let mut cmd = build_exitcmd(
            &entry.unwrap(),
            &source_file.to_str().unwrap(),
            &dir_parent_tmp.as_str(),
        );
        let out = cmd.output().expect("could not execute");
        io::stdout().write_all(&out.clone().stdout).unwrap();
        io::stderr().write_all(&out.clone().stderr).unwrap();
        if !out.status.success() {
            println!("Aborting as exitcmd was non-zero");
            std::process::exit(out.status.code().unwrap());
        }
    }

    if std::fs::rename(&dir_parent_tmp.as_str(), source_file).is_err() {
        println!(
            "Could not rename {} to {}",
            &dir_parent_tmp.as_str(),
            source_file.to_str().unwrap()
        );
        std::process::exit(1);
    }
}

#[cfg(test)]
mod test {}
