//    pleaseedit
//    Copyright (C) 2020  ed neville
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

use pleaser::util::{
    can, challenge_password, get_editor, log_action, read_ini_config_file, remove_token, set_privs,
    EnvOptions, RunOptions, ACLTYPE,
};

use std::fs::*;
use std::io::{self, Write};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

use regex::Regex;

use getopts::Options;

use nix::sys::stat::fchmodat;
use nix::sys::wait::WaitStatus::Exited;
use nix::unistd::{chown, fork, gethostname, ForkResult};

use users::*;

fn print_usage(program: &str) {
    println!("usage:");
    println!("{} /path/to/file", program);
    println!(" -n, --noprompt: rather than prompt for password, exit non-zero");
    println!(" -p, --purge: purge valid tokens");
    println!(" -r, --reason, [text]: provide reason for execution");
    println!(" -t, --target, [user]: edit as target user");
    println!(" -w, --warm: warm token cache");
    println!("version: {}", env!("CARGO_PKG_VERSION"));
}

fn setup_temp_edit_file(
    service: &str,
    source_file: &Path,
    original_uid: u32,
    original_gid: u32,
    original_user: &str,
) -> String {
    let tmp_edit_file = format!(
        "/tmp/{}.{}.{}",
        source_file.file_name().unwrap().to_str().unwrap(),
        service,
        original_user
    );
    let tmp_edit_file_path = Path::new(&tmp_edit_file);

    if source_file.exists() {
        std::fs::copy(source_file, tmp_edit_file_path).unwrap();
    } else {
        File::create(tmp_edit_file_path).unwrap();
    }

    chown(
        tmp_edit_file_path,
        Some(nix::unistd::Uid::from_raw(original_uid)),
        Some(nix::unistd::Gid::from_raw(original_gid)),
    )
    .unwrap();

    fchmodat(
        None,
        tmp_edit_file_path,
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        nix::sys::stat::FchmodatFlags::FollowSymlink,
    )
    .unwrap();

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

    cmd
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let original_command = args.clone();
    let program = args[0].clone();
    let service = String::from("pleaseedit");
    let mut ro = RunOptions::new();
    let mut prompt = true;
    let mut purge_token = false;
    let mut warm_token = false;
    let original_uid = get_current_uid();
    let original_user = get_user_by_uid(original_uid).unwrap();
    let original_gid = original_user.primary_group_id();
    ro.name = original_user.name().to_string_lossy().to_string();
    ro.acl_type = ACLTYPE::EDIT;
    ro.syslog = true;
    let mut vec_eo: Vec<EnvOptions> = vec![];

    set_privs(
        "root",
        nix::unistd::Uid::from_raw(0),
        nix::unistd::Gid::from_raw(0),
    );

    let mut opts = Options::new();
    opts.parsing_style(getopts::ParsingStyle::StopAtFirstFree);
    opts.optflag("h", "help", "print usage help");
    opts.optflag("n", "noprompt", "do nothing if a password is required");
    opts.optflag("p", "purge", "purge access token");
    opts.optopt("r", "reason", "reason for execution", "REASON");
    opts.optopt("t", "target", "edit as target user", "TARGET");
    opts.optflag("w", "warm", "warm access token and exit");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => panic!(f.to_string()),
    };
    if matches.opt_present("h") {
        print_usage(&program);
        return;
    }
    if matches.opt_present("r") {
        ro.reason = Some(matches.opt_str("r").unwrap());
    }
    if matches.opt_present("t") {
        ro.target = matches.opt_str("t").unwrap();
    }
    if matches.opt_present("p") {
        purge_token = true;
    }
    if matches.opt_present("w") {
        warm_token = true;
    }

    if matches.opt_present("n") {
        prompt = false;
    }

    let new_args = matches.free;
    ro.command = new_args.join(" ");

    if purge_token {
        remove_token(&ro.name);
        return;
    }

    if warm_token {
        if prompt {
            challenge_password(ro.name, EnvOptions::new(), &service, prompt);
        }
        return;
    }

    if ro.target == "" {
        ro.target = "root".to_string();
    }

    if new_args.is_empty() || new_args.len() > 1 {
        print_usage(&program);
        return;
    }

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

    if !challenge_password(
        ro.name.to_string(),
        entry.clone().unwrap(),
        &service,
        prompt,
    ) {
        log_action(&service, "deny", &ro, &original_command.join(" "));
        std::process::exit(1);
    }

    let lookup_name = users::get_user_by_name(&ro.target).unwrap();
    let source_file = Path::new(&new_args[0]);

    let edit_file =
        &setup_temp_edit_file(&service, source_file, original_uid, original_gid, &ro.name);

    std::env::set_var("PLEASE_USER", original_user.name());
    std::env::set_var("PLEASE_UID", original_uid.to_string());
    std::env::set_var("PLEASE_EDIT_FILE", edit_file.to_string());
    std::env::set_var("PLEASE_SOURCE_FILE", source_file.to_str().unwrap());

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

            set_privs(
                &ro.name,
                nix::unistd::Uid::from_raw(original_uid),
                nix::unistd::Gid::from_raw(original_gid),
            );

            Command::new(editor.as_str()).arg(&edit_file).exec();
            std::process::exit(1);
        }
        Err(_) => println!("Fork failed"),
    }

    if !good_edit {
        println!("Exiting as editor or child did not close cleanly.");
        std::process::exit(1);
    }

    log_action(&service, "permit", &ro, &original_command.join(" "));

    if entry.clone().unwrap().exitcmd.is_some() {
        let mut cmd = build_exitcmd(
            &entry.clone().unwrap(),
            &source_file.to_str().unwrap(),
            &edit_file,
        );
        let out = cmd.output().expect("could not execute");
        io::stdout().write_all(&out.clone().stdout).unwrap();
        io::stderr().write_all(&out.clone().stderr).unwrap();
        if !out.status.success() {
            println!("Aborting as exitcmd was non-zero");
            std::process::exit(out.status.code().unwrap());
        }
    }

    let dir_parent_tmp = format!("{}.{}.{}", source_file.to_str().unwrap(), service, ro.name);
    std::fs::copy(edit_file, dir_parent_tmp.as_str()).unwrap();

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
            nix::sys::stat::Mode::from_bits(entry.unwrap().edit_mode.unwrap() as u32).unwrap()
        } else {
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR
        },
        nix::sys::stat::FchmodatFlags::FollowSymlink,
    )
    .unwrap();

    std::fs::rename(&dir_parent_tmp.as_str(), source_file).unwrap();
}

#[cfg(test)]
mod test {}
