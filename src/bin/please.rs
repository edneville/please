//    please
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

//! please.rs a sudo-like clone that implements regex all over the place

use pleaser::util::{
    can, challenge_password, group_hash, list, log_action, read_ini_config_file, remove_token,
    search_path, EnvOptions, RunOptions, ACLTYPE,
};

use std::os::unix::process::CommandExt;
use std::process::Command;

use getopts::Options;

use nix::unistd::{gethostname, setgid, setgroups, setuid};

use users::os::unix::UserExt;
use users::*;

fn print_usage(program: &str) {
    println!("usage:");
    println!("{} [arguments] <path/to/executable>", program);
    println!(" -c, --check, [file]: check config file");
    println!(" -d, --dir, [dir]: change to dir before execution");
    println!(" -l, --list, <-t users permissions> <-v>: list permissions");
    println!(" -n, --noprompt: rather than prompt for password, exit non-zero");
    println!(" -p, --purge: purge valid tokens");
    println!(" -r, --reason, [text]: provide reason for execution");
    println!(" -t, --target, [user]: become target user");
    println!(" -w, --warm: warm token cache");
    println!("version: {}", env!("CARGO_PKG_VERSION"));
}

fn do_list(ro: &mut RunOptions, vec_eo: &[EnvOptions], service: &str) {
    let name = if ro.target != "" { &ro.target } else { "You" };

    let can_do = can(&vec_eo, &ro);
    if can_do.is_ok() && can_do.unwrap().permit {
        println!("{} may run the following:", name);
        ro.acl_type = ACLTYPE::RUN;
        list(&vec_eo, &ro);
        println!("{} may edit the following:", name);
        ro.acl_type = ACLTYPE::EDIT;
        list(&vec_eo, &ro);
        println!("{} may list the following:", name);
        ro.acl_type = ACLTYPE::LIST;
        list(&vec_eo, &ro);
    } else {
        let dest = format!("{}'s", &ro.target);
        log_action(
            &service,
            "deny",
            &ro.name,
            &ro.target,
            &ro.reason,
            &ro.command,
        );
        println!(
            "You may not view {} command list",
            if ro.target == "" { "your" } else { &dest }
        );
    }
}

fn do_dir_changes(ro: &RunOptions) {
    if ro.directory != "" {
        if let Err(x) = std::env::set_current_dir(&ro.directory) {
            println!("Cannot cd into {}: {}", &ro.directory, x);
            std::process::exit(1);
        }
    }
}

fn do_environment(
    ro: &mut RunOptions,
    original_user: &User,
    original_uid: u32,
    lookup_name: &User,
) {
    for (key, _) in std::env::vars() {
        if key == "LANGUAGE"
            || key == "XAUTHORITY"
            || key == "LANG"
            || key == "LS_COLORS"
            || key == "TERM"
            || key == "DISPLAY"
            || key == "LOGNAME"
        {
            continue;
        }
        std::env::remove_var(key);
    }

    std::env::set_var("PLEASE_USER", original_user.name());
    std::env::set_var("PLEASE_UID", original_uid.to_string());
    std::env::set_var("PLEASE_GID", original_user.primary_group_id().to_string());
    std::env::set_var("PLEASE_COMMAND", &ro.command);

    std::env::set_var("SUDO_USER", original_user.name());
    std::env::set_var("SUDO_UID", original_uid.to_string());
    std::env::set_var("SUDO_GID", original_user.primary_group_id().to_string());
    std::env::set_var("SUDO_COMMAND", &ro.command);

    std::env::set_var(
        "PATH",
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
    );
    std::env::set_var("HOME", lookup_name.home_dir().as_os_str());
    std::env::set_var("MAIL", format!("/var/mail/{}", ro.target));
    std::env::set_var("SHELL", lookup_name.shell());
    std::env::set_var("USER", &ro.target);
    std::env::set_var("LOGNAME", &ro.target);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let original_command = args.clone();
    let program = args[0].clone();
    let service = String::from("please");
    let mut ro = RunOptions::new();
    let mut prompt = true;
    let mut purge_token = false;
    let mut warm_token = false;
    let original_uid = get_current_uid();
    let original_user = get_user_by_uid(original_uid).unwrap();
    ro.name = original_user.name().to_string_lossy().to_string();
    let mut vec_eo: Vec<EnvOptions> = vec![];

    let mut opts = Options::new();
    opts.parsing_style(getopts::ParsingStyle::StopAtFirstFree);
    opts.optopt("c", "check", "check config file", "CHECK");
    opts.optopt("d", "dir", "change to directory prior to execution", "DIR");
    opts.optflag("h", "help", "print usage help");
    opts.optflag("l", "list", "list effective rules");
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

    if matches.opt_present("c") {
        std::process::exit(read_ini_config_file(
            &matches.opt_str("c").unwrap(),
            &mut vec_eo,
            &ro.name,
            true,
        ) as i32);
    }

    if matches.opt_present("d") {
        ro.directory = matches.opt_str("d").unwrap();
    }
    if matches.opt_present("l") {
        ro.acl_type = ACLTYPE::LIST;
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

    let mut new_args = matches.free;

    ro.groups = group_hash(original_user.groups().unwrap());

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

    if ro.acl_type == ACLTYPE::LIST {
        do_list(&mut ro, &vec_eo, &service);
        return;
    }

    if ro.target == "" {
        ro.target = "root".to_string();
    }

    if new_args.is_empty() {
        println!("No command given.");
        std::process::exit(1);
    }

    match search_path(&new_args[0]) {
        None => {
            println!("[{}]: command not found", service);
            std::process::exit(1);
        }
        Some(x) => {
            new_args[0] = x;
        }
    }

    ro.command = new_args.join(" ");
    let entry = can(&vec_eo, &ro);

    match &entry {
        Err(_) => {
            log_action(
                &service,
                "deny",
                &ro.name,
                &ro.target,
                &ro.reason,
                &original_command.join(" "),
            );
            println!(
                "You may not execute \"{}\" on {} as {}",
                &ro.command, &ro.hostname, &ro.target
            );
            std::process::exit(1);
        }
        Ok(x) => {
            if !x.permit {
                log_action(
                    &service,
                    "deny",
                    &ro.name,
                    &ro.target,
                    &ro.reason,
                    &original_command.join(" "),
                );
                println!(
                    "You may not execute \"{}\" on {} as {}",
                    &ro.command, &ro.hostname, &ro.target
                );
                std::process::exit(1);
            }
            // check if a reason was given
            if x.permit && x.reason && ro.reason.is_none() {
                log_action(
                    &service,
                    "no_reason",
                    &ro.name,
                    &ro.target,
                    &ro.reason,
                    &original_command.join(" "),
                );
                println!(
                    "Sorry but no reason was given to execute \"{}\" on {} as {}",
                    &ro.command, &ro.hostname, &ro.target
                );
                std::process::exit(1);
            }
        }
    }

    if !challenge_password(ro.name.to_string(), entry.unwrap(), &service, prompt) {
        log_action(
            &service,
            "deny",
            &ro.name,
            &ro.target,
            &ro.reason,
            &original_command.join(" "),
        );
        println!("Keyboard not present or not functioning, press F1 to continue.");
        std::process::exit(1);
    }

    do_dir_changes(&ro);

    log_action(
        &service,
        "permit",
        &ro.name,
        &ro.target,
        &ro.reason,
        &original_command.join(" "),
    );
    let lookup_name = get_user_by_name(&ro.target).unwrap();
    let target_uid = nix::unistd::Uid::from_raw(lookup_name.uid());
    let target_gid = nix::unistd::Gid::from_raw(lookup_name.primary_group_id());

    do_environment(&mut ro, &original_user, original_uid, &lookup_name);

    let mut groups: Vec<nix::unistd::Gid> = vec![];
    for x in lookup_name.groups().unwrap() {
        groups.push(nix::unistd::Gid::from_raw(x.gid()));
    }

    if !groups.is_empty() {
        match setgroups(groups.as_slice()) {
            Ok(_) => {}
            Err(err) => println!("Error setting groups: {}", err),
        }
    }

    setgid(target_gid).unwrap();
    setuid(target_uid).unwrap();

    if new_args.len() > 1 {
        Command::new(&new_args[0])
            .args(new_args.clone().split_off(1))
            .exec();
        Command::new(&"/bin/sh").args(new_args).exec();
    } else {
        Command::new(&new_args[0]).exec();
        Command::new("/bin/sh").args(new_args).exec();
    }
}

#[cfg(test)]
mod test {}
