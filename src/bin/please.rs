//    please
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

use std::os::unix::process::CommandExt;
use std::process::Command;

use getopts::Options;

use nix::unistd::gethostname;

use users::os::unix::UserExt;
use users::*;

fn do_list(ro: &mut RunOptions, vec_eo: &[EnvOptions], service: &str) {
    let name = if ro.target == ro.name || ro.target == "" {
        "You"
    } else {
        &ro.target
    };

    let can_do = can(&vec_eo, &ro);

    if let Ok(can_do) = can_do {
        if !can_do.permit {
            let dest = format!("{}'s", &ro.target);
            log_action(&service, "deny", &ro, &ro.command);
            println!(
                "You may not view {} command list",
                if ro.target == "" || ro.target == ro.name {
                    "your"
                } else {
                    &dest
                }
            );
            std::process::exit(1);
        }

        // check if a reason was given
        if can_do.reason && ro.reason.is_none() {
            log_action(&service, "no_reason", &ro, &ro.original_command.join(" "));
            println!(
                "Sorry but no reason was given to list on {} as {}",
                &ro.hostname, &ro.target
            );
            std::process::exit(1);
        }

        // check if a password is required
        if !challenge_password(&ro.name, can_do, &service, ro.prompt) {
            log_action(&service, "deny", &ro, &ro.original_command.join(" "));
            std::process::exit(1);
        }

        log_action(&service, "permit", &ro, &ro.command);
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
        log_action(&service, "deny", &ro, &ro.command);
        println!(
            "You may not view {} command list",
            if ro.target == "" || ro.target == ro.name {
                "your"
            } else {
                &dest
            }
        );
        std::process::exit(1);
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

fn general_options(
    mut ro: &mut RunOptions,
    args: Vec<String>,
    service: &str,
    mut vec_eo: &mut Vec<EnvOptions>,
) {
    let mut opts = Options::new();
    opts.parsing_style(getopts::ParsingStyle::StopAtFirstFree);
    opts.optopt("c", "check", "check config file", "FILE");
    opts.optopt("d", "dir", "change to directory prior to execution", "DIR");
    opts.optflag("h", "help", "print usage help");
    opts.optflag("l", "list", "list effective rules, can combine with -t/-u");
    opts.optflag("n", "noprompt", "do nothing if a password is required");
    opts.optflag("p", "purge", "purge access token");
    opts.optopt("r", "reason", "provide reason for execution", "REASON");
    opts.optopt("t", "target", "become target user", "USER");
    opts.optopt("u", "user", "become target user", "USER");
    opts.optflag("v", "version", "print version and exit");
    opts.optflag("w", "warm", "warm access token and exit");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => {
            println!("{}", f.to_string());
            std::process::exit(1);
        }
    };

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

    let header = format!("{} [arguments] </path/to/executable>", &service);
    common_opt_arguments(&matches, &opts, &mut ro, &service, &header);

    ro.new_args = matches.free;

    if ro.new_args.is_empty() && !ro.warm_token && !ro.purge_token && ro.acl_type != ACLTYPE::LIST {
        println!("No command given");
        print_usage(&opts, &header);
        print_version(&service);
        std::process::exit(0);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let original_command = args.clone();
    let service = String::from("please");
    let mut ro = RunOptions::new();
    let original_uid = get_current_uid();
    let original_user = get_user_by_uid(original_uid).unwrap();
    ro.name = original_user.name().to_string_lossy().to_string();
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

    general_options(&mut ro, args, &service, &mut vec_eo);

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

    if ro.acl_type == ACLTYPE::LIST {
        if ro.target == "" {
            ro.target = ro.name.to_string();
        }
        do_list(&mut ro, &vec_eo, &service);
        return;
    }

    if ro.target == "" {
        ro.target = "root".to_string();
    }

    match search_path(&ro.new_args[0]) {
        None => {
            println!("[{}]: command not found", service);
            std::process::exit(1);
        }
        Some(x) => {
            ro.new_args[0] = x;
        }
    }

    ro.command = replace_new_args(ro.new_args.clone());
    let entry = can(&vec_eo, &ro);

    match &entry {
        Err(_) => {
            log_action(&service, "deny", &ro, &original_command.join(" "));
            println!(
                "You may not execute \"{}\" on {} as {}",
                &ro.command, &ro.hostname, &ro.target
            );
            std::process::exit(1);
        }
        Ok(x) => {
            ro.syslog = x.syslog;
            if !x.permit {
                log_action(&service, "deny", &ro, &original_command.join(" "));
                println!(
                    "You may not execute \"{}\" on {} as {}",
                    &ro.command, &ro.hostname, &ro.target
                );
                std::process::exit(1);
            }
            // check if a reason was given
            if x.permit && x.reason && ro.reason.is_none() {
                log_action(&service, "no_reason", &ro, &original_command.join(" "));
                println!(
                    "Sorry but no reason was given to execute \"{}\" on {} as {}",
                    &ro.command, &ro.hostname, &ro.target
                );
                std::process::exit(1);
            }
        }
    }

    if !challenge_password(&ro.name, entry.unwrap(), &service, ro.prompt) {
        log_action(&service, "deny", &ro, &original_command.join(" "));
        std::process::exit(1);
    }

    do_dir_changes(&ro);

    log_action(&service, "permit", &ro, &original_command.join(" "));
    let lookup_name = get_user_by_name(&ro.target);
    if lookup_name.is_none() {
        println!("Could not lookup {}", &ro.target);
        std::process::exit(1);
    }
    let lookup_name = lookup_name.unwrap();
    let target_uid = nix::unistd::Uid::from_raw(lookup_name.uid());
    let target_gid = nix::unistd::Gid::from_raw(lookup_name.primary_group_id());

    do_environment(&mut ro, &original_user, original_uid, &lookup_name);

    if !set_privs(&ro.target.to_string(), target_uid, target_gid) {
        println!("I cannot set privs. Exiting as not installed correctly.");
        std::process::exit(1);
    }

    if ro.new_args.len() > 1 {
        Command::new(&ro.new_args[0])
            .args(ro.new_args.clone().split_off(1))
            .exec();
        Command::new(&"/bin/sh").args(ro.new_args).exec();
    } else {
        Command::new(&ro.new_args[0]).exec();
        Command::new("/bin/sh").args(ro.new_args).exec();
    }
}

#[cfg(test)]
mod test {}
