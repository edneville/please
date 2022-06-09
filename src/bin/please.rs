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

use pleaser::*;

use std::os::unix::process::CommandExt;
use std::process::Command;

use std::collections::HashMap;

use getopts::Options;

use users::*;

/// walk through user ACL
fn do_list(ro: &mut RunOptions, vec_eo: &[EnvOptions], service: &str) {
    let name = if ro.target == ro.name || ro.target.is_empty() {
        "You".to_string()
    } else {
        ro.target.clone()
    };

    let can_do = can(vec_eo, ro);
    ro.env_options = Some(can_do.clone());
    if can_do.syslog.is_some() {
        ro.syslog = can_do.syslog.unwrap();
    }

    if !can_do.permit() {
        let dest = format!("{}'s", &ro.target);
        log_action(service, "deny", ro, &ro.command);
        println!(
            "You may not view {} command list",
            if ro.target.is_empty() || ro.target == ro.name {
                "your"
            } else {
                &dest
            }
        );
        std::process::exit(1);
    }

    // check if a reason was given
    if !reason_ok(&can_do, ro) {
        log_action(service, "reason_fail", ro, &ro.original_command.join(" "));
        std::process::exit(1);
    }

    // check if a password is required
    if !challenge_password(ro, &can_do, service) {
        log_action(service, "deny", ro, &ro.original_command.join(" "));
        std::process::exit(1);
    }

    log_action(service, "permit", ro, &ro.command);
    println!("{} may run the following:", name);
    ro.acl_type = Acltype::Run;
    list(vec_eo, ro);
    println!("{} may edit the following:", name);
    ro.acl_type = Acltype::Edit;
    list(vec_eo, ro);
    println!("{} may list the following:", name);
    ro.acl_type = Acltype::List;
    list(vec_eo, ro);
}

/// navigate to directory or exit 1
fn do_dir_changes(ro: &RunOptions, service: &str) {
    if ro.directory.is_some() {
        if let Err(x) = std::env::set_current_dir(&ro.directory.as_ref().unwrap()) {
            println!(
                "[{}] cannot cd into {}: {}",
                &service,
                &ro.directory.as_ref().unwrap(),
                x
            );
            std::process::exit(1);
        }
    }
}

/// setup getopts for argument parsing and help output
fn general_options(
    mut ro: &mut RunOptions,
    args: Vec<String>,
    service: &str,
    vec_eo: &mut Vec<EnvOptions>,
) {
    let mut opts = Options::new();
    opts.parsing_style(getopts::ParsingStyle::StopAtFirstFree);
    opts.optopt(
        "a",
        "allowenv",
        "allow permitted comma separated envs",
        "LIST",
    );
    opts.optopt("c", "check", "check config file", "FILE");
    opts.optopt("d", "dir", "change to directory prior to execution", "DIR");
    opts.optopt("g", "group", "become target group", "GROUP");
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
            println!("{}", f);
            std::process::exit(1);
        }
    };

    if matches.opt_present("c") {
        let mut bytes = 0;
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        std::process::exit(read_ini_config_file(
            &matches.opt_str("c").unwrap(),
            vec_eo,
            ro,
            true,
            &mut bytes,
            &mut ini_list,
        ) as i32);
    }

    if matches.opt_present("a") {
        let mut vec = vec![];

        for s in matches.opt_str("a").unwrap().split(',') {
            if s.trim() == "" {
                continue;
            }
            vec.push(s.to_string());
        }
        ro.allow_env_list = Some(vec);
    }

    if matches.opt_present("d") {
        ro.directory = Some(matches.opt_str("d").unwrap());
    }
    if matches.opt_present("l") {
        ro.acl_type = Acltype::List;
    }

    let header = format!("{} [arguments] </path/to/executable>", &service);
    common_opt_arguments(&matches, &opts, ro, service, &header);

    if ro.new_args.is_empty() && !ro.warm_token && !ro.purge_token && ro.acl_type != Acltype::List {
        println!("No command given");
        print_usage(&opts, &header);
        print_version(service);
        std::process::exit(0);
    }
}

fn exit_if_command_not_found(ro: &RunOptions, service: &str) {
    if let Some(k) = ro.located_bin.get(&ro.new_args[0]) {
        if k.is_none() {
            println!("[{service}] command not found");
            std::process::exit(1);
        }
    }
}

fn is_command_cd(ro: &RunOptions, service: &str) {
    if ro.cloned_args.is_none() && &ro.new_args[0] == "cd" {
        println!("[{service}] {} is a shell feature.", &ro.new_args[0]);
        if ro.new_args.len() > 1 {
            println!(
                "Try either changing to {} first or using {} -d {} instead.",
                &ro.new_args[1], service, &ro.new_args[1]
            );
        }
        std::process::exit(1);
    }
}

/// main entry point
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let service = String::from("please");
    let mut ro = RunOptions::new();
    let original_uid = get_current_uid();
    let original_user = get_user_by_uid(original_uid).unwrap();
    ro.name = original_user.name().to_string_lossy().to_string();
    ro.syslog = true;
    ro.original_command = args.clone();
    let mut vec_eo: Vec<EnvOptions> = vec![];

    let root_uid = nix::unistd::Uid::from_raw(0);
    let root_gid = nix::unistd::Gid::from_raw(0);

    if !set_privs("root", root_uid, root_gid) {
        std::process::exit(1);
    }

    if !drop_privs(&ro) {
        std::process::exit(1);
    }

    general_options(&mut ro, args, &service, &mut vec_eo);

    clean_environment(&mut ro);

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

    ro.command = replace_new_args(ro.new_args.clone());

    if ro.acl_type == Acltype::List {
        if ro.target.is_empty() {
            ro.target = ro.name.to_string();
        }
        do_list(&mut ro, &vec_eo, &service);
        return;
    }

    if ro.target.is_empty() {
        ro.target = "root".to_string();
    }

    let entry = can(&vec_eo, &mut ro);
    ro.env_options = Some(entry.clone());

    if entry.syslog.is_some() {
        ro.syslog = entry.syslog.unwrap();
    }

    if !entry.permit() {
        log_action(&service, "deny", &ro, &ro.original_command.join(" "));

        is_command_cd(&ro, &service);

        exit_if_command_not_found(&ro, &service);

        print_may_not(&ro);
        std::process::exit(1);
    }

    // check if a reason was given
    if !reason_ok(&entry, &ro) {
        log_action(&service, "reason_fail", &ro, &ro.original_command.join(" "));
        std::process::exit(1);
    }

    // password required?
    if !challenge_password(&ro, &entry, &service) {
        log_action(&service, "deny", &ro, &ro.original_command.join(" "));
        std::process::exit(1);
    }

    if !drop_privs(&ro) {
        std::process::exit(1);
    }

    // target user
    let lookup_name = get_user_by_name(&ro.target);
    if lookup_name.is_none() {
        println!("Could not lookup {}", &ro.target);
        std::process::exit(1);
    }
    let lookup_name = lookup_name.unwrap();
    let target_uid = nix::unistd::Uid::from_raw(lookup_name.uid());
    let target_gid = runopt_target_gid(&ro, &lookup_name);

    if !esc_privs() {
        std::process::exit(1);
    }
    if !set_eprivs(target_uid, target_gid) {
        std::process::exit(1);
    }

    // change to target dir
    do_dir_changes(&ro, &service);

    if !drop_privs(&ro) {
        std::process::exit(1);
    }

    log_action(&service, "permit", &ro, &ro.original_command.join(" "));

    set_environment(&ro, &entry, &original_user, original_uid, &lookup_name);

    if !esc_privs() {
        std::process::exit(1);
    }

    if !set_privs(&ro.target, target_uid, target_gid) {
        std::process::exit(1);
    }

    nix::sys::stat::umask(ro.old_umask.unwrap());

    if ro.cloned_args.as_ref().unwrap().len() > 1 {
        Command::new(&ro.cloned_args.as_ref().unwrap()[0])
            .args(ro.cloned_args.as_ref().unwrap().clone().split_off(1))
            .exec();
    } else {
        Command::new(&ro.cloned_args.as_ref().unwrap()[0]).exec();
    }
    println!("Error executing");
    std::process::exit(1);
}
