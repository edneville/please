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

use getopts::Options;

use nix::unistd::gethostname;

use users::*;

/// walk through user ACL
fn do_list(ro: &mut RunOptions, vec_eo: &[EnvOptions], service: &str) {
    let name = if ro.target == ro.name || ro.target.is_empty() {
        "You"
    } else {
        &ro.target
    };

    let can_do = can(&vec_eo, &ro);
    ro.syslog = can_do.syslog;

    if !can_do.permit {
        let dest = format!("{}'s", &ro.target);
        log_action(&service, "deny", &ro, &ro.command);
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
    if can_do.reason && ro.reason.is_none() {
        log_action(&service, "no_reason", &ro, &ro.original_command.join(" "));
        println!(
            "Sorry but no reason was given to list on {} as {}",
            &ro.hostname, &ro.target
        );
        std::process::exit(1);
    }

    // check if a password is required
    if !challenge_password(&ro, &can_do, &service) {
        log_action(&service, "deny", &ro, &ro.original_command.join(" "));
        std::process::exit(1);
    }

    log_action(&service, "permit", &ro, &ro.command);
    println!("{} may run the following:", name);
    ro.acl_type = Acltype::Run;
    list(&vec_eo, &ro);
    println!("{} may edit the following:", name);
    ro.acl_type = Acltype::Edit;
    list(&vec_eo, &ro);
    println!("{} may list the following:", name);
    ro.acl_type = Acltype::List;
    list(&vec_eo, &ro);
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
    mut vec_eo: &mut Vec<EnvOptions>,
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
        let mut bytes = 0;
        std::process::exit(read_ini_config_file(
            &matches.opt_str("c").unwrap(),
            &mut vec_eo,
            &ro.name,
            true,
            &mut bytes,
        ) as i32);
    }

    if matches.opt_present("a") {
        let mut vec = vec![];

        for s in matches.opt_str("a").unwrap().split(',') {
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
    common_opt_arguments(&matches, &opts, &mut ro, &service, &header);

    if ro.new_args.is_empty() && !ro.warm_token && !ro.purge_token && ro.acl_type != Acltype::List {
        println!("No command given");
        print_usage(&opts, &header);
        print_version(&service);
        std::process::exit(0);
    }
}

/// main entry point
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
    if read_ini_config_file("/etc/please.ini", &mut vec_eo, &ro.name, true, &mut bytes) {
        println!("Exiting due to error, cannot fully process /etc/please.ini");
        std::process::exit(1);
    }

    if !drop_privs(&ro) {
        std::process::exit(1);
    }

    let mut buf = [0u8; 64];
    ro.hostname = gethostname(&mut buf)
        .expect("Failed getting hostname")
        .to_str()
        .expect("Hostname wasn't valid UTF-8")
        .to_string();

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

    ro.command = replace_new_args(ro.new_args.clone());

    match search_path(&ro.new_args[0]) {
        None => {
            println!("[{}]: command not found", service);
            std::process::exit(1);
        }
        Some(x) => {
            ro.new_args[0] = x;
            ro.command = replace_new_args(ro.new_args.clone());
        }
    }

    let entry = can(&vec_eo, &ro);

    ro.syslog = entry.syslog;
    if !entry.permit {
        log_action(&service, "deny", &ro, &original_command.join(" "));
        print_may_not(&ro);
        std::process::exit(1);
    }
    // check if a reason was given
    if entry.permit && entry.reason && ro.reason.is_none() {
        log_action(&service, "no_reason", &ro, &original_command.join(" "));
        println!(
            "Sorry but no reason was given to execute \"{}\" on {} as {}",
            &ro.command, &ro.hostname, &ro.target
        );
        std::process::exit(1);
    }

    if !challenge_password(&ro, &entry, &service) {
        log_action(&service, "deny", &ro, &original_command.join(" "));
        std::process::exit(1);
    }

    if !drop_privs(&ro) {
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

    if !esc_privs() {
        std::process::exit(1);
    }
    if !set_eprivs(target_uid, target_gid) {
        std::process::exit(1);
    }

    do_dir_changes(&ro, &service);

    if !drop_privs(&ro) {
        std::process::exit(1);
    }

    log_action(&service, "permit", &ro, &original_command.join(" "));

    set_environment(&ro, &entry, &original_user, original_uid, &lookup_name);

    if !esc_privs() {
        std::process::exit(1);
    }

    if !set_privs(&ro.target, target_uid, target_gid) {
        std::process::exit(1);
    }

    nix::sys::stat::umask(ro.old_umask.unwrap());

    if ro.new_args.len() > 1 {
        Command::new(&ro.new_args[0])
            .args(ro.new_args.clone().split_off(1))
            .exec();
    } else {
        Command::new(&ro.new_args[0]).exec();
    }
}

#[cfg(test)]
mod test {}
