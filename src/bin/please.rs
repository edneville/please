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

use chrono::Utc;
use pleaser::util::{
    can_list, can_run, challenge_password, group_hash, list_edit, list_run, log_action,
    read_ini_config_file, search_path, update_token, valid_token, EnvOptions,
};

use std::os::unix::process::CommandExt;
use std::process::Command;

use getopt::prelude::*;

use nix::unistd::{gethostname, setgid, setgroups, setsid, setuid};

use users::os::unix::UserExt;
use users::*;

fn print_usage(program: &str) {
    println!("usage:");
    println!("{} [arguments] <path/to/executable>", program);
    println!(" -l <-t users permissions> <-v>: list permissions");
    println!(" -t [user]: become target user");
    println!(" -c [file]: check config file");
    println!("version: 0.3.3");
}

fn main() {
    let mut args: Vec<String> = std::env::args().collect();
    let original_command = args.clone();
    let program = args[0].clone();
    let mut opts = Parser::new(&args, "c:hlt:");
    let service = String::from("please");

    let mut target = String::from("");
    let mut list = false;

    let original_uid = get_current_uid();
    let original_user = get_user_by_uid(original_uid).unwrap();
    let user = original_user.name().to_string_lossy();
    let mut vec_eo: Vec<EnvOptions> = vec![];

    loop {
        match opts.next().transpose() {
            Err(_x) => {
                println!("Cannot parse arguments");
                print_usage(&program);
                std::process::exit(1);
            }
            Ok(a) => match a {
                None => break,
                Some(opt) => match opt {
                    Opt('h', None) => {
                        print_usage(&program);
                        return;
                    }
                    Opt('t', Some(string)) => target = string,
                    Opt('l', None) => list = true,
                    Opt('c', Some(string)) => {
                        std::process::exit(
                            read_ini_config_file(&string, &mut vec_eo, &user, true) as i32
                        )
                    }
                    _ => unreachable!(),
                },
            },
        }
    }

    let mut new_args = args.split_off(opts.index());
    let groups = group_hash(original_user.groups().unwrap());

    if read_ini_config_file("/etc/please.ini", &mut vec_eo, &user, true) {
        println!("Exiting due to error");
        std::process::exit(1);
    }

    let date = Utc::now().naive_utc();
    let mut buf = [0u8; 64];
    let hostname = gethostname(&mut buf)
        .expect("Failed getting hostname")
        .to_str()
        .expect("Hostname wasn't valid UTF-8");

    if list {
        if target != "" {
            let can_do = can_list(&vec_eo, &user, &target, &date, &hostname, &"", &groups);

            if can_do.is_ok() && can_do.unwrap().permit {
                println!("{} may run the following:", target);
                list_run(&vec_eo, &user, &date, &hostname, &target, &groups);
                println!("{} may edit the following:", target);
                list_edit(&vec_eo, &user, &date, &hostname, &target, &groups);
            } else {
                log_action(
                    &service,
                    "deny",
                    &user,
                    &target,
                    &original_command.join(" "),
                );
                println!("You may not view {}'s command list", target);
            }
        } else {
            log_action(
                &service,
                "permit",
                &user,
                &target,
                &original_command.join(" "),
            );
            println!("You may run the following:");
            list_run(&vec_eo, &user, &date, &hostname, &target, &groups);
            println!("You may edit the following:");
            list_edit(&vec_eo, &user, &date, &hostname, &target, &groups);
        }
        return;
    }

    if target == "" {
        target = "root".to_string();
    }

    if new_args.is_empty() {
        println!("No command given.");
        return;
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

    let entry = can_run(
        &vec_eo,
        &user,
        &target,
        &date,
        &hostname,
        &new_args.join(" "),
        &groups,
    );

    match &entry {
        Err(_) => {
            log_action(
                &service,
                "deny",
                &user,
                &target,
                &original_command.join(" "),
            );
            println!(
                "You may not execute \"{}\" on {} as {}",
                new_args.join(" "),
                &hostname,
                &target
            );
            return;
        }
        Ok(x) => {
            if !x.permit {
                log_action(
                    &service,
                    "deny",
                    &user,
                    &target,
                    &original_command.join(" "),
                );
                println!(
                    "You may not execute \"{}\" on {} as {}",
                    new_args.join(" "),
                    &hostname,
                    &target
                );
                return;
            }
        }
    }

    if new_args.is_empty() {
        print_usage(&program);
        return;
    }

    if !challenge_password(user.to_string(), entry.unwrap(), &service) {
        log_action(
            &service,
            "deny",
            &user,
            &target,
            &original_command.join(" "),
        );
        println!("Keyboard not present or not functioning, press F1 to continue.");
        return;
    }

    log_action(
        &service,
        "permit",
        &user,
        &target,
        &original_command.join(" "),
    );
    let lookup_name = get_user_by_name(&target).unwrap();
    let target_uid = nix::unistd::Uid::from_raw(lookup_name.uid());
    let target_gid = nix::unistd::Gid::from_raw(lookup_name.primary_group_id());

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
    std::env::set_var("PLEASE_COMMAND", new_args.join(" "));

    std::env::set_var("SUDO_USER", original_user.name());
    std::env::set_var("SUDO_UID", original_uid.to_string());
    std::env::set_var("SUDO_GID", original_user.primary_group_id().to_string());
    std::env::set_var("SUDO_COMMAND", new_args.join(" "));

    std::env::set_var(
        "PATH",
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
    );
    std::env::set_var("HOME", lookup_name.home_dir().as_os_str());
    std::env::set_var("MAIL", format!("/var/mail/{}", target));
    std::env::set_var("SHELL", lookup_name.shell());
    std::env::set_var("USER", &target);
    std::env::set_var("LOGNAME", &target);

    let mut groups: Vec<nix::unistd::Gid> = vec![];
    for x in lookup_name.groups().unwrap() {
        groups.push(nix::unistd::Gid::from_raw(x.gid()));
    }
    setgroups(groups.as_slice()).unwrap();

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
