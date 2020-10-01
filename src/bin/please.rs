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

use getopt::prelude::*;

use nix::unistd::{gethostname, setgid, setgroups, setuid};

use users::os::unix::UserExt;
use users::*;

fn print_usage(program: &str) {
    println!("usage:");
    println!("{} [arguments] <path/to/executable>", program);
    println!(" -l <-t users permissions> <-v>: list permissions");
    println!(" -t [user]: become target user");
    println!(" -c [file]: check config file");
    println!(" -d [dir]: change to dir before execution");
    println!(" -n: rather than prompt for password, exit non-zero");
    println!(" -p: purge valid tokens");
    println!(" -w: warm token cache");
}

fn main() {
    let mut args: Vec<String> = std::env::args().collect();
    let original_command = args.clone();
    let program = args[0].clone();
    let mut opts = Parser::new(&args, "c:d:hlwpnt:");
    let service = String::from("please");
    let mut ro = RunOptions::new();
    let mut prompt = true;
    let mut purge_token = false;
    let mut warm_token = false;
    let original_uid = get_current_uid();
    let original_user = get_user_by_uid(original_uid).unwrap();
    ro.name = original_user.name().to_string_lossy().to_string();
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
                    Opt('t', Some(string)) => ro.target = string,
                    Opt('l', None) => ro.acl_type = ACLTYPE::LIST,
                    Opt('c', Some(config_file)) => std::process::exit(read_ini_config_file(
                        &config_file,
                        &mut vec_eo,
                        &ro.name,
                        true,
                    ) as i32),
                    Opt('d', Some(string)) => ro.directory = string,
                    Opt('n', None) => prompt = false,
                    Opt('p', None) => purge_token = true,
                    Opt('w', None) => warm_token = true,
                    _ => unreachable!(),
                },
            },
        }
    }

    let mut new_args = args.split_off(opts.index());
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
        println!("Exiting due to error");
        std::process::exit(1);
    }

    let mut buf = [0u8; 64];
    ro.hostname = gethostname(&mut buf)
        .expect("Failed getting hostname")
        .to_str()
        .expect("Hostname wasn't valid UTF-8")
        .to_string();

    if ro.acl_type == ACLTYPE::LIST {
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
            // let dest = if ro.target == "" { "your" } else { format!("{}'s", &ro.target).as_str() };
            let dest = format!("{}'s", &ro.target);
            log_action(&service, "deny", &ro.name, &ro.target, &ro.command);
            println!(
                "You may not view {} command list",
                if ro.target == "" { "your" } else { &dest }
            );
        }
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
                &original_command.join(" "),
            );
            println!(
                "You may not execute \"{}\" on {} as {}",
                &ro.command,
                &ro.hostname,
                &ro.target
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
                    &original_command.join(" "),
                );
                println!(
                    "You may not execute \"{}\" on {} as {}",
                    &ro.command,
                    &ro.hostname,
                    &ro.target
                );
                std::process::exit(1);
            }
        }
    }

    if new_args.is_empty() {
        print_usage(&program);
        return;
    }

    if !challenge_password(ro.name.to_string(), entry.unwrap(), &service, prompt) {
        log_action(
            &service,
            "deny",
            &ro.name,
            &ro.target,
            &original_command.join(" "),
        );
        println!("Keyboard not present or not functioning, press F1 to continue.");
        std::process::exit(1);
    }

    if ro.directory != "" {
        if let Err(x) = std::env::set_current_dir(&ro.directory) {
            println!("Cannot cd into {}: {}", &ro.directory, x);
            std::process::exit(1);
        }
    }

    log_action(
        &service,
        "permit",
        &ro.name,
        &ro.target,
        &original_command.join(" "),
    );
    let lookup_name = get_user_by_name(&ro.target).unwrap();
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
