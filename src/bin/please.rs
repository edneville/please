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
use please::util::{can_run, challenge_password, read_config, UserData, list_edit, list_run};

use std::collections::HashMap;
use std::os::unix::process::CommandExt;
use std::process::Command;

use getopt::prelude::*;

use nix::unistd::{gethostname, setgid, setgroups, setuid};

use users::*;

fn print_usage(program: &str) {
    println!(" usage:");
    println!("{} /path/to/executable [arguments]", program);
    println!(" -t [user]: become target user");
}

fn main() {
    let mut args: Vec<String> = std::env::args().collect();
    let program = args[0].clone();
    let mut opts = Parser::new(&args, "t:hl");

    let mut target = String::from("root");
    let mut list = false;

    loop {
        match opts.next().transpose().expect("bad args") {
            None => break,
            Some(opt) => match opt {
                Opt('h', None) => {
                    print_usage(&program);
                    return;
                }
                Opt('t', Some(string)) => target = string,
                Opt('l', None) => list = true,
                _ => unreachable!(),
            },
        }
    }

    let new_args = args.split_off(opts.index());

    let mut hm: HashMap<String, UserData> = HashMap::new();
    read_config("/etc/please.conf", &mut hm);

    let original_uid = get_current_uid();
    let original_user = get_user_by_uid(original_uid).unwrap();
    let user = original_user.name().to_string_lossy();
    let date = Utc::now().naive_utc();
    let mut buf = [0u8; 64];
    let hostname = gethostname(&mut buf)
        .expect("Failed getting hostname")
        .to_str()
        .expect("Hostname wasn't valid UTF-8");
    let entry = can_run(&hm, &user, &target, &date, &hostname, &new_args.join(" "));

    if list {
        println!("You may run the following:");
        list_run( &hm, &user, &date, &hostname );
        println!("You may edit the following:");
        list_edit( &hm, &user, &date, &hostname );
        return;
    }

    match &entry {
        Err(_) => {
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

    let service = String::from("please");
    if !challenge_password(user.to_string(), entry.clone().unwrap(), &service) {
        return;
    }

    let lookup_name = users::get_user_by_name(&entry.unwrap().target).unwrap();
    let target_uid = nix::unistd::Uid::from_raw(lookup_name.uid());
    let target_gid = nix::unistd::Gid::from_raw(lookup_name.primary_group_id());

    std::env::set_var("PLEASE_USER", original_user.name());
    std::env::set_var("PLEASE_UID", original_uid.to_string());

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
    } else {
        Command::new(&new_args[0]).exec();
    }
}

#[cfg(test)]
mod test {}
