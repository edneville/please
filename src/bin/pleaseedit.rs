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
    can, challenge_password, get_editor, log_action, read_ini_config_file, remove_token,
    EnvOptions, RunOptions, ACLTYPE,
};

use std::fs::*;
use std::io::{self, Write};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

use getopt::prelude::*;

use nix::sys::wait::WaitStatus::Exited;
use nix::unistd::{fork, gethostname, setgid, setgroups, setuid, ForkResult};

use users::*;

fn print_usage(program: &str) {
    println!("usage:");
    println!("{} /path/to/file", program);
    println!(" -t [user]: edit as target user");
    println!(" -n: rather than prompt for password, exit non-zero");
    println!(" -p: purge valid tokens");
    println!(" -w: warm token cache");
    println!("version: 0.3.3");
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

    nix::unistd::chown(
        tmp_edit_file_path,
        Some(nix::unistd::Uid::from_raw(original_uid)),
        Some(nix::unistd::Gid::from_raw(original_gid)),
    )
    .unwrap();

    nix::sys::stat::fchmodat(
        None,
        tmp_edit_file_path,
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        nix::sys::stat::FchmodatFlags::FollowSymlink,
    )
    .unwrap();

    tmp_edit_file
}

fn main() {
    let mut args: Vec<String> = std::env::args().collect();
    let original_command = args.clone();
    let program = args[0].clone();
    let mut opts = Parser::new(&args, "t:hnpw");
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
    let mut vec_eo: Vec<EnvOptions> = vec![];

    loop {
        match opts.next().transpose() {
            Err(_x) => {
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
                    Opt('n', None) => prompt = false,
                    Opt('p', None) => purge_token = true,
                    Opt('w', None) => warm_token = true,
                    _ => unreachable!(),
                },
            },
        }
    }

    let new_args = args.split_off(opts.index());
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
        println!("Exiting due to error");
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
            log_action(
                &service,
                "deny",
                &ro.name,
                &ro.target,
                &original_command.join(" "),
            );
            println!(
                "You may not edit \"{}\" on {} as {}",
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
                    "You may not edit \"{}\" on {} as {}",
                    &ro.command,
                    &ro.hostname,
                    &ro.target
                );
                std::process::exit(1);
            }
        }
    }

    if !challenge_password(
        ro.name.to_string(),
        entry.clone().unwrap(),
        &service,
        prompt,
    ) {
        log_action(
            &service,
            "deny",
            &ro.name,
            &ro.target,
            &original_command.join(" "),
        );
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
    match fork() {
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

            let mut groups: Vec<nix::unistd::Gid> = vec![];
            for x in lookup_name.groups().unwrap() {
                groups.push(nix::unistd::Gid::from_raw(x.gid()));
            }
            setgroups(groups.as_slice()).unwrap();

            setgid(nix::unistd::Gid::from_raw(original_gid)).unwrap();
            setuid(nix::unistd::Uid::from_raw(original_uid)).unwrap();

            Command::new(editor.as_str()).arg(&edit_file).exec();
            std::process::exit(1);
        }
        Err(_) => println!("Fork failed"),
    }

    if !good_edit {
        println!("Exiting as editor or child did not close cleanly.");
        std::process::exit(1);
    }

    log_action(
        &service,
        "permit",
        &ro.name,
        &ro.target,
        &original_command.join(" "),
    );

    if entry.clone().unwrap().exitcmd.is_some() {
        let out = Command::new(entry.unwrap().exitcmd.unwrap().as_str())
            .arg(&source_file)
            .arg(&edit_file)
            .output()
            .expect("could not execute");
        io::stdout().write_all(&out.clone().stdout).unwrap();
        io::stderr().write_all(&out.clone().stderr).unwrap();
        if !out.status.success() {
            println!("Aborting as exitcmd was non-zero");
            std::process::exit(out.status.code().unwrap());
        }
    }

    let dir_parent_tmp = format!("{}.{}.{}", source_file.to_str().unwrap(), service, ro.name);
    std::fs::copy(edit_file, dir_parent_tmp.as_str()).unwrap();

    nix::unistd::chown(
        dir_parent_tmp.as_str(),
        Some(nix::unistd::Uid::from_raw(lookup_name.uid())),
        Some(nix::unistd::Gid::from_raw(lookup_name.primary_group_id())),
    )
    .unwrap();

    nix::sys::stat::fchmodat(
        None,
        dir_parent_tmp.as_str(),
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        nix::sys::stat::FchmodatFlags::FollowSymlink,
    )
    .unwrap();

    std::fs::rename(&dir_parent_tmp.as_str(), source_file).unwrap();
}

#[cfg(test)]
mod test {}
