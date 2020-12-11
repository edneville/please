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
use regex::Regex;

use std::collections::HashMap;
use std::env;
use std::ffi::{CStr, CString};
use std::path::Path;
use std::process;
use std::time::SystemTime;
use syslog::{Facility, Formatter3164};

use chrono::{NaiveDate, NaiveDateTime, Utc};
use std::fs;
use std::fs::File;
use std::io::prelude::*;
use users::*;

use nix::unistd::{initgroups, setgid, setuid};

#[derive(Clone)]
pub struct EnvOptions {
    pub name: String,
    pub rule: String,
    pub notbefore: Option<NaiveDateTime>,
    pub notafter: Option<NaiveDateTime>,
    pub datematch: Option<String>,
    pub target: String,
    pub hostname: Option<String>,
    pub permit: bool,
    pub require_pass: bool,
    pub acl_type: ACLTYPE,
    pub file_name: String,
    pub section: String,
    pub group: bool,
    pub configured: bool,
    pub dir: Option<String>,
    pub exitcmd: Option<String>,
    pub edit_mode: Option<i32>,
    pub reason: bool,
    pub last: bool,
    pub syslog: bool,
}

impl EnvOptions {
    pub fn new() -> EnvOptions {
        EnvOptions {
            name: "".to_string(),
            rule: "^$".to_string(),
            target: "root".to_string(),
            notbefore: None,
            notafter: None,
            datematch: None,
            hostname: None,
            file_name: "".to_string(),
            section: "".to_string(),
            permit: true,
            require_pass: true,
            acl_type: ACLTYPE::RUN,
            group: false,
            configured: false,
            dir: None,
            exitcmd: None,
            edit_mode: None,
            reason: false,
            last: false,
            syslog: true,
        }
    }
    fn new_deny() -> EnvOptions {
        let mut opt = EnvOptions::new();
        opt.permit = false;
        opt.rule = ".".to_string();
        opt.target = "^$".to_string();
        opt.acl_type = ACLTYPE::LIST;
        opt
    }
}

impl Default for EnvOptions {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone)]
pub struct RunOptions {
    pub name: String,
    pub target: String,
    pub command: String,
    pub original_command: Vec<String>,
    pub hostname: String,
    pub directory: String,
    pub groups: HashMap<String, u32>,
    pub date: NaiveDateTime,
    pub acl_type: ACLTYPE,
    pub reason: Option<String>,
    pub syslog: bool,
}

impl RunOptions {
    pub fn new() -> RunOptions {
        RunOptions {
            name: "root".to_string(),
            target: "".to_string(),
            command: "".to_string(),
            original_command: vec![],
            hostname: "localhost".to_string(),
            date: Utc::now().naive_utc(),
            groups: HashMap::new(),
            directory: ".".to_string(),
            acl_type: ACLTYPE::RUN,
            reason: None,
            syslog: true,
        }
    }
}

impl Default for RunOptions {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(PartialEq, Eq, Clone, Debug)]
pub enum ACLTYPE {
    RUN,
    LIST,
    EDIT,
}

pub fn regex_build(v: &str, user: &str, config_path: &str, section: &str) -> Option<Regex> {
    let rule = Regex::new(&format!("^{}$", &v.replace("%{USER}", &user)));
    if rule.is_err() {
        println!(
            "Error parsing {}:{}, {}",
            config_path,
            section,
            v.to_string()
        );
        return None;
    }
    Some(rule.unwrap())
}

pub fn can_dir_include(file: &str) -> bool {
    let dir_pattern = Regex::new(r".*\.ini$").unwrap();

    if dir_pattern.is_match(file) {
        let p = Path::new(file);
        if p.is_file() {
            return true;
        }
    }

    false
}

pub fn read_ini(
    conf: &str,
    vec_eo: &mut Vec<EnvOptions>,
    user: &str,
    fail_error: bool,
    config_path: &str,
) -> bool {
    let parse_datetime_from_str = NaiveDateTime::parse_from_str;
    let parse_date_from_str = NaiveDate::parse_from_str;
    let mut faulty = false;
    let mut section = String::from("no section defined");
    let mut in_section = false;
    let mut opt = EnvOptions::new();

    for l in conf.split('\n') {
        let line = l.trim();

        if line == "" || line.starts_with('#') {
            continue;
        }

        if line.starts_with('[') && line.ends_with(']') {
            in_section = true;
            section = line[1..line.len() - 1].to_string();
            if opt.configured {
                vec_eo.push(opt);
            }
            opt = EnvOptions::new();
            opt.section = section.clone();
            opt.file_name = String::from(config_path);
            continue;
        }

        let equals_pos = line.find('=');
        if equals_pos.is_none() {
            continue;
        }

        let key = line[0..equals_pos.unwrap()].trim();
        let value = line[equals_pos.unwrap() + 1..].trim();

        if !in_section {
            println!("Error parsing {}:{}", config_path, line);
            faulty = true;
            continue;
        }

        match key {
            "include" => {
                if read_ini_config_file(&value, vec_eo, &user, fail_error) {
                    println!("Couldn't read {}", value);
                    return true;
                }
                continue;
            }
            "includedir" => {
                match fs::read_dir(value) {
                    Err(_x) => {
                        faulty = true;
                    }
                    Ok(inc) => {
                        let mut collect = vec![];
                        for file in inc {
                            collect.push(file.unwrap().path().to_str().unwrap().to_string());
                        }
                        collect.sort();
                        for file in collect {
                            let incf = file;
                            if !can_dir_include(&incf) {
                                continue;
                            }
                            if read_ini_config_file(&incf, vec_eo, &user, fail_error) {
                                println!("Could not read {}", value);
                                return true;
                            }
                        }
                    }
                }

                continue;
            }
            "name" => {
                opt.name = value.to_string();
                opt.configured = true;
                if fail_error && regex_build(value, user, config_path, &section).is_none() {
                    faulty = true;
                }
            }
            "hostname" => {
                opt.hostname = Some(value.to_string());
                opt.configured = true;
                if fail_error && regex_build(value, user, config_path, &section).is_none() {
                    faulty = true;
                }
            }
            "target" => {
                opt.target = value.to_string();
                if fail_error && regex_build(value, user, config_path, &section).is_none() {
                    faulty = true;
                }
            }
            "permit" => opt.permit = value == "true",
            "require_pass" => opt.require_pass = value != "false",
            "type" => match value.to_lowercase().as_str() {
                "edit" => opt.acl_type = ACLTYPE::EDIT,
                "list" => opt.acl_type = ACLTYPE::LIST,
                _ => opt.acl_type = ACLTYPE::RUN,
            },
            "group" => opt.group = value == "true",
            "regex" | "rule" => {
                opt.rule = value.to_string();
                if fail_error && regex_build(value, user, config_path, &section).is_none() {
                    faulty = true;
                }
            }
            "notbefore" if value.len() == 8 => {
                opt.notbefore = Some(
                    parse_date_from_str(&value.to_string(), "%Y%m%d")
                        .unwrap()
                        .and_hms(0, 0, 0),
                )
            }
            "notafter" if value.len() == 8 => {
                opt.notafter = Some(
                    parse_date_from_str(&value.to_string(), "%Y%m%d")
                        .unwrap()
                        .and_hms(23, 59, 59),
                )
            }
            "notbefore" if value.len() == 14 => {
                opt.notbefore =
                    Some(parse_datetime_from_str(&value.to_string(), "%Y%m%d%H%M%S").unwrap())
            }
            "notafter" if value.len() == 14 => {
                opt.notafter =
                    Some(parse_datetime_from_str(&value.to_string(), "%Y%m%d%H%M%S").unwrap())
            }
            "datematch" => {
                opt.datematch = Some(value.to_string());
                if fail_error && regex_build(value, user, config_path, &section).is_none() {
                    faulty = true;
                }
            }
            "dir" => {
                opt.dir = Some(value.to_string());
                if fail_error && regex_build(value, user, config_path, &section).is_none() {
                    faulty = true;
                }
            }
            "exitcmd" => {
                if !value.is_empty() {
                    opt.exitcmd = Some(value.to_string());
                }
            }
            "editmode" => {
                if !value.is_empty() {
                    if value.parse::<i16>().is_ok() {
                        opt.edit_mode = Some(
                            i32::from_str_radix(value.trim_start_matches('0'), 8)
                                .expect("unable to parse editmode"),
                        );
                    } else {
                        println!("Could not convert {} to numerical file mode", value);
                        faulty = true;
                    }
                }
            }
            "reason" => opt.reason = value == "true",
            "last" => opt.last = value == "true",
            "syslog" => opt.syslog = value == "true",
            &_ => {
                println!("{}: unknown attribute \"{}\": {}", config_path, key, value);
                faulty = true;
            }
        }
    }

    if opt.configured {
        vec_eo.push(opt);
    }

    fail_error && faulty
}

pub fn read_ini_config_file(
    config_path: &str,
    vec_eo: &mut Vec<EnvOptions>,
    user: &str,
    fail_error: bool,
) -> bool {
    let path = Path::new(config_path);
    let display = path.display();

    let mut file = match File::open(&path) {
        Err(_why) => return true,
        Ok(file) => file,
    };

    let mut s = String::new();
    match file.read_to_string(&mut s) {
        Err(why) => {
            println!("couldn't read {}: {}", display, why);
            true
        }
        Ok(_) => read_ini(&s, vec_eo, &user, fail_error, config_path),
    }
}

pub fn read_ini_config_str(
    config: &str,
    vec_eo: &mut Vec<EnvOptions>,
    user: &str,
    fail_error: bool,
) -> bool {
    read_ini(&config, vec_eo, &user, fail_error, "static")
}

pub fn hostname_ok(item: &EnvOptions, ro: &RunOptions) -> bool {
    if item.hostname.is_some() {
        let hostname_re = match regex_build(
            &item.hostname.as_ref().unwrap(),
            &ro.name,
            &item.file_name,
            &item.section,
        ) {
            Some(check) => check,
            None => {
                println!("Could not compile {}", &item.name);
                return false;
            }
        };

        if !hostname_re.is_match(&ro.hostname)
            && !hostname_re.is_match("any")
            && !hostname_re.is_match("localhost")
        {
            // println!("{}: hostname mismatch", item.section);
            return false;
        }
    }
    true
}

pub fn directory_check_ok(item: &EnvOptions, ro: &RunOptions) -> bool {
    if item.dir.is_some() {
        let dir_re = match regex_build(
            &item.dir.as_ref().unwrap(),
            &ro.name,
            &item.file_name,
            &item.section,
        ) {
            Some(check) => check,
            None => {
                println!("Could not compile {}", &item.name);
                return false;
            }
        };

        if !dir_re.is_match(&ro.directory) {
            // && ro.directory != "." {
            return false;
        }
    }
    true
}

pub fn permitted_dates_ok(item: &EnvOptions, ro: &RunOptions) -> bool {
    if item.notbefore.is_some() && item.notbefore.unwrap() > ro.date {
        // println!("{}: now is before date", item.section);
        return false;
    }

    if item.notafter.is_some() && item.notafter.unwrap() < ro.date {
        // println!("{}: now is after date", item.section);
        return false;
    }

    if item.datematch.is_some() {
        let datematch_re = match regex_build(
            &item.datematch.as_ref().unwrap(),
            &ro.name,
            &item.file_name,
            &item.section,
        ) {
            Some(check) => check,
            None => {
                println!("Could not compile {}", &item.name);
                return false;
            }
        };

        if !datematch_re.is_match(&ro.date.format("%a %e %b %T UTC %Y").to_string()) {
            // println!("{}: skipping as not a datematch {} vs {}", item.section, item.datematch.clone().unwrap(), &ro.date.format( "%a %e %b %T UTC %Y" ).to_string() );
            return false;
        }
    }
    true
}

pub fn can(vec_eo: &[EnvOptions], ro: &RunOptions) -> Result<EnvOptions, ()> {
    let mut opt = EnvOptions::new_deny();
    let mut matched = false;

    for item in vec_eo {
        // println!("{}:", item.section);
        if item.acl_type != ro.acl_type {
            // println!("{}: not {:?} != {:?}", item.section, item.acl_type, ro.acl_type);
            continue;
        }

        if !permitted_dates_ok(&item, &ro) {
            continue;
        }

        let name_re = match regex_build(&item.name, &ro.name, &item.file_name, &item.section) {
            Some(check) => check,
            None => {
                println!("Could not compile {}", &item.name);
                continue;
            }
        };

        if !item.group && !name_re.is_match(&ro.name) {
            // println!("{}: skipping as not a name match ({}), group={}", item.section, item.name, item.group);
            continue;
        }

        if item.group {
            let mut found = false;
            for (k, _) in ro.groups.iter() {
                if name_re.is_match(&k.to_string()) {
                    // println!("{}: {} matches group {}", item.section,item.name, k);
                    found = true;
                    break;
                }
            }
            if !found {
                // println!("{}: did not find a group name match",item.section);
                continue;
            }
        }

        if !hostname_ok(&item, &ro) {
            continue;
        }

        if !directory_check_ok(&item, &ro) {
            continue;
        }

        let target_re = match regex_build(&item.target, &ro.name, &item.file_name, &item.section) {
            Some(check) => check,
            None => {
                println!("Could not compile {}", &item.name);
                continue;
            }
        };

        if item.acl_type == ACLTYPE::LIST {
            if target_re.is_match(&ro.target) {
                // println!("{}: is list", item.section);
                opt = item.clone();
                matched = true;
            }
        } else {
            if !target_re.is_match(&ro.target) {
                // println!("{}: item target {} != target {}", item.section, item.target, ro.target);
                continue;
            }

            let rule_re = match regex_build(&item.rule, &ro.name, &item.file_name, &item.section) {
                Some(check) => check,
                None => {
                    println!("Could not compile {}", &item.name);
                    continue;
                }
            };

            if rule_re.is_match(&ro.command) {
                // println!("{}: item rule is match", item.section);
                opt = item.clone();
                matched = true;
            } else {
                // println!("{}: item rule ({}) is not a match for {}", item.section, item.rule, ro.command);
            }
        }

        if opt.last && matched {
            break;
        }
        // println!("didn't match");
    }
    Ok(opt)
}

pub fn auth_ok(u: &str, p: &str, service: &str) -> bool {
    let mut auth = pam::Authenticator::with_password(&service).expect("Failed to init PAM client.");
    auth.get_handler().set_credentials(u, p);
    if auth.authenticate().is_ok() && auth.open_session().is_ok() {
        return true;
    }
    false
}

pub fn get_editor() -> String {
    let editor = "/usr/bin/vi";

    for prog in [String::from("VISUAL"), String::from("EDITOR")].iter() {
        if let Ok(val) = std::env::var(prog) {
            return val;
        }
    }

    editor.to_string()
}

pub fn challenge_password(user: String, entry: EnvOptions, service: &str, prompt: bool) -> bool {
    if entry.require_pass {
        let mut retry_counter = 0;
        if valid_token(&user) {
            update_token(&user);
            return true;
        }

        if !prompt {
            return false;
        }

        loop {
            let pass = rpassword::read_password_from_tty(Some(&format!(
                "[{}] password for {}: ",
                &service, &user
            )))
            .unwrap();

            if auth_ok(&user, &pass, &service) {
                update_token(&user);
                return true;
            }
            retry_counter += 1;
            if retry_counter == 3 {
                println!("Authentication failed :-(");
                return false;
            }
        }
    }
    true
}

pub fn list(vec_eo: &[EnvOptions], ro: &RunOptions) {
    let search_user = if ro.target != "" {
        String::from(&ro.target)
    } else {
        String::from(&ro.name)
    };

    let mut last_file = "";

    for item in vec_eo {
        let name_re = match regex_build(&item.name, &ro.name, &item.file_name, &item.section) {
            Some(check) => check,
            None => {
                println!("Could not compile {}", &item.name);
                continue;
            }
        };

        if !item.group && !name_re.is_match(&search_user) {
            continue;
        }

        if item.group {
            let mut found = false;
            for (k, _) in ro.groups.iter() {
                if name_re.is_match(&k) {
                    found = true;
                    break;
                }
            }
            if !found {
                continue;
            }
        }

        let mut prefixes = vec![];
        if item.notbefore.is_some() && item.notbefore.unwrap() > ro.date {
            prefixes.push(format!("upcomming({})", item.notbefore.unwrap()));
        }

        if item.notafter.is_some() && item.notafter.unwrap() < ro.date {
            prefixes.push(format!("expired({})", item.notafter.unwrap()));
        }

        if item.reason {
            prefixes.push(String::from("reason_required"));
        }

        if item.acl_type != ro.acl_type {
            continue;
        }

        if !item.permit {
            prefixes.push(String::from("not permitted"));
        }

        if !hostname_ok(&item, &ro) {
            continue;
        }

        if item.last {
            prefixes.push(String::from("last"));
        }

        let mut prefix = prefixes.join(", ");
        if !prefix.is_empty() {
            if item.acl_type != ACLTYPE::LIST {
                prefix = format!(" {} as ", prefix);
            } else {
                prefix = format!(" {} to ", prefix);
            }
        }
        if last_file != item.file_name {
            println!("  file: {}", item.file_name);
            last_file = &item.file_name;
        }

        if item.acl_type == ACLTYPE::LIST {
            println!("    {}:{}list: {}", item.section, prefix, item.target);
            continue;
        }

        println!(
            "    {}:{}{} (pass={},dirs={}): {}",
            item.section,
            prefix,
            item.target,
            item.require_pass,
            if item.dir.is_some() {
                item.dir.as_ref().unwrap()
            } else {
                ""
            },
            item.rule
        );
    }
}

pub fn search_path(binary: &str) -> Option<String> {
    let p = Path::new(binary);
    if binary.starts_with('/') || binary.starts_with("./") {
        if !p.exists() {
            return None;
        } else {
            return Some(binary.to_string());
        }
    }

    if let Ok(path) = env::var("PATH") {
        for dir in path.split(':') {
            let path_name = format!("{}/{}", &dir, &binary.to_string());
            let p = Path::new(&path_name);

            if !p.exists() {
                continue;
            }
            return Some(path_name);
        }
    }

    None
}

pub fn set_privs(user: &str, target_uid: nix::unistd::Uid, target_gid: nix::unistd::Gid) {
    let user = CString::new(user).unwrap();
    initgroups(&user, target_gid).unwrap();
    setgid(target_gid).unwrap();
    setuid(target_uid).unwrap();
}

pub fn tty_name() -> String {
    let mut ttyname = "failed";

    /* sometimes a tty isn't attached for all pipes FIXME: make this testable */
    unsafe {
        for n in 0..255 {
            let ptr = libc::ttyname(n);
            if ptr.is_null() {
                continue;
            }

            match CStr::from_ptr(ptr).to_str() {
                Err(_x) => ttyname = "failed",
                Ok(x) => ttyname = x,
            }
            break;
        }
    }

    ttyname.to_string()
}

pub fn log_action(service: &str, result: &str, ro: &RunOptions, command: &str) -> bool {
    if !ro.syslog {
        return false;
    }

    let formatter = Formatter3164 {
        facility: Facility::LOG_USER,
        hostname: None,
        process: service.into(),
        pid: process::id() as i32,
    };

    match syslog::unix(formatter) {
        Err(e) => println!("Impossible to connect to syslog: {:?}", e),
        Ok(mut writer) => {
            writer
                .err(format!(
                    "user={} tty={} action={} target={} reason={} command={}",
                    &ro.name,
                    tty_name(),
                    result,
                    &ro.target,
                    if ro.reason.clone().is_some() {
                        ro.reason.clone().unwrap()
                    } else {
                        String::from("")
                    },
                    command
                ))
                .expect("could not write error message");
        }
    }
    false
}

pub fn token_dir() -> String {
    "/var/run/please/token".to_string()
}

pub fn token_path(user: &str) -> String {
    let ppid = nix::unistd::getppid();
    return format!(
        "{}/{}:{}:{}",
        token_dir(),
        user,
        tty_name().replace("/", "_"),
        ppid
    );
}

pub fn valid_token(user: &str) -> bool {
    if !Path::new(&token_dir()).is_dir() && fs::create_dir_all(&token_dir()).is_err() {
        return false;
    }

    match fs::metadata(token_path(user)) {
        Ok(meta) => match meta.modified() {
            Ok(t) => match SystemTime::now().duration_since(t) {
                Ok(d) => {
                    if d.as_secs() < 600 {
                        return true;
                    }
                    false
                }
                Err(_e) => false,
            },
            Err(_e) => false,
        },
        Err(_) => false,
    }
}

pub fn update_token(user: &str) {
    if !Path::new(&token_dir()).is_dir() && fs::create_dir_all(&token_dir()).is_err() {
        return;
    }

    match fs::File::create(token_path(&user)) {
        Ok(_x) => {}
        Err(x) => println!("Error creating token: {}", x),
    }
}

pub fn remove_token(user: &str) {
    if !Path::new(&token_dir()).is_dir() && fs::create_dir_all(&token_dir()).is_err() {
        return;
    }

    let token_location = token_path(&user);
    let p = Path::new(&token_location);
    if p.is_file() {
        match fs::remove_file(p) {
            Ok(_x) => {}
            Err(x) => println!("Error removing token {}: {}", p.to_str().unwrap(), x),
        }
    }
}

pub fn group_hash(groups: Vec<Group>) -> HashMap<String, u32> {
    let mut hm: HashMap<String, u32> = HashMap::new();
    for group in groups {
        hm.entry(String::from(group.name().to_string_lossy()))
            .or_insert_with(|| group.gid());
    }
    hm
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_execute_config() {
        let config = "[ed_all_dated]
name=ed
target=root
notbefore=20200101
notafter=20201225
regex =^.*$

[ed_false_oracle]
name=ed
target=oracle
permit=false
regex=^/bin/bash .*$

[ed_root_bash_all]
name=ed
target=root
regex=^/bin/bash .*$
"
        .to_string();

        let mut vec_eo: Vec<EnvOptions> = vec![];
        read_ini_config_str(&config, &mut vec_eo, "ed", false);
        let mut ro = RunOptions::new();
        ro.date = NaiveDate::from_ymd(2020, 1, 1).and_hms(0, 0, 0);
        ro.name = "ed".to_string();
        ro.target = "root".to_string();
        ro.acl_type = ACLTYPE::RUN;
        ro.command = "/bin/bash".to_string();
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, true);
    }

    #[test]
    fn test_user_bash() {
        let config = "
[ed_edn]
name = ed
type = list
target = root
regex = (edn?)

[ed]
name = ed
target = root
regex = /bin/bash
        "
        .to_string();

        let mut vec_eo: Vec<EnvOptions> = vec![];
        read_ini_config_str(&config, &mut vec_eo, "ed", false);
        let mut ro = RunOptions::new();
        ro.name = "ed".to_string();
        ro.target = "root".to_string();
        ro.acl_type = ACLTYPE::RUN;
        ro.command = "/bin/bash".to_string();
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, true);
    }

    #[test]
    fn test_execute_user_does_not_exist() {
        let config = "[ed_root_all]
name=ed
target=root
notbefore=20200101
notafter=20201225
regex= ^.*$

[ed_oracle_bash]
name=ed
target=oracle
regex=^/bin/bash .*$

[ed_root_bash]
name=ed
target=root
regex=^/bin/bash .*$

[user_all_todo]
name=.*
target=thingy
regex=^/bin/bash"
            .to_string();

        let mut ro = RunOptions::new();
        ro.date = NaiveDate::from_ymd(2019, 12, 31).and_hms(0, 0, 0);
        ro.name = "ed".to_string();
        ro.target = "root".to_string();
        ro.acl_type = ACLTYPE::RUN;
        ro.command = "/bin/bash".to_string();

        let mut vec_eo: Vec<EnvOptions> = vec![];
        read_ini_config_str(&config, &mut vec_eo, &ro.name, false);
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, false);

        ro.name = "other".to_string();
        ro.target = "thingy".to_string();
        let mut vec_eo: Vec<EnvOptions> = vec![];
        read_ini_config_str(&config, &mut vec_eo, &ro.name, false);
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, true);

        ro.name = "other".to_string();
        ro.target = "oracle".to_string();
        let mut vec_eo: Vec<EnvOptions> = vec![];
        read_ini_config_str(&config, &mut vec_eo, &ro.name, false);
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, false);
    }

    #[test]
    fn test_execute_config_too_early() {
        let config = "
[ed]
name=ed
target=root
notbefore=20200101
notafter=20201225
regex =^.*$
[ed_oracle]
name=ed
target=oracle ^/bin/bash .*$
[ed_dated]
name=ed
target=root
notbefore=20200101
notafter=20200125
regex =^.*
[name_all_todo]
name=m{}
target=^ "
            .to_string();

        let mut ro = RunOptions::new();
        ro.name = "ed".to_string();
        ro.target = "root".to_string();
        ro.acl_type = ACLTYPE::RUN;
        ro.command = "/bin/bash".to_string();

        let mut vec_eo: Vec<EnvOptions> = vec![];
        read_ini_config_str(&config, &mut vec_eo, "ed", false);

        ro.date = NaiveDate::from_ymd(2019, 12, 31).and_hms(0, 0, 0);
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, false);

        ro.date = NaiveDate::from_ymd(2020, 12, 25).and_hms(0, 0, 0);
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, true);

        ro.date = NaiveDate::from_ymd(2020, 01, 25).and_hms(0, 0, 0);
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, true);

        ro.date = NaiveDate::from_ymd(2020, 03, 25).and_hms(0, 0, 0);
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, true);
    }

    #[test]
    fn test_list_regex() {
        let config = "
[ed_root]
name = (floppy)
group = true
permit = true
require_pass = false
target = ^.*

[ed_list]
name = (ed)
type = list
target = %{USER}
require_pass = false
            "
        .to_string();

        let mut vec_eo: Vec<EnvOptions> = vec![];
        read_ini_config_str(&config, &mut vec_eo, "ed", false);
        let mut ro = RunOptions::new();
        ro.name = "ed".to_string();
        ro.acl_type = ACLTYPE::LIST;

        ro.target = "ed".to_string();
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, true);
        ro.target = "root".to_string();
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, false);
    }

    #[test]
    fn test_execute_config_too_early_long() {
        let config = "
[ed_too_early]
name=ed
target=root
notbefore=20200808
notafter=20200810235959
regex=^.*
        "
        .to_string();

        let mut vec_eo: Vec<EnvOptions> = vec![];
        read_ini_config_str(&config, &mut vec_eo, "ed", false);
        let mut ro = RunOptions::new();
        ro.name = "ed".to_string();
        ro.target = "root".to_string();

        let mut vec_eo: Vec<EnvOptions> = vec![];
        read_ini_config_str(&config, &mut vec_eo, "ed", false);

        ro.date = NaiveDate::from_ymd(2020, 8, 8).and_hms(0, 0, 0);
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, true);

        ro.date = NaiveDate::from_ymd(2020, 8, 10).and_hms(0, 0, 0);
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, true);

        ro.date = NaiveDate::from_ymd(2020, 8, 10).and_hms(23, 59, 59);
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, true);

        ro.date = NaiveDate::from_ymd(2020, 8, 11).and_hms(0, 0, 0);
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, false);

        ro.date = NaiveDate::from_ymd(2020, 8, 7).and_hms(0, 0, 0);
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, false);
    }

    #[test]
    fn test_execute_config_oracle() {
        let config = "[ed_oracle]
name=ed
target=oracle
notbefore=20200101
notafter=20201225
regex=^/bin/bash .*$

[ed_oracle_permit]
name=ed
target=oracle
notbefore=20190101
notafter=20201225
permit=true
regex=^/bin/bash .*$
        "
        .to_string();

        let mut vec_eo: Vec<EnvOptions> = vec![];
        read_ini_config_str(&config, &mut vec_eo, "ed", false);
        let mut ro = RunOptions::new();
        ro.name = "ed".to_string();
        ro.target = "oracle".to_string();
        ro.date = NaiveDate::from_ymd(2019, 12, 31).and_hms(0, 0, 0);

        ro.command = "/bin/bash /usr/local/oracle/backup_script".to_string();
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, true);

        ro.command = "/bin/sh /usr/local/oracle/backup_script".to_string();
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, false);

        ro.hostname = "web1".to_string();
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, false);

        ro.hostname = "".to_string();
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, false);

        ro.hostname = "localhost".to_string();
        ro.target = "grid".to_string();
        ro.command = "/bin/bash /usr/local/oracle/backup_script".to_string();
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, false);

        ro.target = "root".to_string();
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, false);
    }

    #[test]
    fn test_execute_config_hostname_any() {
        let config = "
[ed_config_hostname]
name=ed
target=oracle
hostname=any
regex=^/bin/bash.*$
    "
        .to_string();

        let mut vec_eo: Vec<EnvOptions> = vec![];
        read_ini_config_str(&config, &mut vec_eo, "ed", false);
        let mut ro = RunOptions::new();
        ro.name = "ed".to_string();
        ro.target = "oracle".to_string();

        ro.command = "/bin/bash /usr/local/oracle/backup_script".to_string();
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, true);

        ro.command = "/bin/sh /usr/local/oracle/backup_script".to_string();
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, false);

        ro.hostname = "web1".to_string();
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, false);

        ro.hostname = "".to_string();
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, false);

        ro.target = "grid".to_string();
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, false);
    }

    #[test]
    fn test_execute_config_hostname_locahost() {
        let config = "
[ed_oralce_web1]
name=ed
target=oracle
hostname=web1
regex=^/bin/bash .*$

[ed_oracle_localhost]
name=ed
target=oracle
hostname=localhost
regex=^/bin/sh.*$
    "
        .to_string();

        let mut vec_eo: Vec<EnvOptions> = vec![];
        read_ini_config_str(&config, &mut vec_eo, "ed", false);
        let mut ro = RunOptions::new();
        ro.name = "ed".to_string();
        ro.target = "oracle".to_string();

        ro.command = "/bin/bash /usr/local/oracle/backup_script".to_string();
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, false);

        ro.hostname = "web1".to_string();
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, true);

        ro.hostname = "web2".to_string();
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, false);

        ro.hostname = "localhost".to_string();
        ro.command = "/bin/sh /usr/local/oracle/backup_script".to_string();
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, true);

        ro.hostname = "web1".to_string();
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, true);

        ro.hostname = "web2".to_string();
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, true);
    }

    #[test]
    fn test_missing_user() {
        let config = "
[missing_user]
target=oracle
hostname=localhost
regex=/bin/sh\\b.*
"
        .to_string();

        let mut vec_eo: Vec<EnvOptions> = vec![];
        read_ini_config_str(&config, &mut vec_eo, "ed", false);
        let mut ro = RunOptions::new();
        ro.name = "".to_string();
        ro.target = "oracle".to_string();

        assert_eq!(can(&vec_eo, &ro).unwrap().permit, false);
    }

    #[test]
    fn test_regex_line_anchor() {
        let config = "
[regex_anchor]
name=ed
target=oracle
hostname=localhost
regex=.*
"
        .to_string();

        let mut vec_eo: Vec<EnvOptions> = vec![];
        read_ini_config_str(&config, &mut vec_eo, "ed", false);
        let mut ro = RunOptions::new();
        ro.name = "ed".to_string();
        ro.target = "oracle".to_string();
        ro.command = "/bin/bash".to_string();

        assert_eq!(can(&vec_eo, &ro).unwrap().permit, true);
    }

    #[test]
    fn test_edit_apache() {
        let config = "
[ed_edit_root]
name=ed
target=root
notbefore=20200101
notafter=20201225
type = edit
regex = .*

[ed_edit_apache]
name=ed
target=oracle
permit=false
type = edit
regex = /etc/apache

[ed_edit_hosts]
name=ed
target=root
regex = /etc/hosts
type = edit

[user_all_todo]
name=m{}
target=^
type = edit
regex = ^"
            .to_string();

        let mut vec_eo: Vec<EnvOptions> = vec![];
        read_ini_config_str(&config, &mut vec_eo, "ed", false);
        let mut ro = RunOptions::new();
        ro.date = NaiveDate::from_ymd(2020, 1, 1).and_hms(0, 0, 0);
        ro.name = "ed".to_string();
        ro.target = "root".to_string();
        ro.acl_type = ACLTYPE::EDIT;
        ro.command = "/etc/apache/httpd2.conf".to_string();

        assert_eq!(can(&vec_eo, &ro).unwrap().permit, true);
    }

    #[test]
    fn test_edit_user_macro() {
        let config = "
[ed]
name=ed
target=root
regex =^/bin/cat /etc/%{USER}"
            .to_string();

        let mut vec_eo: Vec<EnvOptions> = vec![];
        read_ini_config_str(&config, &mut vec_eo, "ed", false);
        let mut ro = RunOptions::new();
        ro.date = NaiveDate::from_ymd(2020, 1, 1).and_hms(0, 0, 0);
        ro.name = "ed".to_string();
        ro.target = "root".to_string();
        ro.command = "/bin/cat /etc/ed".to_string();

        assert_eq!(can(&vec_eo, &ro).unwrap().permit, true);

        ro.name = "ned".to_string();
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, false);
    }

    #[test]
    fn test_parse_regex_fail() {
        let mut vec_eo: Vec<EnvOptions> = vec![];

        let config = "
[ed]
name=ed
target=root
regex = ^/bin/cat /etc/("
            .to_string();

        assert_eq!(read_ini_config_str(&config, &mut vec_eo, "ed", true), true);

        let mut vec_eo: Vec<EnvOptions> = vec![];
        let config = "
[ed]
name=ed
target=root
regex = ^/bin/cat /etc/
"
        .to_string();

        assert_eq!(read_ini_config_str(&config, &mut vec_eo, "ed", true), false);
    }

    #[test]
    fn test_group_assignment() {
        let config = "
[users]
name=users
group=true
target=root
notbefore=20200101
notafter=20201225
regex = ^.*$
"
        .to_string();

        let mut vec_eo: Vec<EnvOptions> = vec![];
        read_ini_config_str(&config, &mut vec_eo, "ed", false);
        let mut ro = RunOptions::new();
        ro.date = NaiveDate::from_ymd(2020, 1, 1).and_hms(0, 0, 0);
        ro.name = "ed".to_string();
        ro.target = "root".to_string();
        ro.command = "/bin/cat /etc/ed".to_string();

        assert_eq!(can(&vec_eo, &ro).unwrap().permit, false);

        ro.groups.insert(String::from("users"), 1);
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, true);

        ro.groups = HashMap::new();

        ro.groups.insert(String::from("wwwadm"), 1);
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, false);
    }

    #[test]
    fn test_list_other_user() {
        let config = "
[ed_all]
name=ed
notbefore=20200101
notafter=20201225
type = list
target = ^.*$

[bob_all]
name=bob
type=edit
target = ^.*$

[bob_all]
name=bob
type = list
permit=false
target = ^.*$

[meh_ed]
name=meh
type =list
target=^ed$

[root_all]
name=root
type=run
regex =^.*$

[ben_ops]
name=ben
permit=true
type=list
target = ^(eng|dba|net)ops$
"
        .to_string();

        let mut vec_eo: Vec<EnvOptions> = vec![];
        read_ini_config_str(&config, &mut vec_eo, "ed", false);
        let mut ro = RunOptions::new();
        ro.date = NaiveDate::from_ymd(2020, 1, 1).and_hms(0, 0, 0);
        ro.name = "ed".to_string();
        ro.target = "root".to_string();
        ro.command = "/bin/cat /etc/ed".to_string();
        ro.acl_type = ACLTYPE::LIST;

        assert_eq!(can(&vec_eo, &ro).unwrap().permit, true);

        ro.name = "meh".to_string();
        ro.target = "ed".to_string();
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, true);

        ro.target = "bob".to_string();
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, false);

        ro.target = "root".to_string();
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, false);

        ro.name = "bob".to_string();
        ro.target = "ed".to_string();
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, false);

        ro.name = "ben".to_string();
        ro.target = "dbaops".to_string();
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, true);
        ro.target = "engops".to_string();
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, true);

        ro.target = "netops".to_string();
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, true);

        ro.target = "wwwops".to_string();
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, false);
    }

    #[test]
    fn test_edit_regression() {
        let config = "
[www-data-bio]
name = root
group = true
permit = true
type = edit
require_pass = false
regex = ^/var/www/html/%{USER}.html
"
        .to_string();

        let mut vec_eo: Vec<EnvOptions> = vec![];
        read_ini_config_str(&config, &mut vec_eo, "ed", false);

        let mut ro = RunOptions::new();
        ro.date = NaiveDate::from_ymd(2020, 1, 1).and_hms(0, 0, 0);
        ro.name = "ed".to_string();
        ro.target = "root".to_string();
        ro.command = "/etc/please.ini".to_string();
        ro.acl_type = ACLTYPE::EDIT;

        assert_eq!(can(&vec_eo, &ro).unwrap().permit, false);

        ro.groups.insert(String::from("root"), 1);
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, false);

        ro.command = "/var/www/html/ed.html".to_string();
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, true);

        ro.command = "/var/www/html/%{USER}.html".to_string();
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, false);

        ro.groups = HashMap::new();
        ro.groups.insert(String::from("wwwadm"), 1);
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, false);
    }

    #[test]
    fn test_edit_user_expansion() {
        let config = "
[www-data-bio]
name = root
group = true
permit = true
type = edit
require_pass = false
regex = ^/var/www/html/%{USER}.html$
"
        .to_string();

        let mut vec_eo: Vec<EnvOptions> = vec![];
        read_ini_config_str(&config, &mut vec_eo, "ed", false);

        let mut ro = RunOptions::new();
        ro.name = "ed".to_string();
        ro.target = "root".to_string();
        ro.command = "/var/www/html/ed.html".to_string();
        ro.acl_type = ACLTYPE::EDIT;
        ro.groups.insert(String::from("root"), 1);

        assert_eq!(can(&vec_eo, &ro).unwrap().permit, true);
    }

    #[test]
    fn test_edit_user_expansion_unescaped() {
        let config = "
[www-data-bio]
name = root
group = true
permit = true
type = edit
require_pass = false
regex = ^/var/www/html/%USER.html$"
            .to_string();
        let mut vec_eo: Vec<EnvOptions> = vec![];
        read_ini_config_str(&config, &mut vec_eo, "ed", false);

        let mut ro = RunOptions::new();
        ro.name = "ed".to_string();
        ro.target = "root".to_string();
        ro.acl_type = ACLTYPE::EDIT;
        ro.command = "/var/www/html/ed.html".to_string();

        ro.groups.insert(String::from("root"), 1);
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, false);
    }

    #[test]
    fn test_edit_user_expansion_escapes() {
        let config = "
[www-data-bio]
name = root
group = true
permit = true
type = edit
require_pass = false
regex = ^/var/www/html/%{USER}.html$"
            .to_string();
        let mut vec_eo: Vec<EnvOptions> = vec![];
        read_ini_config_str(&config, &mut vec_eo, "ed", false);

        let mut ro = RunOptions::new();
        ro.name = "ed".to_string();
        ro.target = "root".to_string();
        ro.acl_type = ACLTYPE::EDIT;
        ro.command = "/var/www/html/ed.html".to_string();

        ro.groups.insert(String::from("root"), 1);
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, true);
    }

    #[test]
    fn test_target_regex() {
        let config = "
[ed_target_ot]
name = .*ot
group = true
target = .*ot
permit = true
require_pass = false
regex = /bin/bash"
            .to_string();

        let mut vec_eo: Vec<EnvOptions> = vec![];
        read_ini_config_str(&config, &mut vec_eo, "ed", false);
        assert_eq!(vec_eo.iter().next().unwrap().rule.as_str(), "/bin/bash");

        let mut ro = RunOptions::new();
        ro.name = "ed".to_string();
        ro.target = "root".to_string();
        ro.acl_type = ACLTYPE::RUN;
        ro.command = "/bin/bash".to_string();
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, false);

        ro.groups.insert(String::from("root"), 1);
        ro.command = "/bin/sh".to_string();
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, false);

        ro.command = "/bin/bash".to_string();
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, true);

        ro.target = "woot".to_string();
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, true);
    }

    #[test]
    fn test_edit_regression_empty() {
        let mut vec_eo: Vec<EnvOptions> = vec![];
        let config = "".to_string();
        read_ini_config_str(&config, &mut vec_eo, "ed", false);
        let mut ro = RunOptions::new();
        ro.name = "ed".to_string();
        ro.target = "root".to_string();
        ro.acl_type = ACLTYPE::EDIT;
        ro.command = "/etc/please.ini".to_string();
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, false);
    }

    #[test]
    fn test_dir_any() {
        let config = "
[regex_anchor]
name=ed
target=oracle
hostname=localhost
regex=.*
dir=.*
        "
        .to_string();

        let mut vec_eo: Vec<EnvOptions> = vec![];
        read_ini_config_str(&config, &mut vec_eo, "ed", false);
        let mut ro = RunOptions::new();
        ro.name = "ed".to_string();
        ro.target = "oracle".to_string();
        ro.acl_type = ACLTYPE::RUN;
        ro.command = "/bin/bash".to_string();

        assert_eq!(can(&vec_eo, &ro).unwrap().permit, true);

        ro.directory = "/".to_string();
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, true);
    }

    #[test]
    fn test_dir_fixed() {
        let config = "
[regex_anchor]
name=ed
target=oracle
hostname=localhost
regex=.*
dir=/var/www
        "
        .to_string();

        let mut vec_eo: Vec<EnvOptions> = vec![];
        read_ini_config_str(&config, &mut vec_eo, "ed", false);
        let mut ro = RunOptions::new();
        ro.date = NaiveDate::from_ymd(2020, 1, 1).and_hms(0, 0, 0);
        ro.name = "ed".to_string();
        ro.target = "oracle".to_string();
        ro.acl_type = ACLTYPE::RUN;
        ro.command = "/bin/bash".to_string();

        assert_eq!(
            can(&vec_eo, &ro).unwrap().permit,
            false,
            "no directory given",
        );

        ro.directory = "/".to_string();
        assert_eq!(
            can(&vec_eo, &ro).unwrap().permit,
            false,
            "change outside permitted",
        );

        ro.directory = "/var/www".to_string();
        assert_eq!(
            can(&vec_eo, &ro).unwrap().permit,
            true,
            "change to permitted"
        );
    }

    #[test]
    fn test_date_match() {
        let config = "
[regex_anchor]
name=ed
target=root
hostname=localhost
regex=.*
dir=.*
datematch=Fri.*UTC.*
"
        .to_string();

        let mut vec_eo: Vec<EnvOptions> = vec![];
        read_ini_config_str(&config, &mut vec_eo, "ed", false);
        let mut ro = RunOptions::new();
        ro.name = "ed".to_string();
        ro.date = NaiveDate::from_ymd(2020, 10, 02).and_hms(22, 0, 0);
        ro.target = "root".to_string();
        ro.acl_type = ACLTYPE::RUN;
        ro.command = "/bin/bash".to_string();

        assert_eq!(can(&vec_eo, &ro).unwrap().permit, true);

        ro.date = NaiveDate::from_ymd(2020, 10, 01).and_hms(22, 0, 0);
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, false);

        let config = "
[regex_anchor]
name=ed
target=root
hostname=localhost
regex=.*
dir=.*
datematch=Fri.*\\s22:00:00\\s+UTC\\s2020
"
        .to_string();

        let mut vec_eo: Vec<EnvOptions> = vec![];
        read_ini_config_str(&config, &mut vec_eo, "ed", false);
        ro.date = NaiveDate::from_ymd(2020, 10, 02).and_hms(21, 0, 0);
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, false);
        ro.date = NaiveDate::from_ymd(2020, 10, 02).and_hms(23, 0, 0);
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, false);
        ro.date = NaiveDate::from_ymd(2020, 10, 02).and_hms(22, 0, 0);
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, true);

        let config = "
[regex_anchor]
name=ed
target=root
hostname=localhost
regex=.*
dir=.*
datematch=Thu\\s+1\\s+Oct\\s+22:00:00\\s+UTC\\s+2020
"
        .to_string();

        let mut vec_eo: Vec<EnvOptions> = vec![];
        read_ini_config_str(&config, &mut vec_eo, "ed", false);
        ro.date = NaiveDate::from_ymd(2020, 10, 01).and_hms(21, 0, 0);
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, false);
        ro.date = NaiveDate::from_ymd(2020, 10, 01).and_hms(23, 0, 0);
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, false);
        ro.date = NaiveDate::from_ymd(2020, 10, 01).and_hms(22, 0, 0);
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, true);
    }

    #[test]
    fn test_edit_mode() {
        let config = "
[edit_filemode]
name=ed
target=root
regex=/etc/please.ini.*
type=edit
editmode=0644
"
        .to_string();

        let mut vec_eo: Vec<EnvOptions> = vec![];
        read_ini_config_str(&config, &mut vec_eo, "ed", false);
        let mut ro = RunOptions::new();
        ro.name = "ed".to_string();
        ro.target = "root".to_string();
        ro.acl_type = ACLTYPE::EDIT;
        ro.command = "/etc/please.ini".to_string();

        let entry = can(&vec_eo, &ro).unwrap();

        assert_eq!(entry.edit_mode, Some(420));
    }

    #[test]
    fn test_read_ini_config_file() {
        let mut vec_eo: Vec<EnvOptions> = vec![];
        assert_eq!(read_ini_config_file(".", &mut vec_eo, "ed", true), true);
        assert_eq!(read_ini_config_file("", &mut vec_eo, "ed", true), true);
        assert_eq!(
            read_ini_config_file("./faulty", &mut vec_eo, "ed", true),
            true
        );
    }

    #[test]
    fn test_last() {
        let config = "
[first]
name=ed
target=root
regex=/bin/bash
permit=false
last=true

[unreachable]
name=ed
target=root
regex=/bin/bash
permit=true
"
        .to_string();

        let mut vec_eo: Vec<EnvOptions> = vec![];
        read_ini_config_str(&config, &mut vec_eo, "ed", false);
        let mut ro = RunOptions::new();
        ro.name = "ed".to_string();
        ro.target = "root".to_string();
        ro.command = "/bin/bash".to_string();

        let entry = can(&vec_eo, &ro).unwrap();

        assert_eq!(entry.permit, false);
    }

    #[test]
    fn test_reason() {
        let config = "
[first]
name=ed
target=root
regex=/bin/bash
permit=false
reason=true
"
        .to_string();

        let mut vec_eo: Vec<EnvOptions> = vec![];
        read_ini_config_str(&config, &mut vec_eo, "ed", false);
        let mut ro = RunOptions::new();
        ro.name = "ed".to_string();
        ro.target = "root".to_string();
        ro.command = "/bin/bash".to_string();

        let entry = can(&vec_eo, &ro).unwrap();

        assert_eq!(entry.reason, true);
    }

    #[test]
    fn test_regex_build_user_expansion() {
        let regex_re = regex_build("/var/www/html/%{USER}/page.html", "ed", "/", "none").unwrap();

        assert_eq!(regex_re.as_str(), "^/var/www/html/ed/page.html$");
    }

    #[test]
    fn test_section_name() {
        let config = "
[first]
name=ed
target=root
regex=/bin/bash
permit=false
reason=true
"
        .to_string();

        let mut vec_eo: Vec<EnvOptions> = vec![];
        read_ini_config_str(&config, &mut vec_eo, "ed", false);
        let mut ro = RunOptions::new();
        ro.name = "ed".to_string();
        ro.target = "root".to_string();
        ro.command = "/bin/bash".to_string();

        let entry = can(&vec_eo, &ro).unwrap();

        assert_eq!(entry.section, "first");
    }

    #[test]
    fn test_multi_log() {
        let config = "
[first]
name=ed
target=root
regex=^/usr/bin/wc (/var/log/[a-zA-Z0-9-]+(\\.\\d+)?(\\s)?)+$
"
        .to_string();

        let mut vec_eo: Vec<EnvOptions> = vec![];
        read_ini_config_str(&config, &mut vec_eo, "ed", false);
        let mut ro = RunOptions::new();
        ro.name = "ed".to_string();
        ro.target = "root".to_string();

        ro.command = "/usr/bin/wc /var/log/messages /var/log/syslog /var/log/maillog".to_string();
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, true);

        ro.command = "/usr/bin/wc /var/log/messages /var/log/messages.1".to_string();
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, true);

        ro.command =
            "/usr/bin/wc /var/log/messages /var/log/syslog /var/log/maillog /var/log/../../shadow"
                .to_string();
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, false);

        ro.command = "/usr/bin/wc".to_string();
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, false);

        ro.command = "/usr/bin/wc /etc/shadow".to_string();
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, false);

        ro.command = "/usr/bin/wc".to_string();
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, false);

        ro.command = "/usr/bin/wc /var/log/messages /var/log/messages.1 /var/log/../../etc/shadow"
            .to_string();
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, false);
    }
}
