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

use regex::Regex;

use std::collections::HashMap;
use std::env;
use std::ffi::{CStr, CString};
use std::path::Path;
use std::process;
use syslog::{Facility, Formatter3164};

use chrono::{NaiveDate, NaiveDateTime, Utc};
use std::fmt;
use std::fs;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::time::SystemTime;
use users::os::unix::UserExt;
use users::*;

use getopts::{Matches, Options};
use nix::unistd::{initgroups, setegid, seteuid, setgid, setuid};
use pam::Authenticator;

use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};

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
    pub original_uid: nix::unistd::Uid,
    pub original_gid: nix::unistd::Gid,
    pub target: String,
    pub command: String,
    pub original_command: Vec<String>,
    pub hostname: String,
    pub directory: Option<String>,
    pub groups: HashMap<String, u32>,
    pub date: NaiveDateTime,
    pub acl_type: ACLTYPE,
    pub reason: Option<String>,
    pub syslog: bool,
    pub prompt: bool,
    pub purge_token: bool,
    pub warm_token: bool,
    pub new_args: Vec<String>,
    pub old_umask: Option<nix::sys::stat::Mode>,
}

impl RunOptions {
    pub fn new() -> RunOptions {
        RunOptions {
            name: "root".to_string(),
            original_uid: nix::unistd::Uid::from_raw(get_current_uid()),
            original_gid: nix::unistd::Gid::from_raw(get_current_gid()),
            target: "".to_string(),
            command: "".to_string(),
            original_command: vec![],
            hostname: "localhost".to_string(),
            date: Utc::now().naive_utc(),
            groups: HashMap::new(),
            directory: None,
            acl_type: ACLTYPE::RUN,
            reason: None,
            syslog: true,
            prompt: true,
            purge_token: false,
            warm_token: false,
            new_args: vec![],
            old_umask: None,
        }
    }
}

impl Default for RunOptions {
    fn default() -> Self {
        Self::new()
    }
}

struct PamConvo {
    login: String,
    passwd: Option<String>,
    service: String,
}

impl pam::Converse for PamConvo {
    fn prompt_echo(&mut self, _msg: &CStr) -> Result<CString, ()> {
        CString::new(self.login.clone()).map_err(|_| ())
    }
    fn prompt_blind(&mut self, _msg: &CStr) -> Result<CString, ()> {
        self.passwd = Some(
            rpassword::read_password_from_tty(Some(&format!(
                "[{}] password for {}: ",
                self.service, self.login
            )))
            .unwrap(),
        );

        CString::new(self.passwd.clone().unwrap()).map_err(|_| ())
    }
    fn info(&mut self, _msg: &CStr) {}
    fn error(&mut self, msg: &CStr) {
        println!("[{} pam error] {}", self.service, msg.to_string_lossy());
    }
    fn username(&self) -> &str {
        &self.login
    }
}

#[derive(PartialEq, Eq, Clone, Debug)]
pub enum ACLTYPE {
    RUN,
    LIST,
    EDIT,
}

impl fmt::Display for ACLTYPE {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ACLTYPE::RUN => write!(f, "run"),
            ACLTYPE::LIST => write!(f, "list"),
            ACLTYPE::EDIT => write!(f, "edit"),
        }
    }
}

pub fn print_may_not(ro: &RunOptions) {
    println!(
        "You may not {} \"{}\" on {} as {}",
        if ro.acl_type == ACLTYPE::RUN {
            "execute".to_string()
        } else {
            ro.acl_type.to_string()
        },
        &ro.command,
        &ro.hostname,
        &ro.target
    );
}

/// build a regex and replace %{USER} with the user str, prefix with ^ and suffix with $
pub fn regex_build(
    v: &str,
    user: &str,
    config_path: &str,
    section: &str,
    line: Option<i32>,
) -> Option<Regex> {
    let rule = Regex::new(&format!("^{}$", &v.replace("%{USER}", &user)));
    if rule.is_err() {
        println!(
            "Error parsing {}{}",
            config_path,
            if line.is_some() {
                format!(": {}:{}", section, line.unwrap())
            } else {
                "".to_string()
            }
        );
        return None;
    }
    Some(rule.unwrap())
}

/// return true if the inclusion exists and ends with .ini
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

/// print the usage
pub fn print_usage(opts: &Options, header: &str) {
    println!("usage:");
    println!("{}", opts.usage(header));
}

/// added around easter time
pub fn credits(service: &str) {
    let mut contributors = [
        "All of the Debian Rust Maintainers, and especially Sylvestre Ledru",
        "Andy Kluger, for your feedback",
        "Cyrus Wyett, jim was better than ed",
        "@unmellow, for your early testing",
        "noproto, for your detailed report",
        "pin, for work with pkgsrc",
        "Stanley Dziegiel, for ini suggestions",
        "My wife and child, for putting up with me",
        "The SUSE Security Team, especially Matthias Gerstner",
    ];

    print_version(&service);

    contributors.sort();

    println!("\nWith thanks to the following teams and people, you got us where we are today.\n");
    println!("If your name is missing, or incorrect, please get in contact.\n");
    println!("In sort order:\n");

    for i in contributors.iter() {
        println!("\t{}", i);
    }

    println!("\nYou too of course, for motivating me.");
    println!("\nI thank you all for your help.\n\n\t-- Edward Neville");
}

/// common opt arguments
pub fn common_opt_arguments(
    matches: &Matches,
    opts: &Options,
    ro: &mut RunOptions,
    service: &str,
    header: &str,
) {
    ro.new_args = matches.free.clone();

    if matches.opt_present("r") {
        ro.reason = Some(matches.opt_str("r").unwrap());
    }
    if matches.opt_present("t") {
        ro.target = matches.opt_str("t").unwrap();
    }
    if matches.opt_present("u") {
        ro.target = matches.opt_str("u").unwrap();
    }

    if matches.opt_str("u").is_some()
        && matches.opt_str("t").is_some()
        && matches.opt_str("t").unwrap() != matches.opt_str("u").unwrap()
    {
        println!("Cannot use -t and -u with conflicting values");
        print_usage(&opts, &header);
        std::process::exit(1);
    }

    if matches.opt_present("p") {
        ro.purge_token = true;
    }
    if matches.opt_present("v") {
        print_version(&service);
        std::process::exit(0);
    }
    if matches.opt_present("w") {
        ro.warm_token = true;
    }

    if matches.opt_present("n") {
        ro.prompt = false;
    }
    if matches.opt_present("h") {
        if ro.new_args == ["credits"] {
            credits(&service);
            std::process::exit(0);
        }

        print_usage(&opts, &header);
        print_version(&service);
        std::process::exit(0);
    }

    if ro.purge_token {
        if !esc_privs() {
            std::process::exit(1);
        }
        remove_token(&ro.name);
        if !drop_privs(&ro) {
            std::process::exit(1);
        }
        std::process::exit(0);
    }

    if ro.warm_token {
        if ro.prompt {
            challenge_password(&ro, EnvOptions::new(), &service);
        }
        std::process::exit(0);
    }
}

/// read an ini file and traverse includes
pub fn read_ini(
    conf: &str,
    vec_eo: &mut Vec<EnvOptions>,
    user: &str,
    fail_error: bool,
    config_path: &str,
    bytes: &mut u64,
) -> bool {
    let parse_datetime_from_str = NaiveDateTime::parse_from_str;
    let parse_date_from_str = NaiveDate::parse_from_str;
    let mut faulty = false;
    let mut section = String::from("no section defined");
    let mut in_section = false;
    let mut opt = EnvOptions::new();
    let mut line_number = 0;

    for l in conf.split('\n') {
        line_number += 1;
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
            println!("Error parsing {}:{}", config_path, line_number);
            faulty = true;
            continue;
        }

        match key {
            "include" => {
                if !value.starts_with('/') {
                    println!("Includes should start with /");
                    return true;
                }
                if read_ini_config_file(&value, vec_eo, &user, fail_error, bytes) {
                    println!("Could not include file");
                    return true;
                }
                continue;
            }
            "includedir" => {
                if !value.starts_with('/') {
                    println!("Includes should start with /");
                    return true;
                }
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
                            if read_ini_config_file(&incf, vec_eo, &user, fail_error, bytes) {
                                println!("Could not include file");
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
                if fail_error
                    && regex_build(value, user, config_path, &section, Some(line_number)).is_none()
                {
                    faulty = true;
                }
            }
            "hostname" => {
                opt.hostname = Some(value.to_string());
                opt.configured = true;
                if fail_error
                    && regex_build(value, user, config_path, &section, Some(line_number)).is_none()
                {
                    faulty = true;
                }
            }
            "target" => {
                opt.target = value.to_string();
                if fail_error
                    && regex_build(value, user, config_path, &section, Some(line_number)).is_none()
                {
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
                if fail_error
                    && regex_build(value, user, config_path, &section, Some(line_number)).is_none()
                {
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
                if fail_error
                    && regex_build(value, user, config_path, &section, Some(line_number)).is_none()
                {
                    faulty = true;
                }
            }
            "dir" => {
                opt.dir = Some(value.to_string());
                if fail_error
                    && regex_build(value, user, config_path, &section, Some(line_number)).is_none()
                {
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
                println!("Error parsing {}:{}", config_path, line_number);
                faulty = true;
            }
        }
    }

    if opt.configured {
        vec_eo.push(opt);
    }

    fail_error && faulty
}

/// read through an ini config file, appending EnvOptions to vec_eo
/// hardcoded limit of 10M for confs
pub fn read_ini_config_file(
    config_path: &str,
    vec_eo: &mut Vec<EnvOptions>,
    user: &str,
    fail_error: bool,
    bytes: &mut u64,
) -> bool {
    let path = Path::new(config_path);
    let display = path.display();

    let file = match File::open(&path) {
        Err(why) => {
            println!("Could not open {}: {}", display, why);
            return true;
        }
        Ok(file) => file,
    };

    let byte_limit = 1024 * 1024 * 10;

    if *bytes >= byte_limit {
        println!("Exiting as too much config has already been read.");
        std::process::exit(1);
    }

    let mut s = String::new();
    let reader = BufReader::new(file).take(byte_limit).read_to_string(&mut s);
    *bytes += s.len() as u64;

    match reader {
        Ok(n) => {
            if n >= byte_limit as usize {
                println!("Exiting as too much config has already been read.");
                std::process::exit(1);
            }
        }
        Err(why) => {
            println!("Could not read {}: {}", display, why);
            return true;
        }
    }
    read_ini(&s, vec_eo, &user, fail_error, config_path, bytes)
}

pub fn read_ini_config_str(
    config: &str,
    vec_eo: &mut Vec<EnvOptions>,
    user: &str,
    fail_error: bool,
    bytes: &mut u64,
) -> bool {
    read_ini(&config, vec_eo, &user, fail_error, "static", bytes)
}

/// may we execute with this hostname
pub fn hostname_ok(item: &EnvOptions, ro: &RunOptions, line: Option<i32>) -> bool {
    if item.hostname.is_some() {
        let hostname_re = match regex_build(
            &item.hostname.as_ref().unwrap(),
            &ro.name,
            &item.file_name,
            &item.section,
            line,
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

/// may we execute with this directory
pub fn directory_check_ok(item: &EnvOptions, ro: &RunOptions, line: Option<i32>) -> bool {
    if item.dir.is_some() {
        let dir_re = match regex_build(
            &item.dir.as_ref().unwrap(),
            &ro.name,
            &item.file_name,
            &item.section,
            line,
        ) {
            Some(check) => check,
            None => {
                println!("Could not compile {}", &item.name);
                return false;
            }
        };

        if ro.directory.as_ref().is_none() {
            return false;
        }

        if (&ro.directory.as_ref()).is_some() && !dir_re.is_match(&ro.directory.as_ref().unwrap()) {
            // && ro.directory != "." {
            return false;
        }
        return true;
    }
    if ro.directory.is_some() {
        return false;
    }
    true
}

/// is the RunOption valid for the dates permitted in the EnvOption
pub fn permitted_dates_ok(item: &EnvOptions, ro: &RunOptions, line: Option<i32>) -> bool {
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
            line,
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

/// search the EnvOptions list for matching RunOptions and return the match
pub fn can(vec_eo: &[EnvOptions], ro: &RunOptions) -> Result<EnvOptions, ()> {
    let mut opt = EnvOptions::new_deny();
    let mut matched = false;

    for item in vec_eo {
        // println!("{}:", item.section);
        if item.acl_type != ro.acl_type {
            // println!("{}: not {:?} != {:?}", item.section, item.acl_type, ro.acl_type);
            continue;
        }

        if !permitted_dates_ok(&item, &ro, None) {
            continue;
        }

        let name_re = match regex_build(&item.name, &ro.name, &item.file_name, &item.section, None)
        {
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

        if !hostname_ok(&item, &ro, None) {
            continue;
        }

        if !directory_check_ok(&item, &ro, None) {
            continue;
        }

        let target_re =
            match regex_build(&item.target, &ro.name, &item.file_name, &item.section, None) {
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

            let rule_re =
                match regex_build(&item.rule, &ro.name, &item.file_name, &item.section, None) {
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

/// find editor for user. return /usr/bin/vi if EDITOR and VISUAL are unset
pub fn get_editor() -> String {
    let editor = "/usr/bin/vi";

    for prog in [String::from("VISUAL"), String::from("EDITOR")].iter() {
        if let Ok(val) = std::env::var(prog) {
            return val;
        }
    }

    editor.to_string()
}

/// handler.authenticate without the root privs part for linux
#[cfg(target_os = "linux")]
pub fn handler_shim<T: pam::Converse>(
    _ro: &RunOptions,
    handler: &mut Authenticator<T>,
) -> Result<(), pam::PamError> {
    handler.authenticate()
}

/// handler.authenticate needs esc_privs on netbsd
#[cfg(not(target_os = "linux"))]
pub fn handler_shim<T: pam::Converse>(
    ro: &RunOptions,
    handler: &mut Authenticator<T>,
) -> Result<(), pam::PamError> {
    if !esc_privs() {
        std::process::exit(1);
    }
    let auth = handler.authenticate();
    if !drop_privs(&ro) {
        std::process::exit(1);
    }
    auth
}

/// read password of user via rpassword
/// should pam require a password, and it is successful, then we set a token
pub fn challenge_password(ro: &RunOptions, entry: EnvOptions, service: &str) -> bool {
    if entry.require_pass {
        if tty_name().is_none() {
            println!("Cannot read password without tty");
            return false;
        }

        let mut retry_counter = 0;

        if !esc_privs() {
            std::process::exit(1);
        }

        if valid_token(&ro.name) {
            update_token(&ro.name);
            return true;
        }

        if !drop_privs(&ro) {
            std::process::exit(1);
        }

        if !ro.prompt {
            return false;
        }

        let convo = PamConvo {
            login: ro.name.to_string(),
            passwd: None,
            service: service.to_string(),
        };

        let mut handler = Authenticator::with_handler(service, convo).expect("Cannot init PAM");

        loop {
            let auth = handler_shim(&ro, &mut handler);

            if auth.is_ok() {
                if handler.get_handler().passwd.is_some() {
                    if !esc_privs() {
                        std::process::exit(1);
                    }

                    update_token(&ro.name);

                    if !drop_privs(&ro) {
                        std::process::exit(1);
                    }
                }
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

/// produce output list of acl
pub fn list(vec_eo: &[EnvOptions], ro: &RunOptions) {
    let search_user = if ro.target != "" {
        String::from(&ro.target)
    } else {
        String::from(&ro.name)
    };

    let mut last_file = "";

    for item in vec_eo {
        let name_re = match regex_build(&item.name, &ro.name, &item.file_name, &item.section, None)
        {
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

        if !hostname_ok(&item, &ro, None) {
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
            println!("  in file: {}", item.file_name);
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

/// if binary is not an absolute/relative path, look for it in usual places
pub fn search_path(binary: &str) -> Option<String> {
    let p = Path::new(binary);
    if binary.starts_with('/') || binary.starts_with("./") {
        if !p.exists() {
            return None;
        } else {
            return Some(binary.to_string());
        }
    }

    for dir in "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".split(':') {
        let path_name = format!("{}/{}", &dir, &binary);
        let p = Path::new(&path_name);

        if !p.exists() {
            continue;
        }
        return Some(path_name);
    }

    None
}

/// clean environment aside from ~half a dozen vars
pub fn clean_environment(ro: &mut RunOptions) {
    ro.old_umask = Some(nix::sys::stat::umask(
        nix::sys::stat::Mode::from_bits(0o077).unwrap(),
    ));
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

        if ro.acl_type == ACLTYPE::EDIT && (key == "EDITOR" || key == "VISUAL") {
            continue;
        }
        std::env::remove_var(key);
    }
}

/// set environment for helper scripts
pub fn set_environment(
    ro: &RunOptions,
    original_user: &User,
    original_uid: u32,
    lookup_name: &User,
) {
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

pub fn bad_priv_msg() {
    println!("I cannot set privs. Exiting as not installed correctly.");
}

/// set privs of usr to target_uid and target_gid. return false if fails
pub fn set_privs(user: &str, target_uid: nix::unistd::Uid, target_gid: nix::unistd::Gid) -> bool {
    let user = CString::new(user).unwrap();
    if initgroups(&user, target_gid).is_err() {
        bad_priv_msg();
        return false;
    }

    if setgid(target_gid).is_err() {
        bad_priv_msg();
        return false;
    }

    if setuid(target_uid).is_err() {
        bad_priv_msg();
        return false;
    }
    true
}

/// set privs of usr to target_uid and target_gid. return false if fails
pub fn set_eprivs(target_uid: nix::unistd::Uid, target_gid: nix::unistd::Gid) -> bool {
    if setegid(target_gid).is_err() {
        bad_priv_msg();
        return false;
    }
    if seteuid(target_uid).is_err() {
        bad_priv_msg();
        return false;
    }

    true
}

/// set privs (just call eprivs based on ro)
pub fn drop_privs(ro: &RunOptions) -> bool {
    esc_privs() && set_eprivs(ro.original_uid, ro.original_gid)
}

/// reset privs (just call eprivs based on root)
pub fn esc_privs() -> bool {
    set_eprivs(nix::unistd::Uid::from_raw(0), nix::unistd::Gid::from_raw(0))
}

/// return our best guess of what the user's tty is
pub fn tty_name() -> Option<String> {
    let mut ttyname = None;

    /* sometimes a tty isn't attached for all pipes FIXME: make this testable */
    unsafe {
        for n in 0..3 {
            let ptr = libc::ttyname(n);
            if ptr.is_null() {
                continue;
            }

            match CStr::from_ptr(ptr).to_str() {
                Err(_x) => ttyname = None,
                Ok(x) => ttyname = Some(x.to_string()),
            }
            break;
        }
    }

    ttyname
}

/// add a level of escape to strings when they go to the old as " holds entities
pub fn escape_log(message: &str) -> String {
    message.replace("\"", "\\\"")
}

/// write to syslog a standard log
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

    let cwd = match env::current_dir() {
        Err(_) => "unable to get cwd".to_string(),
        Ok(x) => x.to_string_lossy().to_string(),
    };

    match syslog::unix(formatter) {
        Err(e) => println!("Could not connect to syslog: {:?}", e),
        Ok(mut writer) => {
            let tty_name = tty_name();

            writer
                .err(format!(
                    "user=\"{}\" cwd=\"{}\" tty=\"{}\" action=\"{}\" target=\"{}\" type=\"{}\" reason=\"{}\" command=\"{}\"",
                    escape_log( &ro.name ),
                    escape_log( &cwd ),
                    if tty_name.is_none() {
                        "no_tty".to_string()
                    } else {
                        tty_name.unwrap()
                    },
                    result,
                    escape_log( &ro.target ),
                    ro.acl_type,
                    if ro.reason.as_ref().is_some() {
                        escape_log( &ro.reason.as_ref().unwrap() )
                    } else {
                        String::from("")
                    },
                    escape_log( command )
                ))
                .expect("could not write error message");
        }
    }
    false
}

/// return the directory that the token should use
pub fn token_dir() -> String {
    "/var/run/please/token".to_string()
}

/// return the path of the users token
pub fn token_path(user: &str) -> Option<String> {
    let tty_name = tty_name();
    tty_name.as_ref()?;
    let ppid = nix::unistd::getppid();
    Some(format!(
        "{}/{}:{}:{}",
        token_dir(),
        user,
        tty_name.unwrap().replace("/", "_"),
        ppid
    ))
}

pub fn create_token_dir() -> bool {
    if !Path::new(&token_dir()).is_dir() && fs::create_dir_all(&token_dir()).is_err() {
        println!("Could not create token directory");
        return false;
    }

    true
}

pub fn boot_secs() -> libc::timespec {
    let mut tp = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    #[cfg(target_os = "linux")]
    unsafe {
        libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut tp)
    };
    #[cfg(not(target_os = "linux"))]
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut tp)
    };
    tp
}

/// does the user have a valid token
/// return false if time stamp is in the future
/// return true if token was set within 600 seconds of wall and boot time
pub fn valid_token(user: &str) -> bool {
    if !create_token_dir() {
        return false;
    }

    let token_path = token_path(user);
    if token_path.is_none() {
        return false;
    }

    let secs = 600;

    let token_path = token_path.unwrap();
    match fs::metadata(token_path) {
        Ok(meta) => {
            match meta.modified() {
                Ok(t) => {
                    let tp = boot_secs();

                    match t.duration_since(SystemTime::UNIX_EPOCH) {
                        Ok(s) => {
                            if (tp.tv_sec as u64) < s.as_secs() {
                                // println!("tv_sec lower {} vs {}", tp.tv_sec, s.as_secs());
                                return false;
                            }
                            if ((tp.tv_sec as u64) - s.as_secs()) < secs {
                                // check the atime isn't older than 600 too

                                match SystemTime::now().duration_since(meta.accessed().unwrap()) {
                                    Ok(a) => return a.as_secs() <= secs,
                                    Err(_) => return false,
                                }
                            }
                        }
                        Err(_) => {
                            return false;
                        }
                    }

                    false
                }
                Err(_e) => false,
            }
        }
        Err(_) => false,
    }
}

/// touch the users token on disk
pub fn update_token(user: &str) {
    if !create_token_dir() {
        return;
    }

    let token_path = token_path(user);
    if token_path.is_none() {
        return;
    }

    let old_mode = nix::sys::stat::umask(nix::sys::stat::Mode::from_bits(0o077).unwrap());
    let token_path = token_path.unwrap();
    let token_path_tmp = format!("{}.tmp", &token_path);
    match fs::File::create(&token_path_tmp) {
        Ok(_x) => {}
        Err(x) => println!("Error creating token: {}", x),
    }
    nix::sys::stat::umask(old_mode);

    let tp = boot_secs();

    let tv_mtime = nix::sys::time::TimeVal::from(libc::timeval {
        tv_sec: tp.tv_sec,
        tv_usec: 0,
    });

    let tv_atime = nix::sys::time::TimeVal::from(libc::timeval {
        tv_sec: SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as libc::time_t,
        tv_usec: 0,
    });

    if nix::sys::stat::utimes(Path::new(&token_path_tmp), &tv_atime, &tv_mtime).is_err() {
        return;
    }

    if std::fs::rename(&token_path_tmp.as_str(), token_path).is_err() {
        return;
    }
}

/// remove from disk the users token
pub fn remove_token(user: &str) {
    if !create_token_dir() {
        return;
    }

    let token_location = token_path(&user);
    if token_location.is_none() {
        return;
    }

    let token_location = token_location.unwrap();

    let p = Path::new(&token_location);
    if p.is_file() {
        match fs::remove_file(p) {
            Ok(_x) => {}
            Err(x) => println!("Error removing token {}: {}", p.to_str().unwrap(), x),
        }
    }
}

/// turn group list into an indexed list
pub fn group_hash(groups: Vec<Group>) -> HashMap<String, u32> {
    let mut hm: HashMap<String, u32> = HashMap::new();
    for group in groups {
        hm.entry(String::from(group.name().to_string_lossy()))
            .or_insert_with(|| group.gid());
    }
    hm
}

/// escape ' ' within an argument
pub fn replace_new_args(new_args: Vec<String>) -> String {
    let mut args = vec![];
    for arg in &new_args {
        args.push(arg.replace(" ", "\\ "));
    }

    args.join(" ")
}

/// print version string
pub fn print_version(program: &str) {
    println!("{} version {}", &program, env!("CARGO_PKG_VERSION"));
}

/// return a lump of random alpha numeric characters
pub fn prng_alpha_num_string(n: usize) -> String {
    let rng = thread_rng();
    rng.sample_iter(&Alphanumeric).take(n).collect()
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

        let mut bytes = 0;
        let mut vec_eo: Vec<EnvOptions> = vec![];
        read_ini_config_str(&config, &mut vec_eo, "ed", false, &mut bytes);
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
        let mut bytes = 0;
        read_ini_config_str(&config, &mut vec_eo, "ed", false, &mut bytes);
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
        let mut bytes = 0;
        read_ini_config_str(&config, &mut vec_eo, &ro.name, false, &mut bytes);
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, false);

        ro.name = "other".to_string();
        ro.target = "thingy".to_string();
        let mut vec_eo: Vec<EnvOptions> = vec![];
        read_ini_config_str(&config, &mut vec_eo, &ro.name, false, &mut bytes);
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, true);

        ro.name = "other".to_string();
        ro.target = "oracle".to_string();
        let mut vec_eo: Vec<EnvOptions> = vec![];
        read_ini_config_str(&config, &mut vec_eo, &ro.name, false, &mut bytes);
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
        let mut bytes = 0;
        read_ini_config_str(&config, &mut vec_eo, "ed", false, &mut bytes);

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
        let mut bytes = 0;
        read_ini_config_str(&config, &mut vec_eo, "ed", false, &mut bytes);
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
        let mut bytes = 0;
        read_ini_config_str(&config, &mut vec_eo, "ed", false, &mut bytes);
        let mut ro = RunOptions::new();
        ro.name = "ed".to_string();
        ro.target = "root".to_string();

        let mut vec_eo: Vec<EnvOptions> = vec![];
        let mut bytes = 0;
        read_ini_config_str(&config, &mut vec_eo, "ed", false, &mut bytes);

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
        let mut bytes = 0;
        read_ini_config_str(&config, &mut vec_eo, "ed", false, &mut bytes);
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
        let mut bytes = 0;
        read_ini_config_str(&config, &mut vec_eo, "ed", false, &mut bytes);
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
        let mut bytes = 0;
        read_ini_config_str(&config, &mut vec_eo, "ed", false, &mut bytes);
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
        let mut bytes = 0;
        read_ini_config_str(&config, &mut vec_eo, "ed", false, &mut bytes);
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
        let mut bytes = 0;
        read_ini_config_str(&config, &mut vec_eo, "ed", false, &mut bytes);
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
        let mut bytes = 0;
        read_ini_config_str(&config, &mut vec_eo, "ed", false, &mut bytes);
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
        let mut bytes = 0;
        read_ini_config_str(&config, &mut vec_eo, "ed", false, &mut bytes);
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

        let mut bytes = 0;
        assert_eq!(
            read_ini_config_str(&config, &mut vec_eo, "ed", true, &mut bytes),
            true
        );

        let mut vec_eo: Vec<EnvOptions> = vec![];
        let config = "
[ed]
name=ed
target=root
regex = ^/bin/cat /etc/
"
        .to_string();

        let mut bytes = 0;
        assert_eq!(
            read_ini_config_str(&config, &mut vec_eo, "ed", true, &mut bytes),
            false
        );
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
        let mut bytes = 0;
        read_ini_config_str(&config, &mut vec_eo, "ed", false, &mut bytes);
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
        let mut bytes = 0;
        read_ini_config_str(&config, &mut vec_eo, "ed", false, &mut bytes);
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
        let mut bytes = 0;
        read_ini_config_str(&config, &mut vec_eo, "ed", false, &mut bytes);

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
        let mut bytes = 0;
        read_ini_config_str(&config, &mut vec_eo, "ed", false, &mut bytes);

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
        let mut bytes = 0;
        read_ini_config_str(&config, &mut vec_eo, "ed", false, &mut bytes);

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
        let mut bytes = 0;
        read_ini_config_str(&config, &mut vec_eo, "ed", false, &mut bytes);

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
        let mut bytes = 0;
        read_ini_config_str(&config, &mut vec_eo, "ed", false, &mut bytes);
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
        let mut bytes = 0;
        read_ini_config_str(&config, &mut vec_eo, "ed", false, &mut bytes);
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
        let mut bytes = 0;
        read_ini_config_str(&config, &mut vec_eo, "ed", false, &mut bytes);
        let mut ro = RunOptions::new();
        ro.name = "ed".to_string();
        ro.target = "oracle".to_string();
        ro.acl_type = ACLTYPE::RUN;
        ro.command = "/bin/bash".to_string();

        assert_eq!(can(&vec_eo, &ro).unwrap().permit, false);

        ro.directory = Some("/".to_string());
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
        let mut bytes = 0;
        read_ini_config_str(&config, &mut vec_eo, "ed", false, &mut bytes);
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

        ro.directory = Some("/".to_string());
        assert_eq!(
            can(&vec_eo, &ro).unwrap().permit,
            false,
            "change outside permitted",
        );

        ro.directory = Some("/var/www".to_string());
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, true, "permitted");
    }

    #[test]
    fn test_dir_tmp() {
        let config = "
[regex_anchor]
name=ed
target=root
regex=/bin/bash
dir=/tmp
        "
        .to_string();

        let mut vec_eo: Vec<EnvOptions> = vec![];
        let mut bytes = 0;
        read_ini_config_str(&config, &mut vec_eo, "ed", false, &mut bytes);
        let mut ro = RunOptions::new();
        ro.date = NaiveDate::from_ymd(2020, 1, 1).and_hms(0, 0, 0);
        ro.name = "ed".to_string();
        ro.target = "root".to_string();
        ro.acl_type = ACLTYPE::RUN;
        ro.command = "/bin/bash".to_string();
        ro.directory = Some("/tmp".to_string());

        assert_eq!(can(&vec_eo, &ro).unwrap().permit, true, "dir_tmp",);
    }

    #[test]
    fn test_dir_given_but_none_in_match() {
        let config = "
[regex_anchor]
name=ed
target=oracle
hostname=localhost
regex=.*
        "
        .to_string();

        let mut vec_eo: Vec<EnvOptions> = vec![];
        let mut bytes = 0;
        read_ini_config_str(&config, &mut vec_eo, "ed", false, &mut bytes);
        let mut ro = RunOptions::new();
        ro.date = NaiveDate::from_ymd(2020, 1, 1).and_hms(0, 0, 0);
        ro.name = "ed".to_string();
        ro.target = "oracle".to_string();
        ro.acl_type = ACLTYPE::RUN;
        ro.command = "/bin/bash".to_string();
        ro.directory = Some("/".to_string());

        assert_eq!(can(&vec_eo, &ro).unwrap().permit, false, "directory given",);

        ro.directory = Some("".to_string());
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, false, "directory given",);
    }

    #[test]
    fn test_date_match() {
        let config = "
[regex_anchor]
name=ed
target=root
hostname=localhost
regex=.*
datematch=Fri.*UTC.*
"
        .to_string();

        let mut vec_eo: Vec<EnvOptions> = vec![];
        let mut bytes = 0;
        read_ini_config_str(&config, &mut vec_eo, "ed", false, &mut bytes);
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
datematch=Fri.*\\s22:00:00\\s+UTC\\s2020
"
        .to_string();

        let mut vec_eo: Vec<EnvOptions> = vec![];
        let mut bytes = 0;
        read_ini_config_str(&config, &mut vec_eo, "ed", false, &mut bytes);
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
datematch=Thu\\s+1\\s+Oct\\s+22:00:00\\s+UTC\\s+2020
"
        .to_string();

        let mut vec_eo: Vec<EnvOptions> = vec![];
        let mut bytes = 0;
        read_ini_config_str(&config, &mut vec_eo, "ed", false, &mut bytes);
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
        let mut bytes = 0;
        read_ini_config_str(&config, &mut vec_eo, "ed", false, &mut bytes);
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
        let mut bytes = 0;
        assert_eq!(
            read_ini_config_file(".", &mut vec_eo, "ed", true, &mut bytes),
            true
        );
        assert_eq!(
            read_ini_config_file("", &mut vec_eo, "ed", true, &mut bytes),
            true
        );
        assert_eq!(
            read_ini_config_file("./faulty", &mut vec_eo, "ed", true, &mut bytes),
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
        let mut bytes = 0;
        read_ini_config_str(&config, &mut vec_eo, "ed", false, &mut bytes);
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
        let mut bytes = 0;
        read_ini_config_str(&config, &mut vec_eo, "ed", false, &mut bytes);
        let mut ro = RunOptions::new();
        ro.name = "ed".to_string();
        ro.target = "root".to_string();
        ro.command = "/bin/bash".to_string();

        let entry = can(&vec_eo, &ro).unwrap();

        assert_eq!(entry.reason, true);
    }

    #[test]
    fn test_regex_build_user_expansion() {
        let regex_re =
            regex_build("/var/www/html/%{USER}/page.html", "ed", "/", "none", None).unwrap();

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
        let mut bytes = 0;
        read_ini_config_str(&config, &mut vec_eo, "ed", false, &mut bytes);
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
        let mut bytes = 0;
        read_ini_config_str(&config, &mut vec_eo, "ed", false, &mut bytes);
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

    #[test]
    fn test_edit_group_regression() {
        let config = "
[please_ini]
name = lpadmin
group = true
regex = /etc/please.ini
reason = true
type = edit
exitcmd = /usr/bin/please -c %{NEW}
"
        .to_string();
        let mut vec_eo: Vec<EnvOptions> = vec![];
        let mut bytes = 0;
        read_ini_config_str(&config, &mut vec_eo, "ed", false, &mut bytes);
        let mut ro = RunOptions::new();
        ro.name = "ed".to_string();
        ro.target = "root".to_string();
        ro.groups.insert(String::from("lpadmin"), 1);
        ro.acl_type = ACLTYPE::EDIT;
        ro.command = "/etc/please.ini".to_string();
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, true);
    }

    #[test]
    fn test_ini_relative() {
        let mut vec_eo: Vec<EnvOptions> = vec![];
        let config = "
[inc]
include = ./some.ini
"
        .to_string();
        let mut bytes: u64 = 0;
        assert_eq!(
            read_ini_config_str(&config, &mut vec_eo, "ed", false, &mut bytes),
            true
        );

        let config = "
[inc]
includedir = ./dir.d/some.ini
"
        .to_string();
        assert_eq!(
            read_ini_config_str(&config, &mut vec_eo, "ed", false, &mut bytes),
            true
        );

        let config = "
[inc]
includedir = /dev/null
"
        .to_string();
        assert_eq!(
            read_ini_config_str(&config, &mut vec_eo, "ed", false, &mut bytes),
            false
        );
    }

    #[test]
    fn test_argument_replace() {
        assert_eq!(
            replace_new_args(vec![
                "/bin/bash".to_string(),
                "-c".to_string(),
                "/bin/id".to_string(),
                "you're not the boss of me".to_string()
            ]),
            "/bin/bash -c /bin/id you're\\ not\\ the\\ boss\\ of\\ me"
        );
    }
    #[test]
    fn test_syslog_format() {
        assert_eq!(
            escape_log(&"multiple \"strings\""),
            "multiple \\\"strings\\\"".to_string()
        );
    }

    #[test]
    fn test_prng_alpha_num_string() {
        assert_eq!(prng_alpha_num_string(2).len(), 2);
    }
}
