use regex::Regex;

use std::collections::HashMap;
use std::env;
use std::ffi::CStr;
use std::path::Path;
use std::process;
use std::time::SystemTime;
use syslog::{Facility, Formatter3164};

use chrono::{NaiveDate, NaiveDateTime, Utc};
use std::fs;
use std::fs::File;
use std::io::prelude::*;
use users::*;

#[derive(Clone)]
pub struct EnvOptions {
    pub name: Regex,
    pub rule: Regex,
    pub notbefore: Option<NaiveDateTime>,
    pub notafter: Option<NaiveDateTime>,
    pub target: Regex,
    pub hostname: Regex,
    pub permit: bool,
    pub require_pass: bool,
    pub env_list: Vec<String>,
    pub acl_type: ACLTYPE,
    pub file_name: String,
    pub section: String,
    pub group: bool,
    pub configured: bool,
    pub dir: Regex,
    pub exitcmd: Option<String>,
}

impl EnvOptions {
    pub fn new() -> EnvOptions {
        EnvOptions {
            name: Regex::new(&"^$").unwrap(),
            rule: Regex::new(&"^$").unwrap(),
            target: Regex::new(&"root").unwrap(),
            notbefore: None,
            notafter: None,
            hostname: Regex::new(&"localhost").unwrap(),
            env_list: vec![],
            file_name: "".to_string(),
            section: "".to_string(),
            permit: true,
            require_pass: true,
            acl_type: ACLTYPE::RUN,
            group: false,
            configured: false,
            dir: Regex::new(&"^.*$").unwrap(),
            exitcmd: None,
        }
    }
    fn new_deny() -> EnvOptions {
        let mut opt = EnvOptions::new();
        opt.permit = false;
        opt.rule = Regex::new(".").unwrap();
        opt.target = Regex::new("^$").unwrap();
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

fn regex_build(v: &str, user: &str, config_path: &str, section: &str) -> Option<Regex> {
    let rule = Regex::new(&format!("^{}$", &v.to_string().replace("%{USER}", &user)));
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
    let section_re = Regex::new(r"^\[(?P<section_name>[^\]]+)\]\s*$").unwrap();
    let definition = Regex::new(r"^(?P<key>[^=]+)\s*=\s*(?P<value>.*)\s*$").unwrap();
    let mut opt = EnvOptions::new();

    for line in conf.split('\n') {
        if line.trim() == "" || line.starts_with('#') {
            continue;
        }

        if let Some(cap) = section_re.captures(line) {
            in_section = true;
            section = cap["section_name"].trim().to_string();
            if opt.configured {
                vec_eo.push(opt);
            }
            opt = EnvOptions::new();
            opt.section = section.clone();
            opt.file_name = String::from(config_path);
            continue;
        }

        match definition.captures(line) {
            Some(cap) => {
                if !in_section {
                    println!("Error parsing {}:{}", config_path, line);
                    faulty = true;
                    continue;
                }
                let key = cap["key"].trim();
                let value = cap["value"].trim();

                match key {
                    "include" => {
                        if read_ini_config_file(&value, vec_eo, &user, fail_error) {
                            println!("Couldn't read {}", value);
                            return false;
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
                                    collect
                                        .push(file.unwrap().path().to_str().unwrap().to_string());
                                }
                                collect.sort();
                                for file in collect {
                                    let incf = file;
                                    if !can_dir_include(&incf) {
                                        continue;
                                    }
                                    if read_ini_config_file(&incf, vec_eo, &user, fail_error) {
                                        println!("Could not read {}", value);
                                        return false;
                                    }
                                }
                            }
                        }

                        continue;
                    }
                    "name" => match regex_build(value, user, config_path, &section) {
                        Some(check) => {
                            opt.name = check;
                            opt.configured = true;
                        }
                        None => {
                            faulty = true;
                        }
                    },
                    "hostname" => match regex_build(value, user, config_path, &section) {
                        Some(check) => {
                            opt.hostname = check;
                        }
                        None => {
                            faulty = true;
                        }
                    },
                    "target" => match regex_build(value, user, config_path, &section) {
                        Some(check) => {
                            opt.target = check;
                        }
                        None => {
                            faulty = true;
                        }
                    },
                    "permit" => opt.permit = value == "true",
                    "require_pass" => opt.require_pass = value != "false",
                    "type" => match value.to_lowercase().as_str() {
                        "edit" => opt.acl_type = ACLTYPE::EDIT,
                        "list" => opt.acl_type = ACLTYPE::LIST,
                        _ => opt.acl_type = ACLTYPE::RUN,
                    },
                    "group" => opt.group = value == "true",
                    "regex" => match regex_build(value, user, config_path, &section) {
                        Some(check) => {
                            opt.rule = check;
                        }
                        None => {
                            faulty = true;
                        }
                    },

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
                        opt.notbefore = Some(
                            parse_datetime_from_str(&value.to_string(), "%Y%m%d%H%M%S").unwrap(),
                        )
                    }
                    "notafter" if value.len() == 14 => {
                        opt.notafter = Some(
                            parse_datetime_from_str(&value.to_string(), "%Y%m%d%H%M%S").unwrap(),
                        )
                    }
                    "dir" => match regex_build(value, user, config_path, &section) {
                        Some(dir) => {
                            opt.dir = dir;
                        }
                        None => {
                            faulty = true;
                        }
                    },
                    "exitcmd" => {
                        if !value.is_empty() {
                            opt.exitcmd = Some(value.to_string());
                        }
                    }
                    &_ => {
                        println!("{}: unknown attribute \"{}\": {}", config_path, key, value);
                        faulty = true;
                    }
                }
            }
            None => {
                println!("Error parsing {}:{}", config_path, line);
                faulty = true;
                continue;
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
        Err(why) => panic!("couldn't open {}: {}", display, why),
        Ok(file) => file,
    };

    let mut s = String::new();
    match file.read_to_string(&mut s) {
        Err(why) => panic!("couldn't read {}: {}", display, why),
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

pub fn can(vec_eo: &[EnvOptions], ro: &RunOptions) -> Result<EnvOptions, ()> {
    let mut opt = EnvOptions::new_deny();

    for item in vec_eo {
        // println!("{}:", item.section);
        if item.notbefore.is_some() && item.notbefore.unwrap() > ro.date {
            // println!("{}: now is before date", item.section);
            continue;
        }

        if item.notafter.is_some() && item.notafter.unwrap() < ro.date {
            // println!("{}: now is after date", item.section);
            continue;
        }
        if !item.group && !item.name.is_match(&ro.name) {
            // println!("{}: skipping as not a name match ({}), group={}", item.section, item.name, item.group);
            continue;
        }

        if item.group {
            let mut found = false;
            for (k, _) in ro.groups.iter() {
                if item.name.is_match(&k.to_string()) {
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

        if item.acl_type != ro.acl_type {
            // println!("{}: not {:?} != {:?}", item.section, item.acl_type, ro.acl_type);
            continue;
        }

        if !item.hostname.is_match(&ro.hostname)
            && !item.hostname.is_match("any")
            && !item.hostname.is_match("localhost")
        {
            // println!("{}: hostname mismatch", item.section);
            continue;
        }

        if !item.dir.is_match(&ro.directory) {
            // && ro.directory != "." {
            continue;
        }

        if item.acl_type == ACLTYPE::LIST {
            if item.rule.is_match(&ro.target) {
                // println!("{}: is list", item.section);
                opt = item.clone();
            }
        } else {
            if !item.target.is_match(&ro.target) {
                // println!("{}: item target {} != target {}", item.section, item.target, ro.target);
                continue;
            }
            if item.rule.is_match(&ro.command) {
                // println!("{}: item rule is match", item.section);
                opt = item.clone();
            } else {
                // println!("{}: item rule ({}) is not a match for {}", item.section, item.rule, ro.command);
            }
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
        if !item.group && !item.name.is_match(&search_user) {
            continue;
        }

        if item.group {
            let mut found = false;
            for (k, _) in ro.groups.iter() {
                if item.name.is_match(&k) {
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

        if item.acl_type != ro.acl_type {
            continue;
        }

        if !item.permit {
            prefixes.push(String::from("not permitted"));
        }

        if !item.hostname.is_match(&ro.hostname)
            && !item.hostname.is_match("any")
            && !item.hostname.is_match("localhost")
        {
            continue;
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
            println!("    {}:{}list: {}", item.section, prefix, item.rule);
            continue;
        }

        println!(
            "    {}:{}{} (pass={},dirs={}): {}",
            item.section, prefix, item.target, item.require_pass, item.dir, item.rule
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

pub fn log_action(service: &str, result: &str, user: &str, target: &str, command: &str) -> bool {
    let formatter = Formatter3164 {
        facility: Facility::LOG_USER,
        hostname: None,
        process: service.into(),
        pid: process::id() as i32,
    };
    match syslog::unix(formatter) {
        Err(e) => println!("impossible to connect to syslog: {:?}", e),
        Ok(mut writer) => {
            writer
                .err(format!(
                    "user={} tty={} action={} target={} command={}",
                    user,
                    tty_name(),
                    result,
                    target,
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
    use std::collections::HashMap;

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
regex = ^.*

[ed_list]
name = (ed)
type = list
regex = %{USER}
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
regex = ^.*$

[bob_all]
name=bob
type=edit
regex = ^.*$

[bob_all]
name=bob
type = list
permit=false
regex = ^.*$

[meh_ed]
name=meh
type =list
regex=^ed$

[root_all]
name=root
type=run
regex =^.*$

[ben_ops]
name=ben
permit=true
type=list
regex = ^(eng|dba|net)ops$
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
".to_string();

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

        assert_eq!(
            vec_eo.iter().next().unwrap().rule.as_str(),
            "^^/var/www/html/ed.html$$"
        );

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

        assert_eq!(
            vec_eo.iter().next().unwrap().rule.as_str(),
            "^^/var/www/html/%USER.html$$"
        );

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

        assert_eq!(
            vec_eo.iter().next().unwrap().rule.as_str(),
            "^^/var/www/html/ed.html$$"
        );

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
        assert_eq!(vec_eo.iter().next().unwrap().rule.as_str(), "^/bin/bash$");

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
}
