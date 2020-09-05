use regex::Regex;

use std::collections::HashMap;
use std::env;
use std::ffi::CStr;
use std::path::Path;
use std::io::prelude::*;
use std::fs;
use std::process;
use syslog::{Facility, Formatter3164};
use std::time::SystemTime;

use chrono::{NaiveDate, NaiveDateTime};
use ini::Ini;
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
    pub edit: bool,
    pub file_name: String,
    pub section: String,
    pub list: bool,
    pub group: bool,
}

impl EnvOptions {
    fn new() -> EnvOptions {
        EnvOptions {
            name: Regex::new(&"^$").unwrap(),
            rule: Regex::new(&"^$").unwrap(),
            target: Regex::new(&"root").unwrap(),
            /*
            notbefore: Option::Some(NaiveDate::from_ymd(1970, 1, 1).and_hms(0, 0, 0)),
            notafter: Option::Some(NaiveDate::from_ymd(2038, 1, 19).and_hms(3, 14, 7)),
            */
            notbefore: None,
            notafter: None,
            hostname: Regex::new(&"localhost").unwrap(),
            env_list: vec![],
            file_name: "".to_string(),
            section: "".to_string(),
            permit: true,
            require_pass: true,
            edit: false,
            list: false,
            group: false,
        }
    }
    fn new_deny() -> EnvOptions {
        let mut opt = EnvOptions::new();
        opt.permit = false;
        opt.rule = Regex::new(".").unwrap();
        opt.target = Regex::new("^$").unwrap();
        opt.edit = true;
        opt
    }
}

fn regex_build( v: &str, user: &str, config_path: &str, section: &str ) -> Option<Regex> {
    let rule = Regex::new( &format!("^{}$", &v.to_string().replace("%{USER}", &user) ));
    if rule.is_err() {
        println!( "Error parsing {}:{}, {}", config_path, section, v.to_string());
        return None;
    }
    Some(rule.unwrap())
}

pub fn read_ini(
    conf: &ini::ini::Ini,
    vec_eo: &mut Vec<EnvOptions>,
    user: &str,
    fail_error: bool,
    config_path: &str,
) -> bool {
    let parse_datetime_from_str = NaiveDateTime::parse_from_str;
    let parse_date_from_str = NaiveDate::parse_from_str;
    let mut faulty = false;
    let mut section = String::from("no section defined");

    for (sec, prop) in conf.iter() {
        let mut opt = EnvOptions::new();
        match sec {
            Some(x) => section = x.to_string(),
            None => {}
        }
        opt.file_name = String::from(config_path);
        opt.section = section.clone();
        for (k, v) in prop.iter() {
            match k.as_ref() {
                "name" | "user" => {
                    match regex_build(v, user, config_path, &section) {
                        Some(check) => {
                            opt.name = check;
                        },
                        None => {
                            faulty = true;
                        }
                    }
                },
                "hostname" => {
                    match regex_build(v, user, config_path, &section) {
                        Some(check) => {
                            opt.hostname = check;
                        },
                        None => {
                            faulty = true;
                        }
                    }
                },
                "target" => {
                    match regex_build(v, user, config_path, &section) {
                        Some(check) => {
                            opt.target = check;
                        },
                        None => {
                            faulty = true;
                        }
                    }
                },
                "permit" => opt.permit = v == "true",
                "require_pass" => opt.require_pass = v != "false",
                "edit" => opt.edit = v == "true",
                "list" => opt.list = v == "true",
                "group" => opt.group = v == "true",
                "regex" => {
                    match regex_build(v, user, config_path, &section) {
                        Some(check) => {
                            opt.rule = check;
                        },
                        None => {
                            faulty = true;
                        }
                    }
                }

                "notbefore" if v.len() == 8 => {
                    opt.notbefore = Some(parse_date_from_str(&v.to_string(), "%Y%m%d")
                        .unwrap()
                        .and_hms(0, 0, 0))
                }
                "notafter" if v.len() == 8 => {
                    opt.notafter = Some(parse_date_from_str(&v.to_string(), "%Y%m%d")
                        .unwrap()
                        .and_hms(23, 59, 59))
                }
                "notbefore" if v.len() == 14 => {
                    opt.notbefore =
                        Some( parse_datetime_from_str(&v.to_string(), "%Y%m%d%H%M%S").unwrap())
                }
                "notafter" if v.len() == 14 => {
                    opt.notafter = Some(parse_datetime_from_str(&v.to_string(), "%Y%m%d%H%M%S").unwrap())
                }

                &_ => {
                    println!("{}: unknown attribute \"{}\": {}", config_path, k, v);
                    faulty = true;
                }
            }
        }
        /*
        println!("Name: {}", opt.name);
        println!("Target: {}", opt.target);
        println!("Hostname: {}", opt.hostname);
        println!("Rule: {}", opt.rule);
        println!("Permit: {}", opt.permit);
        */
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
    let conf = Ini::load_from_file(config_path);
    match conf {
        Err(x) => {
            println!("cannot open {}:{}", config_path, x);
            std::process::exit(1);
        }
        Ok(x) => {
            read_ini(&x, vec_eo, &user, fail_error, config_path)
        }
    }
}

pub fn read_ini_config_str(
    config_path: &str,
    vec_eo: &mut Vec<EnvOptions>,
    user: &str,
    fail_error: bool,
) -> bool {
    let conf = Ini::load_from_str(&config_path);
    match conf {
        Err(x) => {
            println!("cannot open {}:{}", config_path, x);
            std::process::exit(1);
        }
        Ok(x) => {
            read_ini(&x, vec_eo, &user, fail_error, "static")
        }
    }
}

pub fn can_run(
    vec_eo: &Vec<EnvOptions>,
    user: &str,
    target: &str,
    date: &NaiveDateTime,
    hostname: &str,
    command: &str,
    group_list: &HashMap<String, u32>,
) -> Result<EnvOptions, ()> {
    can(
        vec_eo,
        &user,
        &target,
        &date,
        &hostname,
        &command,
        false,
        false,
        &group_list,
    )
}

pub fn can_edit(
    vec_eo: &Vec<EnvOptions>,
    user: &str,
    target: &str,
    date: &NaiveDateTime,
    hostname: &str,
    command: &str,
    group_list: &HashMap<String, u32>,
) -> Result<EnvOptions, ()> {
    can(
        vec_eo,
        &user,
        &target,
        &date,
        &hostname,
        &command,
        true,
        false,
        &group_list,
    )
}

pub fn can_list(
    vec_eo: &Vec<EnvOptions>,
    user: &str,
    target: &str,
    date: &NaiveDateTime,
    hostname: &str,
    command: &str,
    group_list: &HashMap<String, u32>,
) -> Result<EnvOptions, ()> {
    can(
        vec_eo,
        &user,
        &target,
        &date,
        &hostname,
        &command,
        false,
        true,
        &group_list,
    )
}

pub fn can(
    vec_eo: &Vec<EnvOptions>,
    user: &str,
    target: &str,
    date: &NaiveDateTime,
    hostname: &str,
    command: &str,
    edit: bool,
    command_list: bool,
    group_list: &HashMap<String, u32>,
) -> Result<EnvOptions, ()> {
    let mut opt = EnvOptions::new_deny();

    for item in vec_eo {
        //println!("{}:", item.section);
        if item.notbefore.is_some() && item.notbefore.unwrap() > *date {
            //println!("{}: now is before date", item.section);
            continue;
        }

        if item.notafter.is_some() && item.notafter.unwrap() < *date {
            //println!("{}: now is after date", item.section);
            continue;
        }
        if !item.group && !item.name.is_match(user) {
            //println!("{}: not name match", item.section);
            continue;
        }

        if item.group {
            let mut found = false;
            for (k,_) in group_list.iter() {
                if item.name.is_match(&k) {
                    //println!("{}: {} matches group {}", item.section,item.name, k);
                    found = true;
                    break;
                }
            }
            if !found {
                //println!("{}: did not find a group name match",item.section);
                continue;
            }
        }

        if item.list != command_list {
            //println!("{}: not list, {} != {}", item.section, item.list, command_list);
            continue;
        }

        if item.edit != edit {
            //println!("{}: item is for edit", item.section);
            continue;
        }

        if !item.hostname.is_match(hostname) && !item.hostname.is_match("any") && !item.hostname.is_match("localhost") {
            //println!("{}: hostname mismatch", item.section);
            continue;
        }

        if command_list {
            if item.rule.is_match(target) {
                //println!("{}: is list", item.section);
                opt = item.clone();
            }
        } else {
            if !item.target.is_match(target) {
                //println!("{}: item target {} != target {}", item.section, item.target, target);
                continue;
            }
            if item.rule.is_match(command) {
                //println!("{}: item rule is match", item.section);
                opt = item.clone();
            }
            else {
                //println!("{}: item rule ({}) is not a match for {}", item.section, item.rule, command);
            }
        }
        //println!("didn't match");
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
        if let Ok(val) = std::env::var(prog) { return val; }
    }

    editor.to_string()
}

pub fn challenge_password(user: String, entry: EnvOptions, service: &str) -> bool {
    if entry.require_pass {
        let mut retry_counter = 0;
        if valid_token(&user) {
            update_token(&user);
            return true;
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

pub fn list_edit(
    vec_eo: &Vec<EnvOptions>,
    user: &str,
    date: &NaiveDateTime,
    hostname: &str,
    target: &str,
    group_list: &HashMap<String, u32>,
) {
    list(vec_eo, &user, &date, &hostname, true, &target, &group_list);
}

pub fn list_run(
    vec_eo: &Vec<EnvOptions>,
    user: &str,
    date: &NaiveDateTime,
    hostname: &str,
    target: &str,
    group_list: &HashMap<String, u32>,
) {
    list(vec_eo, &user, &date, &hostname, false, &target, &group_list);
}

pub fn list(
    vec_eo: &Vec<EnvOptions>,
    user: &str,
    date: &NaiveDateTime,
    hostname: &str,
    edit: bool,
    target: &str,
    group_list: &HashMap<String, u32>,
) {
    let search_user = if target != "" { String::from(target) } else { String::from(user) };
    
    let mut last_file = "";

    for item in vec_eo {
        if !item.group && !item.name.is_match(&search_user) {
            continue;
        }

        if item.group {
            let mut found = false;
            for (k,_) in group_list.iter() {
                if item.name.is_match(&k) {
                    found = true;
                    break;
                }
            }
            if found {
                continue;
            }
        }

        let mut prefixes = vec![];
        if item.notbefore.is_some() && item.notbefore.unwrap() > *date {
            prefixes.push(format!("upcomming({})", item.notbefore.unwrap()));
        }

        if item.notafter.is_some() && item.notafter.unwrap() < *date {
            prefixes.push(format!("expired({})", item.notafter.unwrap()));
        }

        if item.edit != edit {
            continue;
        }

        if !item.permit {
            prefixes.push(String::from("not permitted"));
        }

        if !item.hostname.is_match(hostname) && !item.hostname.is_match("any") && !item.hostname.is_match("localhost") {
            continue;
        }
        let mut prefix = prefixes.join(", ");
        if !prefix.is_empty() {
            if !item.list {
                prefix = format!(" {} as ", prefix);
            } else {
                prefix = format!(" {} to ", prefix);
            }
        }
        if last_file != item.file_name {
            println!("file: {}", item.file_name);
            last_file = &item.file_name;
        }

        if item.list {
            println!("  {}:{}list: {}", item.section, prefix, item.rule);
            continue;
        }

        println!(
            "  {}:{}{}: {}",
            item.section, prefix, item.target, item.rule
        );
    }
}

pub fn search_path(binary: &str) -> Option<String> {
    let p = Path::new(binary);
    if binary.starts_with('/') || binary.starts_with("./") {
        if !p.exists() {
            return None;
        }
        else {
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
                    user, tty_name(), result, target, command
                ))
                .expect("could not write error message");
        }
    }
    false
}

pub fn token_dir() -> String {
    "/var/run/please/token".to_string()
}

pub fn token_path( user: &str ) -> String {
    let ppid = nix::unistd::getppid();
    return format!("{}/{}:{}:{}", token_dir(), user, tty_name().replace("/","_"),ppid);

}

pub fn valid_token( user: &str ) -> bool {
    if !Path::new(&token_dir()).is_dir() {
        if fs::create_dir_all(&token_dir()).is_err() {
            return false
        }
    }

    match fs::metadata( token_path( user ) ) {
        Ok(meta) => {
            match meta.modified() {
                Ok(t) => {
                    match SystemTime::now().duration_since( t ) {
                        Ok(d) => {
                            if d.as_secs() < 600 {
                                return true;
                            }
                            return false;
                        }
                        Err(_e) => { return false; }
                    }
                }
                Err(_e) => { return false; }
            }

            return false;
        },
        Err(_) => { return false; }
    }
}

pub fn update_token( user: &str) {
    if !Path::new(&token_dir()).is_dir() {
        if fs::create_dir_all(&token_dir()).is_err() {
            return;
        }
    }

    fs::File::create(token_path(&user));
}

pub fn remove_token( user: &str ) {
    if !Path::new(&token_dir()).is_dir() {
        if fs::create_dir_all(&token_dir()).is_err() {
            return;
        }
    }

    fs::remove_file(token_path(&user));
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
user=ed
target=root
notbefore=20200101
notafter=20201225
regex =^.*$
[ed_false_oracle]
user=ed
target=oracle
permit=false
regex=^/bin/bash .*$

[ed_root_bash_all]
user=ed
target=root
regex=^/bin/bash .*$
[user_m_all_todo]
user=m{}
target=
regex=^ "
            .to_string();

        let date: NaiveDateTime = NaiveDate::from_ymd(2020, 1, 1).and_hms(0, 0, 0);
        let mut vec_eo: Vec<EnvOptions> = vec![];
        read_ini_config_str(&config, &mut vec_eo, "ed", false);
        let group_hash: HashMap<String, u32> = HashMap::new();

        assert_eq!(
            can_run(
                &vec_eo,
                "ed",
                "root",
                &date,
                "localhost",
                "/bin/bash",
                &group_hash
            )
            .unwrap()
            .permit,
            true
        );
    }

    #[test]
    fn test_execute_user_does_not_exist() {
        let config = "[ed_root_all]
user=ed
target=root
notbefore=20200101
notafter=20201225
regex= ^.*$
[ed_oracle_bash]
user=ed
target=oracle
regex=^/bin/bash .*$
[ed_root_bash]
user=ed
target=root
regex=^/bin/bash .*$
[user_all_todo]
user=.*
target=thingy
regex=^/bin/bash"
            .to_string();

        let date: NaiveDateTime = NaiveDate::from_ymd(2019, 12, 31).and_hms(0, 0, 0);

        let mut vec_eo: Vec<EnvOptions> = vec![];
        read_ini_config_str(&config, &mut vec_eo, "ed", false);
        let group_hash: HashMap<String, u32> = HashMap::new();

        assert_eq!(
            can_run(
                &vec_eo,
                "gone",
                "root",
                &date,
                "localhost",
                "/bin/bash",
                &group_hash
            )
            .unwrap()
            .permit,
            false
        );
        assert_eq!(
            can_run(
                &vec_eo,
                "gone",
                "thingy",
                &date,
                "localhost",
                "/bin/bash",
                &group_hash
            )
            .unwrap()
            .permit,
            true
        );

    }

    #[test]
    fn test_execute_config_too_early() {
        let config = "
[ed]
user=ed
target=root
notbefore=20200101
notafter=20201225
regex =^.*$
[ed_oracle]
user=ed
target=oracle ^/bin/bash .*$
[ed_dated]
user=ed
target=root
notafter=20200125
notbefore=20200101
regex =^
[user_all_todo]
user=m{}
target=^ "
            .to_string();

        let mut vec_eo: Vec<EnvOptions> = vec![];
        read_ini_config_str(&config, &mut vec_eo, "ed", false);
        let group_hash: HashMap<String, u32> = HashMap::new();

        assert_eq!(
            can_run(
                &vec_eo,
                "ed",
                "root",
                &NaiveDate::from_ymd(2019, 12, 31).and_hms(0, 0, 0),
                "localhost",
                "/bin/bash",
                &group_hash
            )
            .unwrap()
            .permit,
            false
        );
        assert_eq!(
            can_run(
                &vec_eo,
                "ed",
                "root",
                &NaiveDate::from_ymd(2020, 12, 25).and_hms(0, 0, 0),
                "localhost",
                "/bin/bash",
                &group_hash
            )
            .unwrap()
            .permit,
            true
        );
        assert_eq!(
            can_run(
                &vec_eo,
                "ed",
                "root",
                &NaiveDate::from_ymd(2020, 12, 25).and_hms(1, 0, 0),
                "localhost",
                "/bin/bash",
                &group_hash
            )
            .unwrap()
            .permit,
            true
        );
    }

    #[test]
    fn test_execute_config_too_early_long() {
        let config = "
[ed_too_early]        
user=ed
target=root
notbefore=20200808
notafter=20200810235959
regex=^.*
    "
        .to_string();

        let mut vec_eo: Vec<EnvOptions> = vec![];
        read_ini_config_str(&config, &mut vec_eo, "ed", false);
        let group_hash: HashMap<String, u32> = HashMap::new();

        assert_eq!(
            can_run(
                &vec_eo,
                "ed",
                "root",
                &NaiveDate::from_ymd(2020, 8, 8).and_hms(0, 0, 0),
                "localhost",
                "/bin/bash",
                &group_hash
            )
            .unwrap()
            .permit,
            true
        );
        assert_eq!(
            can_run(
                &vec_eo,
                "ed",
                "root",
                &NaiveDate::from_ymd(2020, 8, 10).and_hms(0, 0, 0),
                "localhost",
                "/bin/bash",
                &group_hash
            )
            .unwrap()
            .permit,
            true
        );
        assert_eq!(
            can_run(
                &vec_eo,
                "ed",
                "root",
                &NaiveDate::from_ymd(2020, 8, 10).and_hms(23, 59, 59),
                "localhost",
                "/bin/bash",
                &group_hash
            )
            .unwrap()
            .permit,
            true
        );
        assert_eq!(
            can_run(
                &vec_eo,
                "ed",
                "root",
                &NaiveDate::from_ymd(2020, 8, 11).and_hms(0, 0, 0),
                "localhost",
                "/bin/bash",
                &group_hash
            )
            .unwrap()
            .permit,
            false
        );
        assert_eq!(
            can_run(
                &vec_eo,
                "ed",
                "root",
                &NaiveDate::from_ymd(2020, 8, 7).and_hms(0, 0, 0),
                "localhost",
                "/bin/bash",
                &group_hash
            )
            .unwrap()
            .permit,
            false
        );
    }

    #[test]
    fn test_execute_config_oracle() {
        let config = "[ed_oracle]
user=ed
target=oracle
notbefore=20200101
notafter=20201225
regex=^/bin/bash .*$
[ed_oracle_permit]
user=ed
target=oracle
notbefore=20190101
notafter=20201225
permit=true
regex=^/bin/bash .*$
    "
        .to_string();

        let date: NaiveDateTime = NaiveDate::from_ymd(2019, 12, 31).and_hms(0, 0, 0);

        let mut vec_eo: Vec<EnvOptions> = vec![];
        read_ini_config_str(&config, &mut vec_eo, "ed", false);
        let group_hash: HashMap<String, u32> = HashMap::new();

        assert_eq!(
            can_run(
                &vec_eo,
                "ed",
                "oracle",
                &date,
                "localhost",
                "/bin/bash /usr/local/oracle/backup_script",
                &group_hash
            )
            .unwrap()
            .permit,
            true
        );
        assert_eq!(
            can_run(
                &vec_eo,
                "ed",
                "oracle",
                &date,
                "localhost",
                "/bin/sh /usr/local/oracle/backup_script",
                &group_hash
            )
            .unwrap()
            .permit,
            false
        );
        assert_eq!(
            can_run(
                &vec_eo,
                "ed",
                "oracle",
                &date,
                "web1",
                "/bin/sh /usr/local/oracle/backup_script",
                &group_hash
            )
            .unwrap()
            .permit,
            false
        );
        assert_eq!(
            can_run(
                &vec_eo,
                "ed",
                "oracle",
                &date,
                "",
                "/bin/sh /usr/local/oracle/backup_script",
                &group_hash
            )
            .unwrap()
            .permit,
            false
        );
        assert_eq!(
            can_run(
                &vec_eo,
                "ed",
                "grid",
                &date,
                "",
                "/bin/bash /usr/local/oracle/backup_script",
                &group_hash
            )
            .unwrap()
            .permit,
            false
        );
        assert_eq!(
            can_run(
                &vec_eo,
                "ed",
                "root",
                &date,
                "",
                "/bin/bash /usr/local/oracle/backup_script",
                &group_hash
            )
            .unwrap()
            .permit,
            false
        );
    }

    #[test]
    fn test_execute_config_hostname_any() {
        let config = "[ed_config_hostname]
user=ed
target=oracle
hostname=any
regex=^/bin/bash.*$
    "
        .to_string();

        let date: NaiveDateTime = NaiveDate::from_ymd(2019, 12, 31).and_hms(0, 0, 0);

        let mut vec_eo: Vec<EnvOptions> = vec![];
        read_ini_config_str(&config, &mut vec_eo, "ed", false);
        let group_hash: HashMap<String, u32> = HashMap::new();

        assert_eq!(
            can_run(
                &vec_eo,
                "ed",
                "oracle",
                &date,
                "localhost",
                "/bin/bash /usr/local/oracle/backup_script",
                &group_hash
            )
            .unwrap()
            .permit,
            true
        );
        assert_eq!(
            can_run(
                &vec_eo,
                "ed",
                "oracle",
                &date,
                "localhost",
                "/bin/sh /usr/local/oracle/backup_script",
                &group_hash
            )
            .unwrap()
            .permit,
            false
        );
        assert_eq!(
            can_run(
                &vec_eo,
                "ed",
                "oracle",
                &date,
                "web1",
                "/bin/sh /usr/local/oracle/backup_script",
                &group_hash
            )
            .unwrap()
            .permit,
            false
        );
        assert_eq!(
            can_run(
                &vec_eo,
                "ed",
                "oracle",
                &date,
                "",
                "/bin/sh /usr/local/oracle/backup_script",
                &group_hash
            )
            .unwrap()
            .permit,
            false
        );
        assert_eq!(
            can_run(
                &vec_eo,
                "ed",
                "grid",
                &date,
                "",
                "/bin/bash /usr/local/oracle/backup_script",
                &group_hash
            )
            .unwrap()
            .permit,
            false
        );
        assert_eq!(
            can_run(
                &vec_eo,
                "ed",
                "root",
                &date,
                "",
                "/bin/bash /usr/local/oracle/backup_script",
                &group_hash
            )
            .unwrap()
            .permit,
            false
        );
    }

    #[test]
    fn test_execute_config_hostname_locahost() {
        let config = "[ed_oralce_web1]
user=ed
target=oracle
hostname=web1
regex=^/bin/bash .*$

[ed_oracle_localhost]
user=ed
target=oracle
hostname=localhost
regex=^/bin/sh.*$
    "
        .to_string();

        let date: NaiveDateTime = NaiveDate::from_ymd(2019, 12, 31).and_hms(0, 0, 0);

        let mut vec_eo: Vec<EnvOptions> = vec![];
        read_ini_config_str(&config, &mut vec_eo, "ed", false);
        let group_hash: HashMap<String, u32> = HashMap::new();

        assert_eq!(
            can_run(
                &vec_eo,
                "ed",
                "oracle",
                &date,
                "localhost",
                "/bin/bash /usr/local/oracle/backup_script",
                &group_hash
            )
            .unwrap()
            .permit,
            false
        );
        assert_eq!(
            can_run(
                &vec_eo,
                "ed",
                "oracle",
                &date,
                "web1",
                "/bin/bash /usr/local/oracle/backup_script",
                &group_hash
            )
            .unwrap()
            .permit,
            true
        );
        assert_eq!(
            can_run(
                &vec_eo,
                "ed",
                "oracle",
                &date,
                "web2",
                "/bin/bash /usr/local/oracle/backup_script",
                &group_hash
            )
            .unwrap()
            .permit,
            false
        );

        assert_eq!(
            can_run(
                &vec_eo,
                "ed",
                "oracle",
                &date,
                "localhost",
                "/bin/sh /usr/local/oracle/backup_script",
                &group_hash
            )
            .unwrap()
            .permit,
            true
        );
        assert_eq!(
            can_run(
                &vec_eo,
                "ed",
                "oracle",
                &date,
                "web1",
                "/bin/sh /usr/local/oracle/backup_script",
                &group_hash
            )
            .unwrap()
            .permit,
            true
        );
        assert_eq!(
            can_run(
                &vec_eo,
                "ed",
                "oracle",
                &date,
                "web2",
                "/bin/sh /usr/local/oracle/backup_script",
                &group_hash
            )
            .unwrap()
            .permit,
            true
        );
    }

    #[test]
    fn test_missing_user() {
        let config = "[missing_user]
target=oracle
hostname=localhost
regex=/bin/sh\\b.*
    "
        .to_string();

        let date: NaiveDateTime = NaiveDate::from_ymd(2019, 12, 31).and_hms(0, 0, 0);

        let mut vec_eo: Vec<EnvOptions> = vec![];
        read_ini_config_str(&config, &mut vec_eo, "ed", false);
        let group_hash: HashMap<String, u32> = HashMap::new();

        assert_eq!(
            can_run(
                &vec_eo,
                "",
                "oracle",
                &date,
                "localhost",
                "/bin/sh /usr/local/oracle/backup_script",
                &group_hash
            )
            .unwrap()
            .permit,
            false
        );
    }

    #[test]
    fn test_regex_line_anchor() {
        let config = "
[regex_anchor]
user=ed
target=oracle
hostname=localhost
regex=.*
    "
        .to_string();

        let date: NaiveDateTime = NaiveDate::from_ymd(2019, 12, 31).and_hms(0, 0, 0);

        let mut vec_eo: Vec<EnvOptions> = vec![];
        read_ini_config_str(&config, &mut vec_eo, "ed", false);
        let group_hash: HashMap<String, u32> = HashMap::new();

        assert_eq!(
            can_run(
                &vec_eo,
                "ed",
                "oracle",
                &date,
                "localhost",
                "/bin/bash",
                &group_hash
            )
            .unwrap()
            .permit,
            true
        );
    }

    #[test]
    fn test_edit_apache() {
        let config = "
[ed_edit_root]
user=ed
target=root
notbefore=20200101
notafter=20201225
edit=true
regex = .*

[ed_edit_apache]
user=ed
target=oracle
permit=false
edit=true
regex = /etc/apache

[ed_edit_hosts]
user=ed
target=root
edit=true /etc/hosts

[user_all_todo]
user=m{}
target=^
edit=true
regex = ^"
            .to_string();

        let date: NaiveDateTime = NaiveDate::from_ymd(2020, 1, 1).and_hms(0, 0, 0);

        let mut vec_eo: Vec<EnvOptions> = vec![];
        read_ini_config_str(&config, &mut vec_eo, "ed", false);
        let group_hash: HashMap<String, u32> = HashMap::new();

        assert_eq!(
            can_edit(
                &vec_eo,
                "ed",
                "root",
                &date,
                "localhost",
                "/etc/apache/httpd2.conf",
                &group_hash
            )
            .unwrap()
            .permit,
            true
        );
    }

    #[test]
    fn test_edit_user_macro() {
        let config = "
[ed]
user=ed
target=root
regex =^/bin/cat /etc/%{USER}"
            .to_string();

        let date: NaiveDateTime = NaiveDate::from_ymd(2020, 1, 1).and_hms(0, 0, 0);

        let mut vec_eo: Vec<EnvOptions> = vec![];
        read_ini_config_str(&config, &mut vec_eo, "ed", false);
        let group_hash: HashMap<String, u32> = HashMap::new();

        assert_eq!(
            can_run(
                &vec_eo,
                "ed",
                "root",
                &date,
                "localhost",
                "/bin/cat /etc/ed",
                &group_hash
            )
            .unwrap()
            .permit,
            true
        );
        assert_eq!(
            can_run(
                &vec_eo,
                "ned",
                "root",
                &date,
                "localhost",
                "/bin/cat /etc/ed",
                &group_hash
            )
            .unwrap()
            .permit,
            false
        );
    }

    #[test]
    fn test_parse_regex_fail() {
        let mut vec_eo: Vec<EnvOptions> = vec![];

        let config = "
[ed]
user=ed
target=root
regex = ^/bin/cat /etc/("
            .to_string();

        assert_eq!(read_ini_config_str(&config, &mut vec_eo, "ed", true), true);

        let mut vec_eo: Vec<EnvOptions> = vec![];
        let config = "
[ed]
user=ed
target=root
regex = ^/bin/cat /etc/"
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
regex = ^.*$"
            .to_string();

        let date: NaiveDateTime = NaiveDate::from_ymd(2020, 1, 1).and_hms(0, 0, 0);

        let mut vec_eo: Vec<EnvOptions> = vec![];
        read_ini_config_str(&config, &mut vec_eo, "ed", false);

        let mut group_hash: HashMap<String, u32> = HashMap::new();
        group_hash.insert(String::from("users"), 1);
        assert_eq!(
            can_run(&vec_eo, "ed", "root", &date, "localhost", "", &group_hash)
                .unwrap()
                .permit,
            true
        );

        let mut group_hash: HashMap<String, u32> = HashMap::new();
        group_hash.insert(String::from("wwwadm"), 1);
        assert_eq!(
            can_run(&vec_eo, "ed", "root", &date, "localhost", "", &group_hash)
                .unwrap()
                .permit,
            false
        );
    }

    #[test]
    fn test_list_other_user() {
        let config = "
[ed_all]
user=ed
notbefore=20200101
notafter=20201225
list=true
regex = ^.*$

[bob_all]
user=bob
list=false
edit=true
regex = ^.*$

[bob_all]
user=bob
list=true
permit=false
regex = ^.*$

[meh_ed]
user=meh
list=true
regex=^ed$

[root_all]
user=root
list=false
regex =^.*$

[ben_ops]
user=ben
permit=true
list=true 
regex = ^(eng|dba|net)ops$
"
        .to_string();

        let date: NaiveDateTime = NaiveDate::from_ymd(2020, 1, 1).and_hms(0, 0, 0);

        let mut vec_eo: Vec<EnvOptions> = vec![];
        read_ini_config_str(&config, &mut vec_eo, "ed", false);
        let group_hash: HashMap<String, u32> = HashMap::new();

        assert_eq!(
            can_list(&vec_eo, "ed", "root", &date, "localhost", "", &group_hash)
                .unwrap()
                .permit,
            true
        );
        assert_eq!(
            can_list(&vec_eo, "meh", "ed", &date, "localhost", "", &group_hash)
                .unwrap()
                .permit,
            true
        );
        assert_eq!(
            can_list(&vec_eo, "meh", "bob", &date, "localhost", "", &group_hash)
                .unwrap()
                .permit,
            false
        );
        assert_eq!(
            can_list(&vec_eo, "meh", "root", &date, "localhost", "", &group_hash)
                .unwrap()
                .permit,
            false
        );
        assert_eq!(
            can_list(&vec_eo, "bob", "ed", &date, "localhost", "", &group_hash)
                .unwrap()
                .permit,
            false
        );
        assert_eq!(
            can_list(
                &vec_eo,
                "ben",
                "dbaops",
                &date,
                "localhost",
                "",
                &group_hash
            )
            .unwrap()
            .permit,
            true
        );
        assert_eq!(
            can_list(
                &vec_eo,
                "ben",
                "engops",
                &date,
                "localhost",
                "",
                &group_hash
            )
            .unwrap()
            .permit,
            true
        );
        assert_eq!(
            can_list(
                &vec_eo,
                "ben",
                "netops",
                &date,
                "localhost",
                "",
                &group_hash
            )
            .unwrap()
            .permit,
            true
        );
        assert_eq!(
            can_list(
                &vec_eo,
                "ben",
                "wwwops",
                &date,
                "localhost",
                "",
                &group_hash
            )
            .unwrap()
            .permit,
            false
        );
    }

    #[test]
    fn test_edit_regression() {
        let config = "
[www-data-bio]
name = root
group = true
permit = true
edit = true
require_pass = false
regex = ^/var/www/html/%{USER}.html"
            .to_string();

        let date: NaiveDateTime = NaiveDate::from_ymd(2020, 1, 1).and_hms(0, 0, 0);

        let mut vec_eo: Vec<EnvOptions> = vec![];
        read_ini_config_str(&config, &mut vec_eo, "ed", false);
        let group_hash: HashMap<String, u32> = HashMap::new();

        assert_eq!(
            can_edit(&vec_eo, "ed", "root", &date, "localhost", "/etc/please.ini", &group_hash)
                .unwrap()
                .permit,
            false
        );

        let mut group_hash: HashMap<String, u32> = HashMap::new();
        group_hash.insert(String::from("root"), 1);
        assert_eq!(
            can_edit(&vec_eo, "ed", "root", &date, "localhost", "/etc/please.ini", &group_hash)
                .unwrap()
                .permit,
            false
        );

        let mut group_hash: HashMap<String, u32> = HashMap::new();
        group_hash.insert(String::from("root"), 1);
        assert_eq!(
            can_edit(&vec_eo, "ed", "root", &date, "localhost", "/var/www/html/ed.html", &group_hash)
                .unwrap()
                .permit,
            true
        );

        let mut group_hash: HashMap<String, u32> = HashMap::new();
        group_hash.insert(String::from("root"), 1);
        assert_eq!(
            can_edit(&vec_eo, "ed", "root", &date, "localhost", "/var/www/html/%{USER}.html", &group_hash)
                .unwrap()
                .permit,
            false
        );

        let mut group_hash: HashMap<String, u32> = HashMap::new();
        group_hash.insert(String::from("wwwadm"), 1);
        assert_eq!(
            can_edit(&vec_eo, "ed", "root", &date, "localhost", "", &group_hash)
                .unwrap()
                .permit,
            false
        );
    }

    #[test]
    fn test_edit_user_expansion() {
        let config = "
[www-data-bio]
name = root
group = true
permit = true
edit = true
require_pass = false
regex = ^/var/www/html/%\\{USER\\}.html$"
            .to_string();
        let mut vec_eo: Vec<EnvOptions> = vec![];
        read_ini_config_str(&config, &mut vec_eo, "ed", false);

        let date: NaiveDateTime = NaiveDate::from_ymd(2020, 1, 1).and_hms(0, 0, 0);
        let mut group_hash: HashMap<String, u32> = HashMap::new();
        assert_eq!( vec_eo.iter().next().unwrap().rule.as_str(), "^^/var/www/html/ed.html$$" );

        group_hash.insert(String::from("root"), 1);
        assert_eq!(
            can_edit(&vec_eo, "ed", "root", &date, "localhost", "/var/www/html/ed.html", &group_hash)
                .unwrap()
                .permit,
            true
        );
    }

    #[test]
    fn test_edit_user_expansion_unescaped() {
        let config = "
[www-data-bio]
name = root
group = true
permit = true
edit = true
require_pass = false
regex = ^/var/www/html/%{USER}.html$"
            .to_string();
        let mut vec_eo: Vec<EnvOptions> = vec![];
        read_ini_config_str(&config, &mut vec_eo, "ed", false);

        let date: NaiveDateTime = NaiveDate::from_ymd(2020, 1, 1).and_hms(0, 0, 0);
        let mut group_hash: HashMap<String, u32> = HashMap::new();
        assert_eq!( vec_eo.iter().next().unwrap().rule.as_str(), "^^/var/www/html/ed.html$$" );

        group_hash.insert(String::from("root"), 1);
        assert_eq!(
            can_edit(&vec_eo, "ed", "root", &date, "localhost", "/var/www/html/ed.html", &group_hash)
                .unwrap()
                .permit,
            true
        );
    }

    #[test]
    fn test_edit_user_expansion_unbalanced_escapes() {
        let config = "
[www-data-bio]
name = root
group = true
permit = true
edit = true
require_pass = false
regex = ^/var/www/html/%{USER\\}.html$"
            .to_string();
        let mut vec_eo: Vec<EnvOptions> = vec![];
        read_ini_config_str(&config, &mut vec_eo, "ed", false);

        let date: NaiveDateTime = NaiveDate::from_ymd(2020, 1, 1).and_hms(0, 0, 0);
        let mut group_hash: HashMap<String, u32> = HashMap::new();
        assert_eq!( vec_eo.iter().next().unwrap().rule.as_str(), "^^/var/www/html/ed.html$$" );

        group_hash.insert(String::from("root"), 1);
        assert_eq!(
            can_edit(&vec_eo, "ed", "root", &date, "localhost", "/var/www/html/ed.html", &group_hash)
                .unwrap()
                .permit,
            true
        );
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

        let date: NaiveDateTime = NaiveDate::from_ymd(2020, 1, 1).and_hms(0, 0, 0);
        let mut group_hash: HashMap<String, u32> = HashMap::new();
        assert_eq!( vec_eo.iter().next().unwrap().rule.as_str(), "^/bin/bash$" );

        group_hash.insert(String::from("root"), 1);
        assert_eq!(
            can_run(&vec_eo, "ed", "root", &date, "localhost", "/bin/bash", &group_hash)
                .unwrap()
                .permit,
            true
        );
        assert_eq!(
            can_run(&vec_eo, "ed", "moot", &date, "localhost", "/bin/bash", &group_hash)
                .unwrap()
                .permit,
            true
        );
        assert_eq!(
            can_run(&vec_eo, "ed", "woot", &date, "localhost", "/bin/bash", &group_hash)
                .unwrap()
                .permit,
            true
        );
    }

    #[test]
    fn test_edit_regression_empty() {
        let mut vec_eo: Vec<EnvOptions> = vec![];
        let config = "".to_string();
        read_ini_config_str(&config, &mut vec_eo, "ed", false);

        let date: NaiveDateTime = NaiveDate::from_ymd(2020, 1, 1).and_hms(0, 0, 0);
        let group_hash: HashMap<String, u32> = HashMap::new();
        assert_eq!(
            can_edit(&vec_eo, "ed", "root", &date, "localhost", "/etc/please.ini", &group_hash)
                .unwrap()
                .permit,
            false
        );

    }
}

