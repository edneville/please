use regex::Regex;

use std::collections::HashMap;
use std::env;
use std::ffi::CStr;
use std::path::Path;
use std::process;
use syslog::{Facility, Formatter3164};

use chrono::{NaiveDate, NaiveDateTime};
use users::*;
use ini::Ini;

#[derive(Clone)]
pub struct EnvOptions {
    pub name: String,
    pub rule: Regex,
    pub not_before: NaiveDateTime,
    pub not_after: NaiveDateTime,
    pub target: String,
    pub hostname: String,
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
            name: String::from(""),
            rule: Regex::new(&"").unwrap(),
            target: "root".to_string(),
            not_before: NaiveDate::from_ymd(1970, 1, 1).and_hms(0, 0, 0),
            not_after: NaiveDate::from_ymd(2038, 1, 19).and_hms(3, 14, 7),
            hostname: "localhost".to_string(),
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
        opt.target = "".to_string();
        opt.edit = true;
        opt
    }
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
            Some(x) => { section = x.to_string() },
            None => {},
        }
        opt.file_name = String::from(config_path);
        opt.section = section.clone();
        for (k, v) in prop.iter() {
            match k.as_ref() {
                "name" => opt.name = v.to_string(),
                "user" => opt.name = v.to_string(),
                "hostname" => opt.hostname = v.to_string(),
                "target" => opt.target = v.to_string(),
                "permit" => opt.permit = v == "true",
                "require_pass" => opt.require_pass = v != "false",
                "edit" => opt.edit = v == "true",
                "list" => opt.list = v == "true",
                "group" => opt.group = v == "true",
                "regex" => {
                    let rule = Regex::new( &v.to_string().replace("%\\{USER\\}", &user));
                    if rule.is_err() {
                        println!(
                            "Error parsing {}:{}, {}",
                            config_path,
                            section,
                            v.to_string()
                        );
                        faulty = true;
                        continue;
                    }
                    opt.rule = rule.unwrap();
                },

                "notbefore" if v.len() == 8 => {
                    opt.not_before =
                        parse_date_from_str(&v.to_string(), "%Y%m%d")
                            .unwrap()
                            .and_hms(0, 0, 0)
                }
                "notafter" if v.len() == 8 => {
                    opt.not_after =
                        parse_date_from_str(&v.to_string(), "%Y%m%d")
                            .unwrap()
                            .and_hms(23, 59, 59)
                }
                "notbefore" if v.len() == 14 => {
                    opt.not_before =
                        parse_datetime_from_str(&v.to_string(), "%Y%m%d%H%M%S")
                            .unwrap()
                }
                "notafter" if v.len() == 14 => {
                    opt.not_after =
                        parse_datetime_from_str(&v.to_string(), "%Y%m%d%H%M%S")
                            .unwrap()
                }

                &_ => {
                    println!(
                        "{}: unknown attribute \"{}\": {}",
                        config_path, k, v
                    );
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
        vec_eo.push( opt );
    }

    if fail_error {
        faulty
    }
    else {
        false
    }
}

pub fn read_ini_config_file(
    config_path: &str,
    vec_eo: &mut Vec<EnvOptions>,
    user: &str,
    fail_error: bool,
) -> bool {

    let conf = Ini::load_from_file( config_path );
    match conf {
        Err(x) => {
            println!("cannot open {}:{}", config_path, x);
            std::process::exit(1);
        },
        Ok(x) => {
            return read_ini( &x, vec_eo, &user, fail_error, config_path );
        }
    }
}

pub fn read_ini_config_str(
    config_path: &str,
    vec_eo: &mut Vec<EnvOptions>,
    user: &str,
    fail_error: bool,
) -> bool {

    let conf = Ini::load_from_str( &config_path );
    match conf {
        Err(x) => {
            println!("cannot open {}:{}", config_path, x);
            std::process::exit(1);
        },
        Ok(x) => {
            return read_ini( &x, vec_eo, &user, fail_error, "static" );
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
    group_list: &HashMap<String,u32>,
) -> Result<EnvOptions, ()> {
    can(vec_eo, &user, &target, &date, &hostname, &command, false, false, &group_list)
}

pub fn can_edit(
    vec_eo: &Vec<EnvOptions>,
    user: &str,
    target: &str,
    date: &NaiveDateTime,
    hostname: &str,
    command: &str,
    group_list: &HashMap<String,u32>,
) -> Result<EnvOptions, ()> {
    can(vec_eo, &user, &target, &date, &hostname, &command, true, false, &group_list)
}

pub fn can_list(
    vec_eo: &Vec<EnvOptions>,
    user: &str,
    target: &str,
    date: &NaiveDateTime,
    hostname: &str,
    command: &str,
    group_list: &HashMap<String,u32>,
) -> Result<EnvOptions, ()> {
    can(vec_eo, &user, &target, &date, &hostname, &command, false, true, &group_list)
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
    group_list: &HashMap<String,u32>,
) -> Result<EnvOptions, ()> {

    let mut opt = EnvOptions::new_deny();

    for item in vec_eo {
        if item.not_before > *date {
            continue;
        }

        if item.not_after < *date {
            continue;
        }

        if !item.group && item.name != user {
            continue;
        }

        if item.group {
            if group_list.get( &item.name ).is_none() {
                continue;
            }
        }

        if item.list != command_list {
            continue;
        }

        if item.edit != edit {
            continue;
        }

        // println!("can test {} {}", item.hostname, hostname );
        if item.hostname != hostname
            && item.hostname != "any"
            && item.hostname != "localhost"
        {
            continue;
        }

        if command_list {
            if item.rule.is_match(target) {
                // println!("is list");
                opt = item.clone();
            }
        }
        else {
            if item.target != target {
                // println!("item target {} != target {}", item.target, target);
                continue;
            }
            if item.rule.is_match(command) {
                // println!("item rule is match");
                opt = item.clone();
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
        match std::env::var(prog) {
            Ok(val) => return val,
            Err(_) => {}
        }
    }
    editor.to_string()
}

pub fn challenge_password(user: String, entry: EnvOptions, service: &str) -> bool {
    if entry.require_pass {
        let mut retry_counter = 0;

        loop {
            let pass = rpassword::read_password_from_tty(Some(&format!(
                "[{}] password for {}: ",
                &service, &user
            )))
            .unwrap();

            if auth_ok(&user, &pass, &service) {
                return true;
            }
            retry_counter = retry_counter + 1;
            if retry_counter == 3 {
                println!("Authentication failed :-(");
                return false;
            }
        }
    }
    true
}

pub fn list_edit(vec_eo: &Vec<EnvOptions>, user: &str, date: &NaiveDateTime, hostname: &str, target: &str, group_list: &HashMap<String,u32>) {
    list(vec_eo, &user, &date, &hostname, true, &target, &group_list);
}

pub fn list_run(vec_eo: &Vec<EnvOptions>, user: &str, date: &NaiveDateTime, hostname: &str, target: &str, group_list: &HashMap<String,u32>) {
    list(vec_eo, &user, &date, &hostname, false, &target, &group_list);
}

pub fn list(
    vec_eo: &Vec<EnvOptions>,
    user: &str,
    date: &NaiveDateTime,
    hostname: &str,
    edit: bool,
    target: &str,
    group_list: &HashMap<String,u32>,
) {
    let mut search_user = String::from( user );
    if target != "" {
        search_user = String::from( target );
    }
    let mut last_file = "";

    for item in vec_eo {
        if !item.group && item.name != search_user {
            continue;
        }

        if item.group {
            if group_list.get( &item.name ).is_none() {
                continue;
            }
        }

        let mut prefixes = vec![];
        if item.not_before > *date {
            prefixes.push(format!("upcomming({})", item.not_before));
        }

        if item.not_after < *date {
            prefixes.push(format!("expired({})", item.not_after));
        }

        if item.edit != edit {
            continue;
        }

        if !item.permit {
            prefixes.push(String::from("not permitted"));
        }

        if item.hostname != hostname
            && item.hostname != "any"
            && item.hostname != "localhost"
        {
            continue;
        }
        let mut prefix = prefixes.join(", ");
        if !prefix.is_empty() {
            if !item.list {
                prefix = format!(" {} as ", prefix );
            }
            else {
                prefix = format!(" {} to ", prefix );
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
        
        println!("  {}:{}{}: {}", item.section, prefix, item.target, item.rule);
    }
}

pub fn search_path(binary: &str) -> String {
    if binary.starts_with('/') {
        return binary.to_string();
    }

    match env::var("PATH") {
        Ok(path) => {
            for dir in path.split(':') {
                let path_name = format!("{}/{}", &dir, &binary.to_string());
                let p = Path::new(&path_name);

                if !p.exists() {
                    continue;
                }
                return path_name;
            }
        }
        Err(_) => {}
    }
    binary.to_string()
}

pub fn log_action( service: &str, result: &str, user: &str, target: &str, command: &str ) -> bool {
    let formatter = Formatter3164 {
        facility: Facility::LOG_USER,
        hostname: None,
        process: service.into(),
        pid: process::id() as i32,
    };

    let ttyname;
    
    unsafe {
        let ptr = libc::ttyname(0);
        match CStr::from_ptr(ptr).to_str() {
            Err(_x) => ttyname = "failed",
            Ok(x) => ttyname = x,
        }
    };

    match syslog::unix(formatter) {
        Err(e) => println!("impossible to connect to syslog: {:?}", e),
        Ok(mut writer) => {
            writer.err(format!("user={} tty={} action={} target={} command={}", user, ttyname, result, target, command)).expect("could not write error message");
        }
    }

    false
}

pub fn group_hash( groups: Vec<Group> ) -> HashMap<String, u32> {
    let mut hm: HashMap<String,u32> = HashMap::new();
    for group in groups {
        hm.entry( String::from( group.name().to_string_lossy() ) ).or_insert( group.gid() );
    }
    return hm;
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
            can_run(&vec_eo, "ed", "root", &date, "localhost", "/bin/bash", &group_hash)
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
user=m{}
target=
regex=^ "
            .to_string();

        let date: NaiveDateTime = NaiveDate::from_ymd(2019, 12, 31).and_hms(0, 0, 0);

        let mut vec_eo: Vec<EnvOptions> = vec![];
        read_ini_config_str(&config, &mut vec_eo, "ed", false);
        let group_hash: HashMap<String, u32> = HashMap::new();

        assert_eq!(
            can_run(&vec_eo, "gone", "root", &date, "localhost", "/bin/bash", &group_hash )
                .unwrap()
                .permit,
            false
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
                "/bin/bash", &group_hash
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
                "/bin/bash", &group_hash
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
                "/bin/bash", &group_hash
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
regex=^
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
                "/bin/bash", &group_hash
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
                "/bin/bash", &group_hash
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
                "/bin/bash", &group_hash
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
                "/bin/bash", &group_hash
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
                "/bin/bash", &group_hash
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
                "/bin/bash /usr/local/oracle/backup_script", &group_hash
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
                "/bin/sh /usr/local/oracle/backup_script", &group_hash
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
                "/bin/sh /usr/local/oracle/backup_script", &group_hash
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
                "/bin/sh /usr/local/oracle/backup_script", &group_hash
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
                "/bin/bash /usr/local/oracle/backup_script", &group_hash
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
                "/bin/bash /usr/local/oracle/backup_script", &group_hash
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
                "/bin/bash /usr/local/oracle/backup_script", &group_hash
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
                "/bin/sh /usr/local/oracle/backup_script", &group_hash
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
                "/bin/sh /usr/local/oracle/backup_script", &group_hash
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
                "/bin/sh /usr/local/oracle/backup_script", &group_hash
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
                "/bin/bash /usr/local/oracle/backup_script", &group_hash
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
                "/bin/bash /usr/local/oracle/backup_script", &group_hash
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
                "/bin/bash /usr/local/oracle/backup_script", &group_hash
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
                "/bin/bash /usr/local/oracle/backup_script", &group_hash
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
                "/bin/bash /usr/local/oracle/backup_script", &group_hash
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
                "/bin/sh /usr/local/oracle/backup_script", &group_hash
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
                "/bin/sh /usr/local/oracle/backup_script", &group_hash
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
                "/bin/sh /usr/local/oracle/backup_script", &group_hash
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
regex=^/bin/sh\\b.*$
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
                "/bin/sh /usr/local/oracle/backup_script", &group_hash
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
regex=^
    "
        .to_string();

        let date: NaiveDateTime = NaiveDate::from_ymd(2019, 12, 31).and_hms(0, 0, 0);

        let mut vec_eo: Vec<EnvOptions> = vec![];
        read_ini_config_str(&config, &mut vec_eo, "ed", false);
        let group_hash: HashMap<String, u32> = HashMap::new();

        assert_eq!(
            can_run(&vec_eo, "ed", "oracle", &date, "localhost", "/bin/bash", &group_hash)
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
regex = ^.*$

[ed_edit_apache]
user=ed
target=oracle
permit=false
edit=true
regex = ^/etc/apache.*$

[ed_edit_hosts]
user=ed
target=root
edit=true ^/etc/hosts$

[user_all_todo]
user=m{}
target=^
edit=true
regex = ^".to_string();

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
                "/etc/apache/httpd2.conf", &group_hash
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
regex =^/bin/cat /etc/%\\{USER\\}".to_string();

        let date: NaiveDateTime = NaiveDate::from_ymd(2020, 1, 1).and_hms(0, 0, 0);

        let mut vec_eo: Vec<EnvOptions> = vec![];
        read_ini_config_str(&config, &mut vec_eo, "ed", false);
        let group_hash: HashMap<String, u32> = HashMap::new();

        assert_eq!(
            can_run(&vec_eo, "ed", "root", &date, "localhost", "/bin/cat /etc/ed", &group_hash)
                .unwrap()
                .permit,
            true
        );
    }

    #[test]
    fn test_parse_regex_fail() {
        let mut vec_eo: Vec<EnvOptions> = vec![];

        let config = "
[ed]
user=ed
target=root
regex = ^/bin/cat /etc/(".to_string();

        assert_eq!(read_ini_config_str(&config, &mut vec_eo, "ed", true), true);

        let mut vec_eo: Vec<EnvOptions> = vec![];
        let config = "
[ed]
user=ed
target=root
regex = ^/bin/cat /etc/".to_string();

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
        group_hash.insert(String::from("users"),1);
        assert_eq!( can_run( &vec_eo, "ed", "root", &date, "localhost", "", &group_hash ).unwrap().permit, true );

        let mut group_hash: HashMap<String, u32> = HashMap::new();
        group_hash.insert(String::from("wwwadm"),1);
        assert_eq!( can_run( &vec_eo, "ed", "root", &date, "localhost", "", &group_hash ).unwrap().permit, false );
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
".to_string();

        let date: NaiveDateTime = NaiveDate::from_ymd(2020, 1, 1).and_hms(0, 0, 0);

        let mut vec_eo: Vec<EnvOptions> = vec![];
        read_ini_config_str(&config, &mut vec_eo, "ed", false);
        let group_hash: HashMap<String, u32> = HashMap::new();

        assert_eq!( can_list( &vec_eo, "ed", "root", &date, "localhost", "", &group_hash ).unwrap().permit, true );
        assert_eq!( can_list( &vec_eo, "meh", "ed", &date, "localhost", "", &group_hash ).unwrap().permit, true );
        assert_eq!( can_list( &vec_eo, "meh", "bob", &date, "localhost", "", &group_hash ).unwrap().permit, false );
        assert_eq!( can_list( &vec_eo, "meh", "root", &date, "localhost", "", &group_hash ).unwrap().permit, false );
        assert_eq!( can_list( &vec_eo, "bob", "ed", &date, "localhost", "", &group_hash ).unwrap().permit, false );
        assert_eq!( can_list( &vec_eo, "ben", "dbaops", &date, "localhost", "" , &group_hash).unwrap().permit, true );
        assert_eq!( can_list( &vec_eo, "ben", "engops", &date, "localhost", "" , &group_hash).unwrap().permit, true );
        assert_eq!( can_list( &vec_eo, "ben", "netops", &date, "localhost", "", &group_hash ).unwrap().permit, true );
        assert_eq!( can_list( &vec_eo, "ben", "wwwops", &date, "localhost", "" , &group_hash).unwrap().permit, false );
    }
}
