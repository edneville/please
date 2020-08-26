use regex::Regex;

use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::ffi::CStr;
use std::io::prelude::*;
use std::path::Path;
use std::process;
use syslog::{Facility, Formatter3164};

use chrono::{NaiveDate, NaiveDateTime};
use users::*;

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
    pub line_number: u32,
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
            permit: true,
            hostname: "localhost".to_string(),
            require_pass: true,
            env_list: vec![],
            edit: false,
            file_name: "".to_string(),
            line_number: 0,
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

pub fn read_config(
    config_path: &str,
    mut vec_eo: &mut Vec<EnvOptions>,
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
        Ok(_) => return parse_config(&s, &mut vec_eo, &config_path, &user, fail_error),
    }
}

pub fn parse_config(
    lines: &str,
    vec_eo: &mut Vec<EnvOptions>,
    config_path: &str,
    execute_user: &str,
    fail_error: bool,
) -> bool {
    // a computer named 'any' will conflict with the definition of any
    let cfg_re = Regex::new(r"^\s*(?P<options>\S*[^\\])\s+(?P<rule>.*)\s*$").unwrap();
    let split_re = Regex::new(r"\s*(?P<label>[^:]+)\s*=\s*(?P<value>[^:]+\s*):?").unwrap();
    let parse_datetime_from_str = NaiveDateTime::parse_from_str;
    let parse_date_from_str = NaiveDate::parse_from_str;
    let mut line_number = 0;
    let mut faulty = false;

    for line in lines.split('\n') {
        line_number += 1;
        match cfg_re.captures(line) {
            Some(x) => {
                let mut options = x["options"].to_string();
                options = options.trim().to_string();
                let mut opt = EnvOptions::new();
                opt.permit = true;

                let rule = Regex::new(&x["rule"].to_string().replace("%\\{USER\\}", &execute_user));
                if rule.is_err() {
                    println!(
                        "Error parsing {}:{}, {}",
                        config_path,
                        line_number,
                        &x["rule"].to_string()
                    );
                    faulty = true;
                    continue;
                }
                opt.rule = rule.unwrap();

                for parts in split_re.captures_iter(&options) {
                    match &parts["label"] {
                        "user" => opt.name = parts["value"].to_string(),
                        "name" => opt.name = parts["value"].to_string(),

                        "hostname" => opt.hostname = parts["value"].to_string(),

                        "target" => opt.target = parts["value"].to_string(),
                        "permit" => opt.permit = &parts["value"] == "true",
                        "require_pass" => opt.require_pass = &parts["value"] != "false",
                        "edit" => opt.edit = &parts["value"] == "true",
                        "list" => opt.list = &parts["value"] == "true",
                        "group" => opt.group = &parts["value"] == "true",

                        "notbefore" if parts["value"].len() == 8 => {
                            opt.not_before =
                                parse_date_from_str(&parts["value"].to_string(), "%Y%m%d")
                                    .unwrap()
                                    .and_hms(0, 0, 0)
                        }
                        "notafter" if parts["value"].len() == 8 => {
                            opt.not_after =
                                parse_date_from_str(&parts["value"].to_string(), "%Y%m%d")
                                    .unwrap()
                                    .and_hms(23, 59, 59)
                        }
                        "notbefore" if parts["value"].len() == 14 => {
                            opt.not_before =
                                parse_datetime_from_str(&parts["value"].to_string(), "%Y%m%d%H%M%S")
                                    .unwrap()
                        }
                        "notafter" if parts["value"].len() == 14 => {
                            opt.not_after =
                                parse_datetime_from_str(&parts["value"].to_string(), "%Y%m%d%H%M%S")
                                    .unwrap()
                        }

                        &_ => {
                            println!(
                                "{}:{} unknown attribute \"{}\": [{}]",
                                config_path, line_number, &parts["label"], line
                            );
                            faulty = true;
                        }
                    }
                }

                if opt.name == "" {
                    // will become user == "" && other == ""
                    continue;
                }

                opt.file_name = config_path.to_string();
                opt.line_number = line_number;

                vec_eo.push(opt);
            }
            None => {}
        }
    }
    if fail_error {
        return faulty;
    }
    false
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

        if item.hostname != hostname
            && item.hostname != "any"
            && item.hostname != "localhost"
        {
            continue;
        }

        if command_list {
            if item.rule.is_match(target) {
                opt = item.clone();
            }
        }
        else {
            if item.target != target {
                continue;
            }
            if item.rule.is_match(command) {
                opt = item.clone();
            }
        }
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
            prefix += " as ";
        }
        if last_file != item.file_name {
            println!("file: {}", item.file_name);
            last_file = &item.file_name;
        }

        println!("  {}:{}{}: {}", item.line_number, prefix, item.target, item.rule);
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
        let config = "user=ed:target=root:notbefore=20200101:notafter=20201225 ^.*$
    user=ed:target=oracle:permit=false ^/bin/bash .*$
    user=ed:target=root ^/bin/bash .*$
    user=m{}:target=^ "
            .to_string();

        let date: NaiveDateTime = NaiveDate::from_ymd(2020, 1, 1).and_hms(0, 0, 0);
        let mut vec_eo: Vec<EnvOptions> = vec![];
        parse_config(&config, &mut vec_eo, "static", "ed", false);
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
        let config = "user=ed:target=root:notbefore=20200101:notafter=20201225 ^.*$
    user=ed:target=oracle ^/bin/bash .*$
    user=ed:target=root ^/bin/bash .*$
    user=m{}:target=^ "
            .to_string();

        let date: NaiveDateTime = NaiveDate::from_ymd(2019, 12, 31).and_hms(0, 0, 0);

        let mut vec_eo: Vec<EnvOptions> = vec![];
        parse_config(&config, &mut vec_eo, "static", "ed", false);
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
        let config = "user=ed:target=root:notbefore=20200101:notafter=20201225 ^.*$
    user=ed:target=oracle ^/bin/bash .*$
    user=ed:target=root:notafter=20200125:notbefore=20200101  ^
    user=m{}:target=^ "
            .to_string();

        let mut vec_eo: Vec<EnvOptions> = vec![];
        parse_config(&config, &mut vec_eo, "static", "ed", false);
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
        let config = "user=ed:target=root:notbefore=20200808:notafter=20200810235959 ^
    "
        .to_string();

        let mut vec_eo: Vec<EnvOptions> = vec![];
        parse_config(&config, &mut vec_eo, "static", "ed", false);
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
        let config = "user=ed:target=oracle:notbefore=20200101:notafter=20201225 ^/bin/bash .*$
    user=ed:target=oracle:notbefore=20190101:notafter=20201225:permit=true ^/bin/bash .*$
    "
        .to_string();

        let date: NaiveDateTime = NaiveDate::from_ymd(2019, 12, 31).and_hms(0, 0, 0);

        let mut vec_eo: Vec<EnvOptions> = vec![];
        parse_config(&config, &mut vec_eo, "static", "ed", false);
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
        let config = "user=ed:target=oracle:hostname=any ^/bin/bash\\b.*$
    "
        .to_string();

        let date: NaiveDateTime = NaiveDate::from_ymd(2019, 12, 31).and_hms(0, 0, 0);

        let mut vec_eo: Vec<EnvOptions> = vec![];
        parse_config(&config, &mut vec_eo, "static", "ed", false);
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
        let config = "user=ed:target=oracle:hostname=web1 ^/bin/bash\\b.*$
    user=ed:target=oracle:hostname=localhost ^/bin/sh\\b.*$
    "
        .to_string();

        let date: NaiveDateTime = NaiveDate::from_ymd(2019, 12, 31).and_hms(0, 0, 0);

        let mut vec_eo: Vec<EnvOptions> = vec![];
        parse_config(&config, &mut vec_eo, "static", "ed", false);
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
        let config = "target=oracle:hostname=localhost ^/bin/sh\\b.*$
    "
        .to_string();

        let date: NaiveDateTime = NaiveDate::from_ymd(2019, 12, 31).and_hms(0, 0, 0);

        let mut vec_eo: Vec<EnvOptions> = vec![];
        parse_config(&config, &mut vec_eo, "static", "ed", false);
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
        let config = "user=ed:target=oracle:hostname=localhost ^
    "
        .to_string();

        let date: NaiveDateTime = NaiveDate::from_ymd(2019, 12, 31).and_hms(0, 0, 0);

        let mut vec_eo: Vec<EnvOptions> = vec![];
        parse_config(&config, &mut vec_eo, "static", "ed", false);
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
        let config = "user=ed:target=root:notbefore=20200101:notafter=20201225:edit=true ^.*$
    user=ed:target=oracle:permit=false:edit=true ^/etc/apache.*$
    user=ed:target=root:edit=true ^/etc/hosts$
    user=m{}:target=^:edit=true "
            .to_string();

        let date: NaiveDateTime = NaiveDate::from_ymd(2020, 1, 1).and_hms(0, 0, 0);

        let mut vec_eo: Vec<EnvOptions> = vec![];
        parse_config(&config, &mut vec_eo, "static", "ed", false);
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
        let config = "user=ed:target=root ^/bin/cat /etc/%\\{USER\\}".to_string();

        let date: NaiveDateTime = NaiveDate::from_ymd(2020, 1, 1).and_hms(0, 0, 0);

        let mut vec_eo: Vec<EnvOptions> = vec![];
        parse_config(&config, &mut vec_eo, "static", "ed", false);
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

        let config = "user=ed:target=root ^/bin/cat /etc/(".to_string();
        parse_config(&config, &mut vec_eo, "static", "ed", false);

        assert_eq!(parse_config(&config, &mut vec_eo, "static", "ed", true), true);

        let mut vec_eo: Vec<EnvOptions> = vec![];
        let config = "user=ed:target=root ^/bin/cat /etc/".to_string();
        parse_config(&config, &mut vec_eo, "static", "ed", false);

        assert_eq!(parse_config(&config, &mut vec_eo, "static", "ed", true), false);
    }

    #[test]
    fn test_group_assignment() {
        let config = "name=users:group=true:target=root:notbefore=20200101:notafter=20201225 ^.*$"
            .to_string();

        let date: NaiveDateTime = NaiveDate::from_ymd(2020, 1, 1).and_hms(0, 0, 0);

        let mut vec_eo: Vec<EnvOptions> = vec![];
        parse_config(&config, &mut vec_eo, "static", "ed", false);

        let mut group_hash: HashMap<String, u32> = HashMap::new();
        group_hash.insert(String::from("users"),1);
        assert_eq!( can_run( &vec_eo, "ed", "root", &date, "localhost", "", &group_hash ).unwrap().permit, true );

        let mut group_hash: HashMap<String, u32> = HashMap::new();
        group_hash.insert(String::from("wwwadm"),1);
        assert_eq!( can_run( &vec_eo, "ed", "root", &date, "localhost", "", &group_hash ).unwrap().permit, false );
    }

    #[test]
    fn test_list_other_user() {
        let config = "user=ed:name=ed:target=root:notbefore=20200101:notafter=20201225:list=true ^.*$
user=bob:target=root:list=false:edit=true ^.*$
user=bob:target=root:list=true:permit=false ^.*$
user=meh:list=true:target=root ^ed$
user=root:target=root:list=false ^.*$
user=ben:target=root:permit=true:list=true ^(eng|dba|net)ops$"

            .to_string();

        let date: NaiveDateTime = NaiveDate::from_ymd(2020, 1, 1).and_hms(0, 0, 0);

        let mut vec_eo: Vec<EnvOptions> = vec![];
        parse_config(&config, &mut vec_eo, "static", "ed", false);
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
