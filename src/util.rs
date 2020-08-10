use regex::Regex;

use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use std::collections::HashMap;

use chrono::{NaiveDate, NaiveDateTime};

use pam;

#[derive(Clone)]
pub struct EnvOptions {
    pub rule: Regex,
    pub not_before: NaiveDateTime,
    pub not_after: NaiveDateTime,
    pub target: String,
    pub hostname: String,
    pub permit: bool,
    pub require_pass: bool,
    pub env_list: Vec<String>,
    pub edit: bool,
}

fn new_env_options() -> EnvOptions {
    return EnvOptions {
        rule: Regex::new( &"" ).unwrap(),
        target: "root".to_string(),
        not_before: NaiveDate::from_ymd(1970, 1, 1).and_hms(0, 0, 0),
        not_after: NaiveDate::from_ymd(2038, 1, 19).and_hms(3, 14, 7),
        permit: true,
        hostname: "localhost".to_string(),
        require_pass: true,
        env_list: vec![],
        edit: false,
    };
}

pub struct UserData {
    option_list: Vec<EnvOptions>,
}

pub fn read_config(config_path: &str, mut hm: &mut HashMap<String,UserData> ) {
    let path = Path::new( config_path );
	let display = path.display();

    let mut file = match File::open(&path) {
        Err(why) => panic!("couldn't open {}: {}", display, why),
        Ok(file) => file,
    };

    let mut s = String::new();
    match file.read_to_string(&mut s) {
        Err(why) => panic!("couldn't read {}: {}", display, why),
        Ok(_) => parse_config(&s, &mut hm),
    }
}

pub fn parse_config(lines: &str, hm: &mut HashMap<String,UserData> ) {
    // a computer named 'any' will conflict with the definition of any
    let cfg_re = Regex::new(r"^\s*(?P<options>\S*[^\\])\s+(?P<rule>.*)\s*$").unwrap();
    let split_re = Regex::new( r"\s*(?P<label>[^:]+)\s*=\s*(?P<value>[^:]+\s*):?" ).unwrap();
    let parse_datetime_from_str = NaiveDateTime::parse_from_str;
    let parse_date_from_str = NaiveDate::parse_from_str;

    for line in lines.split("\n") {
        match cfg_re.captures(line) {
            Some(x) => { 
                let options = x["options"].to_string();
                let mut user: String = "".to_string();

                /*
                let mut opt = EnvOptions {
                    rule: Regex::new( &x["rule"].to_string() ).unwrap(),
                    target: "root".to_string(),
                    not_before: NaiveDate::from_ymd(1970, 1, 1).and_hms(0, 0, 0),
                    not_after: NaiveDate::from_ymd(2038, 1, 19).and_hms(3, 14, 7),
                    permit: true,
                    hostname: "localhost".to_string(),
                    require_pass: true,
                    env_list: vec![],
                    edit: false,
                };
                */

                let mut opt = new_env_options();
                opt.permit = true;
                opt.rule = Regex::new( &x["rule"].to_string() ).unwrap();

                for parts in split_re.captures_iter( &options ) {
                    match &parts["label"] {
                        "user" => { user = parts["value"].to_string() }

                        "hostname" => { opt.hostname = parts["value"].to_string() }

                        "target" => { opt.target = parts["value"].to_string() }
                        "permit" => { opt.permit = &parts["value"] == "true" }
                        "require_pass" => {
                            opt.require_pass =
                                &parts["value"] != "false"
                        }
                        "edit" => {
                            opt.edit = &parts["value"] == "true"
                        }

                        "notbefore" if parts["value"].len() == 8 => { opt.not_before = parse_date_from_str( &parts["value"].to_string(), "%Y%m%d" ).unwrap().and_hms(0,0,0) }
                        "notafter" if parts["value"].len() == 8 => { opt.not_after = parse_date_from_str( &parts["value"].to_string(), "%Y%m%d" ).unwrap().and_hms(23,59,0) }
                        "notbefore" if parts["value"].len() == 14 => { opt.not_before = parse_datetime_from_str( &parts["value"].to_string(), "%Y%m%d%H%M%S" ).unwrap() }
                        "notafter" if parts["value"].len() == 14 => { opt.not_after = parse_datetime_from_str( &parts["value"].to_string(), "%Y%m%d%H%M%S" ).unwrap() }

                        &_ => {}
                    }
                }

                if user == "" {
                    continue;
                }

                let u = hm.entry( user ).or_insert( UserData { option_list: vec!() } );

                u.option_list.push(opt);
            }
            None => {},
        }
    }
}

pub fn can_run( hm: &HashMap<String,UserData>, user: &str, target: &str, date: &NaiveDateTime, hostname: &str, command: &str ) -> Result<EnvOptions,()> {
    can( &hm, &user, &target, &date, &hostname, &command, false )
}

pub fn can_edit( hm: &HashMap<String,UserData>, user: &str, target: &str, date: &NaiveDateTime, hostname: &str, command: &str ) -> Result<EnvOptions,()> {
    can( &hm, &user, &target, &date, &hostname, &command, true )
}

pub fn can( hm: &HashMap<String,UserData>, user: &str, target: &str, date: &NaiveDateTime, hostname: &str, command: &str, edit: bool ) -> Result<EnvOptions,()> {
    match hm.get( user ) {
        Some( user_options ) => {
            let mut opt = new_env_options();
            opt.permit = false;
            opt.rule = Regex::new(".").unwrap();

            for item in &user_options.option_list {
                if item.not_before > *date {
                    continue;
                }

                if item.not_after < *date {
                    continue;
                }

                if item.edit != edit {
                    continue;
                }

                if item.hostname != hostname && item.hostname != "any" && item.hostname != "localhost" {
                    continue;
                }

                if item.target != target {
                    continue;
                }
                
                if item.rule.is_match( command ) {
                    opt = item.clone();
                }
            }
            Ok( opt )
        }
        None => {
            let mut opt = new_env_options();
            opt.permit = false;
            opt.rule = Regex::new(".").unwrap();
            opt.target = "".to_string();
            opt.edit = true;
            Ok( opt )
        }
    }
}

pub fn auth_ok( u: &str, p: &str, service: &str ) -> bool {
    let mut auth = pam::Authenticator::with_password( &service )
        .expect("Failed to init PAM client.");
    auth.get_handler().set_credentials( u, p);
    if auth.authenticate().is_ok() && auth.open_session().is_ok() {
        return true;
    }
    return false;
}

pub fn get_editor() -> String {
    let editor = "/usr/bin/vi";

    for prog in [String::from( "VISUAL" ), String::from( "EDITOR" ) ].iter() {
        match std::env::var( prog ) {
            Ok(val) => return val.clone(),
            Err(_) => {},
        }
    }
    editor.to_string()
}

pub fn challenge_password( user: String, entry: EnvOptions, service: &str ) -> bool {
    if entry.require_pass {
        let mut retry_counter = 0;

        loop {
            let pass = rpassword::read_password_from_tty( Some( &format!( "[{}] password for {}: ", &service, &user ) )).unwrap();

            if auth_ok( &user, &pass, &service ) {
                println!("returning true");
                return true;
            }
            retry_counter = retry_counter+1;
            if retry_counter == 3 {
                println!("Authentication failed :-(");
                return false;
            }
        }
    }
    true
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;
    use chrono::*;
    use super::*;

    #[test]
    fn test_execute_config() {
        let config = "user=ed:target=root:notbefore=20200101:notafter=20201225 ^.*$
    user=ed:target=oracle:allow=false ^/bin/bash .*$
    user=ed:target=root ^/bin/bash .*$
    user=m{}:target=^ ".to_string();

        let date: NaiveDateTime = NaiveDate::from_ymd(2020, 1, 1).and_hms(0, 0, 0);

        let mut hm: HashMap<String,UserData> = HashMap::new();
        parse_config(&config, &mut hm);

        assert_eq!( can_run( &hm, "ed", "root", &date, "localhost", "/bin/bash" ).unwrap().permit, true );
    }

    #[test]
    fn test_execute_user_does_not_exist() {
        let config = "user=ed:target=root:notbefore=20200101:notafter=20201225 ^.*$
    user=ed:target=oracle ^/bin/bash .*$
    user=ed:target=root ^/bin/bash .*$
    user=m{}:target=^ ".to_string();

        let date: NaiveDateTime = NaiveDate::from_ymd(2019, 12, 31).and_hms(0, 0, 0);

        let mut hm: HashMap<String,UserData> = HashMap::new();
        parse_config(&config, &mut hm);
        assert_eq!( can_run( &hm, "gone", "root", &date, "localhost", "/bin/bash" ).unwrap().permit, false );
    }

    #[test]
    fn test_execute_config_too_early() {
        let config = "user=ed:target=root:notbefore=20200101:notafter=20201225 ^.*$
    user=ed:target=oracle ^/bin/bash .*$
    user=ed:target=root:notbefore=20200101:notafter=20201225  ^/bin/bash .*$
    user=m{}:target=^ ".to_string();

        let mut hm: HashMap<String,UserData> = HashMap::new();
        parse_config(&config, &mut hm);
        assert_eq!( can_run( &hm, "ed", "root", &NaiveDate::from_ymd(2019, 12, 31).and_hms(0, 0, 0), "localhost", "/bin/bash" ).unwrap().permit, false );
        assert_eq!( can_run( &hm, "ed", "root", &NaiveDate::from_ymd(2020, 12, 25).and_hms(0, 0, 0), "localhost", "/bin/bash" ).unwrap().permit, true );
        assert_eq!( can_run( &hm, "ed", "root", &NaiveDate::from_ymd(2020, 12, 25).and_hms(1, 0, 0), "localhost", "/bin/bash" ).unwrap().permit, true );
    }

    #[test]
    fn test_execute_config_too_early_long() {
        let config = "user=ed:target=root:notbefore=20200808:notafter=20200810235959 ^
    ".to_string();

        let mut hm: HashMap<String,UserData> = HashMap::new();
        parse_config(&config, &mut hm);
        assert_eq!( can_run( &hm, "ed", "root", &NaiveDate::from_ymd(2020, 8, 8).and_hms(0, 0, 0), "localhost", "/bin/bash" ).unwrap().permit, true );
        assert_eq!( can_run( &hm, "ed", "root", &NaiveDate::from_ymd(2020, 8, 10).and_hms(0, 0, 0), "localhost", "/bin/bash" ).unwrap().permit, true );
        assert_eq!( can_run( &hm, "ed", "root", &NaiveDate::from_ymd(2020, 8, 10).and_hms(23, 59, 59), "localhost", "/bin/bash" ).unwrap().permit, true );
        assert_eq!( can_run( &hm, "ed", "root", &NaiveDate::from_ymd(2020, 8, 11).and_hms(0, 0, 0), "localhost", "/bin/bash" ).unwrap().permit, false );
        assert_eq!( can_run( &hm, "ed", "root", &NaiveDate::from_ymd(2020, 8, 7).and_hms(0, 0, 0), "localhost", "/bin/bash" ).unwrap().permit, false );
    }

    #[test]
    fn test_execute_config_oracle() {
        let config = "user=ed:target=oracle:notbefore=20200101:notafter=20201225 ^/bin/bash .*$
    user=ed:target=oracle:notbefore=20190101:notafter=20201225:permit=true ^/bin/bash .*$
    ".to_string();

        let date: NaiveDateTime = NaiveDate::from_ymd(2019, 12, 31).and_hms(0, 0, 0);

        let mut hm: HashMap<String,UserData> = HashMap::new();
        parse_config(&config, &mut hm);
        assert_eq!( can_run( &hm, "ed", "oracle", &date, "localhost", "/bin/bash /usr/local/oracle/backup_script" ).unwrap().permit, true );
        assert_eq!( can_run( &hm, "ed", "oracle", &date, "localhost", "/bin/sh /usr/local/oracle/backup_script" ).unwrap().permit, false );
        assert_eq!( can_run( &hm, "ed", "oracle", &date, "web1", "/bin/sh /usr/local/oracle/backup_script" ).unwrap().permit, false );
        assert_eq!( can_run( &hm, "ed", "oracle", &date, "", "/bin/sh /usr/local/oracle/backup_script" ).unwrap().permit, false );
        assert_eq!( can_run( &hm, "ed", "grid", &date, "", "/bin/bash /usr/local/oracle/backup_script" ).unwrap().permit, false );
        assert_eq!( can_run( &hm, "ed", "root", &date, "", "/bin/bash /usr/local/oracle/backup_script" ).unwrap().permit, false );
    }

    #[test]
    fn test_execute_config_hostname_any() {
        let config = "user=ed:target=oracle:hostname=any ^/bin/bash\\b.*$
    ".to_string();

        let date: NaiveDateTime = NaiveDate::from_ymd(2019, 12, 31).and_hms(0, 0, 0);

        let mut hm: HashMap<String,UserData> = HashMap::new();
        parse_config(&config, &mut hm);
        assert_eq!( can_run( &hm, "ed", "oracle", &date, "localhost", "/bin/bash /usr/local/oracle/backup_script" ).unwrap().permit, true );
        assert_eq!( can_run( &hm, "ed", "oracle", &date, "localhost", "/bin/sh /usr/local/oracle/backup_script" ).unwrap().permit, false );
        assert_eq!( can_run( &hm, "ed", "oracle", &date, "web1", "/bin/sh /usr/local/oracle/backup_script" ).unwrap().permit, false );
        assert_eq!( can_run( &hm, "ed", "oracle", &date, "", "/bin/sh /usr/local/oracle/backup_script" ).unwrap().permit, false );
        assert_eq!( can_run( &hm, "ed", "grid", &date, "", "/bin/bash /usr/local/oracle/backup_script" ).unwrap().permit, false );
        assert_eq!( can_run( &hm, "ed", "root", &date, "", "/bin/bash /usr/local/oracle/backup_script" ).unwrap().permit, false );
    }

    #[test]
    fn test_execute_config_hostname_locahost() {
        let config = "user=ed:target=oracle:hostname=web1 ^/bin/bash\\b.*$
    user=ed:target=oracle:hostname=localhost ^/bin/sh\\b.*$
    ".to_string();

        let date: NaiveDateTime = NaiveDate::from_ymd(2019, 12, 31).and_hms(0, 0, 0);

        let mut hm: HashMap<String,UserData> = HashMap::new();
        parse_config(&config, &mut hm);
        assert_eq!( can_run( &hm, "ed", "oracle", &date, "localhost", "/bin/bash /usr/local/oracle/backup_script" ).unwrap().permit, false );
        assert_eq!( can_run( &hm, "ed", "oracle", &date, "web1", "/bin/bash /usr/local/oracle/backup_script" ).unwrap().permit, true );
        assert_eq!( can_run( &hm, "ed", "oracle", &date, "web2", "/bin/bash /usr/local/oracle/backup_script" ).unwrap().permit, false );

        assert_eq!( can_run( &hm, "ed", "oracle", &date, "localhost", "/bin/sh /usr/local/oracle/backup_script" ).unwrap().permit, true );
        assert_eq!( can_run( &hm, "ed", "oracle", &date, "web1", "/bin/sh /usr/local/oracle/backup_script" ).unwrap().permit, true );
        assert_eq!( can_run( &hm, "ed", "oracle", &date, "web2", "/bin/sh /usr/local/oracle/backup_script" ).unwrap().permit, true );
    }

    #[test]
    fn test_missing_user() {
        let config = "target=oracle:hostname=localhost ^/bin/sh\\b.*$
    ".to_string();

        let date: NaiveDateTime = NaiveDate::from_ymd(2019, 12, 31).and_hms(0, 0, 0);

        let mut hm: HashMap<String,UserData> = HashMap::new();
        parse_config(&config, &mut hm);
        assert_eq!( can_run( &hm, "", "oracle", &date, "localhost", "/bin/sh /usr/local/oracle/backup_script" ).unwrap().permit, false );
    }

    #[test]
    fn test_regex_line_anchor() {
        let config = "user=ed:target=oracle:hostname=localhost ^
    ".to_string();

        let date: NaiveDateTime = NaiveDate::from_ymd(2019, 12, 31).and_hms(0, 0, 0);

        let mut hm: HashMap<String,UserData> = HashMap::new();
        parse_config(&config, &mut hm);
        assert_eq!( can_run( &hm, "ed", "oracle", &date, "localhost", "/bin/bash" ).unwrap().permit, true );
    }

    #[test]
    fn test_edit_apache() {
        let config = "user=ed:target=root:notbefore=20200101:notafter=20201225:edit=true ^.*$
    user=ed:target=oracle:allow=false:edit=true ^/etc/apache.*$
    user=ed:target=root:edit=true ^/etc/hosts$
    user=m{}:target=^:edit=true ".to_string();

        let date: NaiveDateTime = NaiveDate::from_ymd(2020, 1, 1).and_hms(0, 0, 0);

        let mut hm: HashMap<String,UserData> = HashMap::new();
        parse_config(&config, &mut hm);

        assert_eq!( can_edit( &hm, "ed", "root", &date, "localhost", "/etc/apache/httpd2.conf" ).unwrap().permit, true );
    }
}

