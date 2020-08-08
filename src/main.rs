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

use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use std::collections::HashMap;
use std::ffi::CString;
use std::ffi::CStr;

use chrono::{NaiveDate, NaiveDateTime, Utc};
use getopt::prelude::*;

use nix::unistd::{execv,setuid,setgid,setgroups,gethostname};

use users::*;

use pam;

#[derive(Clone)]
struct EnvOptions {
    rule: Regex,
    not_before: NaiveDateTime,
    not_after: NaiveDateTime,
    target: String,
    hostname: String,
    permit: bool,
    require_pass: bool,
    env_list: Vec<String>,
}

struct UserData {
    option_list: Vec<EnvOptions>,
}

fn parse_config(lines: &str, hm: &mut HashMap<String,UserData> ) {
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
                let mut opt = EnvOptions {
                    rule: Regex::new( &x["rule"].to_string() ).unwrap(),
                    target: "root".to_string(),
                    not_before: NaiveDate::from_ymd(1970, 1, 1).and_hms(0, 0, 0),
                    not_after: NaiveDate::from_ymd(2038, 1, 19).and_hms(3, 14, 7),
                    permit: true,
                    hostname: "localhost".to_string(),
                    require_pass: true,
                    env_list: vec![],
                };

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

fn can_run( hm: &HashMap<String,UserData>, user: &str, target: &str, date: &NaiveDateTime, hostname: &str, command: &str ) -> Result<EnvOptions,()> {
    match hm.get( user ) {
        Some( user_options ) => {
            let mut env_options = EnvOptions {
                rule: Regex::new(".").unwrap(),
                target: "root".to_string(),
                not_before: NaiveDate::from_ymd(1970, 1, 1).and_hms(0, 0, 0),
                not_after: NaiveDate::from_ymd(2038, 1, 19).and_hms(3, 14, 7),
                permit: false,
                hostname: "localhost".to_string(),
                require_pass: true,
                env_list: vec![],
            };

            for item in &user_options.option_list {
                if item.not_before > *date {
                    continue;
                }

                if item.not_after < *date {
                    continue;
                }

                if item.hostname != hostname && item.hostname != "any" && item.hostname != "localhost" {
                    continue;
                }

                if item.target != target {
                    continue;
                }
                
                if item.rule.is_match( command ) {
                    env_options = item.clone();
                }
            }
            Ok( env_options )
        }
        None => {
            Ok( EnvOptions {
                        rule: Regex::new(".").unwrap(),
                        target: "".to_string(),
                        not_before: NaiveDate::from_ymd(1970, 1, 1).and_hms(0, 0, 0),
                        not_after: NaiveDate::from_ymd(2038, 1, 19).and_hms(3, 14, 7),
                        permit: false,
                        hostname: "localhost".to_string(),
                        require_pass: true,
                        env_list: vec![],
                    }
            )
        }
    }

}

fn read_config(config_path: &str, mut hm: &mut HashMap<String,UserData> ) {
    let path = Path::new( config_path );
	let display = path.display();

    let mut file = match File::open(&path) {
        Err(why) => panic!("couldn't open {}: {}", display, why),
        Ok(file) => file,
    };

    // Read the file contents into a string, returns `io::Result<usize>`
    let mut s = String::new();
    match file.read_to_string(&mut s) {
        Err(why) => panic!("couldn't read {}: {}", display, why),
        Ok(_) => parse_config(&s, &mut hm),
    }
}

fn print_usage( program: &str ) {
    println!(" usage:" );
    println!("{} /path/to/executable [arguments]", program );
    println!(" -t [user]: become target user");
}

fn auth_ok( u: &str, p: &str, service: &str ) -> bool {
    let mut auth = pam::Authenticator::with_password( &service )
        .expect("Failed to init PAM client.");
    auth.get_handler().set_credentials( u, p);
    if auth.authenticate().is_ok() && auth.open_session().is_ok() {
        return true;
    }
    return false;
}

fn main() {
    let mut args: Vec<String> = std::env::args().collect();
	let program = args[0].clone();
    let mut opts = Parser::new( &args, "t:h" );

    let mut target = String::from( "root" );

    loop {
        match opts.next().transpose().expect("bad args") {
            None => break,
            Some(opt) => match opt {
                Opt( 'h', None ) => { print_usage( &program ); return; },
                Opt( 't', Some(string) ) => target = string.clone(),
                _ => unreachable!(),
            }
        }
    }

    let new_args = args.split_off(opts.index());

    let mut hm: HashMap<String,UserData> = HashMap::new();
    read_config("/etc/please.conf", &mut hm);

    let original_uid = get_current_uid();
    let original_user = get_user_by_uid( original_uid ).unwrap();
    let user = original_user.name().to_string_lossy();
    let date = Utc::now().naive_utc();
    let mut buf = [0u8; 64];
    let hostname = gethostname(&mut buf).expect("Failed getting hostname").to_str().expect("Hostname wasn't valid UTF-8");
    let entry = can_run( &hm, &user, &target, &date, &hostname, &new_args.join(" ") );

    match entry.clone() {
        Err(_) => {
            println!( "You may not execute \"{}\" on {} as {}", new_args.join( " " ), &hostname, &target );
            return;
        }
        Ok(x) => {
            if !x.permit {
                println!( "You may not execute \"{}\" on {} as {}", new_args.join( " " ), &hostname, &target );
                return;
            }
        }
    }

    if new_args.len() == 0 {
        println!( "No program given" );
        return;
    }

    let mut params: Vec<CString> = vec!();
    for a in new_args {
        params.push( CString::new(a.as_bytes()).unwrap() );
        params.push( CString::new( a ).unwrap() );
    }

    let service = String::from( "please" );
    if entry.clone().unwrap().require_pass {
        let mut retry_counter = 0;

        loop {
            let pass = rpassword::read_password_from_tty( Some( &format!( "[{}] password: ", &service ) )).unwrap();

            if auth_ok( &user, &pass, &service ) {
                break;
            }
            retry_counter = retry_counter+1;
            if retry_counter == 3 {
                println!("Authentication failed :-(");
                return;
            }
        }
    }

    let lookup_name = users::get_user_by_name( &entry.clone().unwrap().target ).unwrap();
    let target_uid = nix::unistd::Uid::from_raw( lookup_name.uid() );
    let target_gid = nix::unistd::Gid::from_raw( lookup_name.primary_group_id() );

    std::env::set_var( "PLEASE_USER", original_user.name() ); 
    std::env::set_var( "PLEASE_UID", original_uid.to_string() ); 

    let mut groups: Vec<nix::unistd::Gid> = vec!();
    for x in lookup_name.groups().unwrap() {
        groups.push( nix::unistd::Gid::from_raw( x.gid() ) );
    }
    setgroups( groups.as_slice() ).unwrap();

    setgid( target_gid ).unwrap();
    setuid( target_uid ).unwrap();

    let vec_obj: Vec<&CStr> = params.iter().map(|c| c.as_c_str()).collect();
    execv( &params[0], &vec_obj ).expect( "Could not execute" );
}

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
