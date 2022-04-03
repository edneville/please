use std::collections::HashMap;

use chrono::NaiveDate;

#[cfg(test)]
mod test {
    use super::*;
    use pleaser::*;

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
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        let mut vec_eo: Vec<EnvOptions> = vec![];
        let mut ro = RunOptions::new();
        ro.date = NaiveDate::from_ymd(2020, 1, 1).and_hms(0, 0, 0);
        ro.name = "ed".to_string();
        ro.target = "root".to_string();
        ro.acl_type = Acltype::Run;
        ro.command = "/bin/bash".to_string();
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);
        assert_eq!(can(&vec_eo, &ro).permit(), true);
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
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        let mut ro = RunOptions::new();
        ro.name = "ed".to_string();
        ro.target = "root".to_string();
        ro.acl_type = Acltype::Run;
        ro.command = "/bin/bash".to_string();
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);
        assert_eq!(can(&vec_eo, &ro).permit(), true);
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
        ro.acl_type = Acltype::Run;
        ro.command = "/bin/bash".to_string();

        let mut vec_eo: Vec<EnvOptions> = vec![];
        let mut bytes = 0;
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);
        assert_eq!(can(&vec_eo, &ro).permit(), false);

        ro.name = "other".to_string();
        ro.target = "thingy".to_string();
        let mut vec_eo: Vec<EnvOptions> = vec![];
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);
        assert_eq!(can(&vec_eo, &ro).permit(), true);

        ro.name = "other".to_string();
        ro.target = "oracle".to_string();
        let mut vec_eo: Vec<EnvOptions> = vec![];
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);
        assert_eq!(can(&vec_eo, &ro).permit(), false);
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
        ro.acl_type = Acltype::Run;
        ro.command = "/bin/bash".to_string();

        let mut vec_eo: Vec<EnvOptions> = vec![];
        let mut bytes = 0;
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        ro.date = NaiveDate::from_ymd(2019, 12, 31).and_hms(0, 0, 0);
        assert_eq!(can(&vec_eo, &ro).permit(), false);

        ro.date = NaiveDate::from_ymd(2020, 12, 25).and_hms(0, 0, 0);
        assert_eq!(can(&vec_eo, &ro).permit(), true);

        ro.date = NaiveDate::from_ymd(2020, 01, 25).and_hms(0, 0, 0);
        assert_eq!(can(&vec_eo, &ro).permit(), true);

        ro.date = NaiveDate::from_ymd(2020, 03, 25).and_hms(0, 0, 0);
        assert_eq!(can(&vec_eo, &ro).permit(), true);
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
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        let mut ro = RunOptions::new();
        ro.name = "ed".to_string();
        ro.acl_type = Acltype::List;

        ro.target = "ed".to_string();
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);
        assert_eq!(can(&vec_eo, &ro).permit(), true);
        ro.target = "root".to_string();
        assert_eq!(can(&vec_eo, &ro).permit(), false);
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
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        let mut ro = RunOptions::new();
        ro.name = "ed".to_string();
        ro.target = "root".to_string();
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        let mut vec_eo: Vec<EnvOptions> = vec![];
        let mut bytes = 0;
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        ro.date = NaiveDate::from_ymd(2020, 8, 8).and_hms(0, 0, 0);
        assert_eq!(can(&vec_eo, &ro).permit(), true);

        ro.date = NaiveDate::from_ymd(2020, 8, 10).and_hms(0, 0, 0);
        assert_eq!(can(&vec_eo, &ro).permit(), true);

        ro.date = NaiveDate::from_ymd(2020, 8, 10).and_hms(23, 59, 59);
        assert_eq!(can(&vec_eo, &ro).permit(), true);

        ro.date = NaiveDate::from_ymd(2020, 8, 11).and_hms(0, 0, 0);
        assert_eq!(can(&vec_eo, &ro).permit(), false);

        ro.date = NaiveDate::from_ymd(2020, 8, 7).and_hms(0, 0, 0);
        assert_eq!(can(&vec_eo, &ro).permit(), false);
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
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        let mut ro = RunOptions::new();
        ro.name = "ed".to_string();
        ro.target = "oracle".to_string();
        ro.date = NaiveDate::from_ymd(2019, 12, 31).and_hms(0, 0, 0);
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        ro.command = "/bin/bash /usr/local/oracle/backup_script".to_string();
        assert_eq!(can(&vec_eo, &ro).permit(), true);

        ro.command = "/bin/sh /usr/local/oracle/backup_script".to_string();
        assert_eq!(can(&vec_eo, &ro).permit(), false);

        ro.hostname = "web1".to_string();
        assert_eq!(can(&vec_eo, &ro).permit(), false);

        ro.hostname = "".to_string();
        assert_eq!(can(&vec_eo, &ro).permit(), false);

        ro.hostname = "localhost".to_string();
        ro.target = "grid".to_string();
        ro.command = "/bin/bash /usr/local/oracle/backup_script".to_string();
        assert_eq!(can(&vec_eo, &ro).permit(), false);

        ro.target = "root".to_string();
        assert_eq!(can(&vec_eo, &ro).permit(), false);
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
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        let mut ro = RunOptions::new();
        ro.name = "ed".to_string();
        ro.target = "oracle".to_string();
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        ro.command = "/bin/bash /usr/local/oracle/backup_script".to_string();
        assert_eq!(can(&vec_eo, &ro).permit(), true);

        ro.command = "/bin/sh /usr/local/oracle/backup_script".to_string();
        assert_eq!(can(&vec_eo, &ro).permit(), false);

        ro.hostname = "web1".to_string();
        assert_eq!(can(&vec_eo, &ro).permit(), false);

        ro.hostname = "".to_string();
        assert_eq!(can(&vec_eo, &ro).permit(), false);

        ro.target = "grid".to_string();
        assert_eq!(can(&vec_eo, &ro).permit(), false);
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
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        let mut ro = RunOptions::new();
        ro.name = "ed".to_string();
        ro.target = "oracle".to_string();
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        ro.command = "/bin/bash /usr/local/oracle/backup_script".to_string();
        assert_eq!(can(&vec_eo, &ro).permit(), false);

        ro.hostname = "web1".to_string();
        assert_eq!(can(&vec_eo, &ro).permit(), true);

        ro.hostname = "web2".to_string();
        assert_eq!(can(&vec_eo, &ro).permit(), false);

        ro.hostname = "localhost".to_string();
        ro.command = "/bin/sh /usr/local/oracle/backup_script".to_string();
        assert_eq!(can(&vec_eo, &ro).permit(), true);

        ro.hostname = "web1".to_string();
        assert_eq!(can(&vec_eo, &ro).permit(), true);

        ro.hostname = "web2".to_string();
        assert_eq!(can(&vec_eo, &ro).permit(), true);
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
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        let mut ro = RunOptions::new();
        ro.name = "".to_string();
        ro.target = "oracle".to_string();
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        assert_eq!(can(&vec_eo, &ro).permit(), false);
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
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        let mut ro = RunOptions::new();
        ro.name = "ed".to_string();
        ro.target = "oracle".to_string();
        ro.command = "/bin/bash".to_string();
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        assert_eq!(can(&vec_eo, &ro).permit(), true);
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
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        let mut ro = RunOptions::new();
        ro.date = NaiveDate::from_ymd(2020, 1, 1).and_hms(0, 0, 0);
        ro.name = "ed".to_string();
        ro.target = "root".to_string();
        ro.acl_type = Acltype::Edit;
        ro.command = "/etc/apache/httpd2.conf".to_string();
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        assert_eq!(can(&vec_eo, &ro).permit(), true);
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
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        let mut ro = RunOptions::new();
        ro.date = NaiveDate::from_ymd(2020, 1, 1).and_hms(0, 0, 0);
        ro.name = "ed".to_string();
        ro.target = "root".to_string();
        ro.command = "/bin/cat /etc/ed".to_string();
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        assert_eq!(can(&vec_eo, &ro).permit(), true);

        ro.name = "ned".to_string();
        assert_eq!(can(&vec_eo, &ro).permit(), false);
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
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        let mut ro = RunOptions::new();
        ro.date = NaiveDate::from_ymd(2020, 1, 1).and_hms(0, 0, 0);
        ro.name = "ed".to_string();
        ro.target = "root".to_string();
        ro.command = "/bin/cat /etc/ed".to_string();

        assert_eq!(
            read_ini_config_str(&config, &mut vec_eo, &ro, true, &mut bytes, &mut ini_list),
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
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        let mut ro = RunOptions::new();
        ro.date = NaiveDate::from_ymd(2020, 1, 1).and_hms(0, 0, 0);
        ro.name = "ed".to_string();
        ro.target = "root".to_string();
        ro.command = "/bin/cat /etc/ed".to_string();

        assert_eq!(
            read_ini_config_str(&config, &mut vec_eo, &ro, true, &mut bytes, &mut ini_list),
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
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        let mut ro = RunOptions::new();
        ro.date = NaiveDate::from_ymd(2020, 1, 1).and_hms(0, 0, 0);
        ro.name = "ed".to_string();
        ro.target = "root".to_string();
        ro.command = "/bin/cat /etc/ed".to_string();
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        assert_eq!(can(&vec_eo, &ro).permit(), false);

        ro.groups.insert(String::from("users"), 1);
        assert_eq!(can(&vec_eo, &ro).permit(), true);

        ro.groups = HashMap::new();

        ro.groups.insert(String::from("wwwadm"), 1);
        assert_eq!(can(&vec_eo, &ro).permit(), false);
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
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        let mut ro = RunOptions::new();
        ro.date = NaiveDate::from_ymd(2020, 1, 1).and_hms(0, 0, 0);
        ro.name = "ed".to_string();
        ro.target = "root".to_string();
        ro.command = "/bin/cat /etc/ed".to_string();
        ro.acl_type = Acltype::List;
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        assert_eq!(can(&vec_eo, &ro).permit(), true);

        ro.name = "meh".to_string();
        ro.target = "ed".to_string();
        assert_eq!(can(&vec_eo, &ro).permit(), true);

        ro.target = "bob".to_string();
        assert_eq!(can(&vec_eo, &ro).permit(), false);

        ro.target = "root".to_string();
        assert_eq!(can(&vec_eo, &ro).permit(), false);

        ro.name = "bob".to_string();
        ro.target = "ed".to_string();
        assert_eq!(can(&vec_eo, &ro).permit(), false);

        ro.name = "ben".to_string();
        ro.target = "dbaops".to_string();
        assert_eq!(can(&vec_eo, &ro).permit(), true);
        ro.target = "engops".to_string();
        assert_eq!(can(&vec_eo, &ro).permit(), true);

        ro.target = "netops".to_string();
        assert_eq!(can(&vec_eo, &ro).permit(), true);

        ro.target = "wwwops".to_string();
        assert_eq!(can(&vec_eo, &ro).permit(), false);
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
        let mut ini_list: HashMap<String, bool> = HashMap::new();

        let mut ro = RunOptions::new();
        ro.date = NaiveDate::from_ymd(2020, 1, 1).and_hms(0, 0, 0);
        ro.name = "ed".to_string();
        ro.target = "root".to_string();
        ro.command = "/etc/please.ini".to_string();
        ro.acl_type = Acltype::Edit;

        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);
        assert_eq!(can(&vec_eo, &ro).permit(), false);

        ro.groups.insert(String::from("root"), 1);
        assert_eq!(can(&vec_eo, &ro).permit(), false);

        ro.command = "/var/www/html/ed.html".to_string();
        assert_eq!(can(&vec_eo, &ro).permit(), true);

        ro.command = "/var/www/html/%{USER}.html".to_string();
        assert_eq!(can(&vec_eo, &ro).permit(), false);

        ro.groups = HashMap::new();
        ro.groups.insert(String::from("wwwadm"), 1);
        assert_eq!(can(&vec_eo, &ro).permit(), false);
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
        let mut ini_list: HashMap<String, bool> = HashMap::new();

        let mut ro = RunOptions::new();
        ro.name = "ed".to_string();
        ro.target = "root".to_string();
        ro.command = "/var/www/html/ed.html".to_string();
        ro.acl_type = Acltype::Edit;
        ro.groups.insert(String::from("root"), 1);
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        assert_eq!(can(&vec_eo, &ro).permit(), true);
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
        let mut ini_list: HashMap<String, bool> = HashMap::new();

        let mut ro = RunOptions::new();
        ro.name = "ed".to_string();
        ro.target = "root".to_string();
        ro.acl_type = Acltype::Edit;
        ro.command = "/var/www/html/ed.html".to_string();

        ro.groups.insert(String::from("root"), 1);
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);
        assert_eq!(can(&vec_eo, &ro).permit(), false);
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
        let mut ini_list: HashMap<String, bool> = HashMap::new();

        let mut ro = RunOptions::new();
        ro.name = "ed".to_string();
        ro.target = "root".to_string();
        ro.acl_type = Acltype::Edit;
        ro.command = "/var/www/html/ed.html".to_string();
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);
        ro.groups.insert(String::from("root"), 1);
        assert_eq!(can(&vec_eo, &ro).permit(), true);
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
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        let mut ro = RunOptions::new();
        ro.name = "ed".to_string();
        ro.target = "root".to_string();
        ro.acl_type = Acltype::Run;
        ro.command = "/bin/bash".to_string();
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);
        assert_eq!(
            vec_eo
                .iter()
                .next()
                .unwrap()
                .rule
                .as_ref()
                .unwrap()
                .as_str(),
            "/bin/bash"
        );

        assert_eq!(can(&vec_eo, &ro).permit(), false);

        ro.groups.insert(String::from("root"), 1);
        ro.command = "/bin/sh".to_string();
        assert_eq!(can(&vec_eo, &ro).permit(), false);

        ro.command = "/bin/bash".to_string();
        assert_eq!(can(&vec_eo, &ro).permit(), true);

        ro.target = "woot".to_string();
        assert_eq!(can(&vec_eo, &ro).permit(), true);
    }

    #[test]
    fn test_edit_regression_empty() {
        let mut vec_eo: Vec<EnvOptions> = vec![];
        let config = "".to_string();
        let mut bytes = 0;
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        let mut ro = RunOptions::new();
        ro.name = "ed".to_string();
        ro.target = "root".to_string();
        ro.acl_type = Acltype::Edit;
        ro.command = "/etc/please.ini".to_string();
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);
        assert_eq!(can(&vec_eo, &ro).permit(), false);
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
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        let mut ro = RunOptions::new();
        ro.name = "ed".to_string();
        ro.target = "oracle".to_string();
        ro.acl_type = Acltype::Run;
        ro.command = "/bin/bash".to_string();
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        assert_eq!(can(&vec_eo, &ro).permit(), false);

        ro.directory = Some("/".to_string());
        assert_eq!(can(&vec_eo, &ro).permit(), true);
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
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        let mut ro = RunOptions::new();
        ro.date = NaiveDate::from_ymd(2020, 1, 1).and_hms(0, 0, 0);
        ro.name = "ed".to_string();
        ro.target = "oracle".to_string();
        ro.acl_type = Acltype::Run;
        ro.command = "/bin/bash".to_string();
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        assert_eq!(can(&vec_eo, &ro).permit(), false, "no directory given",);

        ro.directory = Some("/".to_string());
        assert_eq!(
            can(&vec_eo, &ro).permit(),
            false,
            "change outside permitted",
        );

        ro.directory = Some("/var/www".to_string());
        assert_eq!(can(&vec_eo, &ro).permit(), true, "permitted");
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
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        let mut ro = RunOptions::new();
        ro.date = NaiveDate::from_ymd(2020, 1, 1).and_hms(0, 0, 0);
        ro.name = "ed".to_string();
        ro.target = "root".to_string();
        ro.acl_type = Acltype::Run;
        ro.command = "/bin/bash".to_string();
        ro.directory = Some("/tmp".to_string());
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        assert_eq!(can(&vec_eo, &ro).permit(), true, "dir_tmp",);
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
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        let mut ro = RunOptions::new();
        ro.date = NaiveDate::from_ymd(2020, 1, 1).and_hms(0, 0, 0);
        ro.name = "ed".to_string();
        ro.target = "oracle".to_string();
        ro.acl_type = Acltype::Run;
        ro.command = "/bin/bash".to_string();
        ro.directory = Some("/".to_string());
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        assert_eq!(can(&vec_eo, &ro).permit(), false, "directory given",);

        ro.directory = Some("".to_string());
        assert_eq!(can(&vec_eo, &ro).permit(), false, "directory given",);
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
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        let mut ro = RunOptions::new();
        ro.name = "ed".to_string();
        ro.date = NaiveDate::from_ymd(2020, 10, 02).and_hms(22, 0, 0);
        ro.target = "root".to_string();
        ro.acl_type = Acltype::Run;
        ro.command = "/bin/bash".to_string();
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        assert_eq!(can(&vec_eo, &ro).permit(), true);

        ro.date = NaiveDate::from_ymd(2020, 10, 01).and_hms(22, 0, 0);
        assert_eq!(can(&vec_eo, &ro).permit(), false);

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
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);
        ro.date = NaiveDate::from_ymd(2020, 10, 02).and_hms(21, 0, 0);
        assert_eq!(can(&vec_eo, &ro).permit(), false);
        ro.date = NaiveDate::from_ymd(2020, 10, 02).and_hms(23, 0, 0);
        assert_eq!(can(&vec_eo, &ro).permit(), false);
        ro.date = NaiveDate::from_ymd(2020, 10, 02).and_hms(22, 0, 0);
        assert_eq!(can(&vec_eo, &ro).permit(), true);

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
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);
        ro.date = NaiveDate::from_ymd(2020, 10, 01).and_hms(21, 0, 0);
        assert_eq!(can(&vec_eo, &ro).permit(), false);
        ro.date = NaiveDate::from_ymd(2020, 10, 01).and_hms(23, 0, 0);
        assert_eq!(can(&vec_eo, &ro).permit(), false);
        ro.date = NaiveDate::from_ymd(2020, 10, 01).and_hms(22, 0, 0);
        assert_eq!(can(&vec_eo, &ro).permit(), true);
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
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        let mut ro = RunOptions::new();
        ro.name = "ed".to_string();
        ro.target = "root".to_string();
        ro.acl_type = Acltype::Edit;
        ro.command = "/etc/please.ini".to_string();
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        let entry = can(&vec_eo, &ro);

        assert!(matches!(entry.edit_mode, Some(EditMode::Mode(420))));

        let config = "
[edit_filemode]
name=ed
target=root
regex=/etc/please.ini.*
type=edit
editmode=keep
"
        .to_string();

        bytes = 0;
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        let entry = can(&vec_eo, &ro);

        assert!(matches!(entry.edit_mode, Some(EditMode::Keep(true))));
    }

    #[test]
    fn test_read_ini_config_file() {
        let mut vec_eo: Vec<EnvOptions> = vec![];
        let mut ro = RunOptions::new();
        ro.name = "ed".to_string();
        ro.target = "root".to_string();
        ro.acl_type = Acltype::Edit;
        ro.command = "/etc/please.ini".to_string();

        let mut bytes = 0;
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        assert_eq!(
            read_ini_config_file(".", &mut vec_eo, &ro, true, &mut bytes, &mut ini_list),
            true
        );
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        assert_eq!(
            read_ini_config_file("", &mut vec_eo, &ro, true, &mut bytes, &mut ini_list),
            true
        );
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        assert_eq!(
            read_ini_config_file(
                "./faulty",
                &mut vec_eo,
                &ro,
                true,
                &mut bytes,
                &mut ini_list
            ),
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
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        let mut ro = RunOptions::new();
        ro.name = "ed".to_string();
        ro.target = "root".to_string();
        ro.command = "/bin/bash".to_string();
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        let entry = can(&vec_eo, &ro);

        assert_eq!(entry.permit(), false);
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
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        let mut ro = RunOptions::new();
        ro.name = "ed".to_string();
        ro.target = "root".to_string();
        ro.command = "/bin/bash".to_string();
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        let entry = can(&vec_eo, &ro);

        assert_eq!(entry.reason, Some(ReasonType::Need(true)));
    }

    #[test]
    fn test_regex_build_user_expansion() {
        let mut ro = RunOptions::new();
        ro.name = "ed".to_string();
        ro.target = "root".to_string();
        ro.command = "/bin/bash".to_string();

        let regex_re =
            regex_build("/var/www/html/%{USER}/page.html", &ro, "/", "none", None).unwrap();

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
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        let mut ro = RunOptions::new();
        ro.name = "ed".to_string();
        ro.target = "root".to_string();
        ro.command = "/bin/bash".to_string();
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        let entry = can(&vec_eo, &ro);

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
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        let mut ro = RunOptions::new();
        ro.name = "ed".to_string();
        ro.target = "root".to_string();

        ro.command = "/usr/bin/wc /var/log/messages /var/log/syslog /var/log/maillog".to_string();

        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);
        assert_eq!(can(&vec_eo, &ro).permit(), true);

        ro.command = "/usr/bin/wc /var/log/messages /var/log/messages.1".to_string();
        assert_eq!(can(&vec_eo, &ro).permit(), true);

        ro.command =
            "/usr/bin/wc /var/log/messages /var/log/syslog /var/log/maillog /var/log/../../shadow"
                .to_string();
        assert_eq!(can(&vec_eo, &ro).permit(), false);

        ro.command = "/usr/bin/wc".to_string();
        assert_eq!(can(&vec_eo, &ro).permit(), false);

        ro.command = "/usr/bin/wc /etc/shadow".to_string();
        assert_eq!(can(&vec_eo, &ro).permit(), false);

        ro.command = "/usr/bin/wc".to_string();
        assert_eq!(can(&vec_eo, &ro).permit(), false);

        ro.command = "/usr/bin/wc /var/log/messages /var/log/messages.1 /var/log/../../etc/shadow"
            .to_string();
        assert_eq!(can(&vec_eo, &ro).permit(), false);
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
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        let mut ro = RunOptions::new();
        ro.name = "ed".to_string();
        ro.target = "root".to_string();
        ro.groups.insert(String::from("lpadmin"), 1);
        ro.acl_type = Acltype::Edit;
        ro.command = "/etc/please.ini".to_string();
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);
        assert_eq!(can(&vec_eo, &ro).permit(), true);
    }

    #[test]
    fn test_ini_relative() {
        let mut vec_eo: Vec<EnvOptions> = vec![];
        let config = "
[inc]
include = ./some.ini
"
        .to_string();
        let mut ro = RunOptions::new();
        ro.name = "ed".to_string();
        ro.target = "ed".to_string();
        ro.acl_type = Acltype::List;
        ro.command = "".to_string();

        let mut bytes = 0;
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        assert_eq!(
            read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list),
            true
        );

        let config = "
[inc]
includedir = ./dir.d/some.ini
"
        .to_string();
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        assert_eq!(
            read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list),
            true
        );

        let config = "
[inc]
includedir = /dev/null
"
        .to_string();
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        assert_eq!(
            read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list),
            false
        );
    }

    #[test]
    fn test_ini_repeat() {
        let mut vec_eo: Vec<EnvOptions> = vec![];
        let config = "
[ed]
name=ed
rule=.*
syslog=false
reason=false
"
        .to_string();
        let mut bytes = 0;
        let mut ini_list: HashMap<String, bool> = HashMap::new();

        let mut ro = RunOptions::new();
        ro.name = "ed".to_string();
        ro.target = "ed".to_string();
        ro.acl_type = Acltype::List;
        ro.command = "".to_string();

        let _ = read_ini(
            &config,
            &mut vec_eo,
            &ro,
            false,
            "/etc/please.ini",
            &mut bytes,
            &mut ini_list,
        );

        assert_eq!(ini_list.contains_key("/etc/please.ini"), true);
    }

    #[test]
    fn test_can_include() {
        assert_eq!(can_dir_include("/etc/please.ini.z"), false);
        assert_eq!(can_dir_include("/etc/.please.ini"), false);
        assert_eq!(can_dir_include("/etc/.please.ini."), false);
    }

    #[test]
    fn test_can_include_pattern() {
        assert_eq!(can_include_file_pattern("/etc/please.ini"), true);
        assert_eq!(can_include_file_pattern("/etc/please.please.ini"), true);
        assert_eq!(can_include_file_pattern("/etc/please.d/ini.z"), false);
        assert_eq!(can_include_file_pattern("/etc/please.d/file.ini"), true);
        assert_eq!(can_include_file_pattern("/etc/please.d/.file.ini"), false);
        assert_eq!(can_include_file_pattern("/etc/please.d/.file"), false);
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

    #[test]
    // this will fail at a point in the future - if so, try and run it again
    // we need some random assurance
    fn test_prng_alpha_num_unique() {
        let length = 8;
        let a = prng_alpha_num_string(length);
        for _ in 1..100 {
            assert_ne!(a, prng_alpha_num_string(length));
        }
    }

    #[test]
    fn test_list_output() {
        let config = "
[list]
name = %{USER}
reason = false
type = list
"
        .to_string();
        let mut vec_eo: Vec<EnvOptions> = vec![];
        let mut bytes = 0;
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        let mut ro = RunOptions::new();
        ro.name = "ed".to_string();
        ro.target = "ed".to_string();
        ro.acl_type = Acltype::List;
        ro.command = "".to_string();
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        let list = produce_list(&vec_eo, &ro);
        assert_eq!(list, ["  in file: static", "    list:list: root"]);
    }

    #[test]
    fn test_environment_provided_but_not_allowed() {
        let config = "
[env_nopes]
name = %{USER}
reason = false
"
        .to_string();
        let mut vec_eo: Vec<EnvOptions> = vec![];
        let mut bytes = 0;
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        let mut ro = RunOptions::new();
        ro.name = "ed".to_string();
        ro.target = "root".to_string();
        ro.command = "".to_string();
        ro.allow_env_list = Some(vec!["PATH".to_string()]);
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        assert_eq!(can(&vec_eo, &ro).permit(), false);
    }

    #[test]
    fn test_environment_assign_env_list() {
        let config = "
[ed_part_allowed]
name = %{USER}
reason = false
type = run
env_assign.ILIKETO = moveitmoveit
env_assign.JOE = 90
regex = .*
"
        .to_string();
        let mut vec_eo: Vec<EnvOptions> = vec![];
        let mut bytes = 0;
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        let mut ro = RunOptions::new();
        ro.name = "ed".to_string();
        ro.target = "root".to_string();
        ro.command = "".to_string();
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);
        let entry = can(&vec_eo, &ro);

        assert_eq!(
            entry.env_assign.as_ref().unwrap().get("ILIKETO").unwrap(),
            "moveitmoveit"
        );
        assert_eq!(entry.env_assign.as_ref().unwrap().get("JOE").unwrap(), "90");
    }

    #[test]
    fn test_environment_provided_and_allowed() {
        let config = "
[ed_part_allowed]
name = %{USER}
reason = false
type = run
permit_env = (HOME|PATH)
"
        .to_string();
        let mut vec_eo: Vec<EnvOptions> = vec![];
        let mut bytes = 0;
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        let mut ro = RunOptions::new();
        ro.name = "ed".to_string();
        ro.target = "root".to_string();
        ro.command = "".to_string();
        ro.allow_env_list = Some(vec!["PATH".to_string(), "HOME".to_string()]);
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        assert_eq!(can(&vec_eo, &ro).permit(), true);
    }

    #[test]
    fn test_environment_provided_but_some_allowed() {
        let config = "
[ed_part_allowed]
name = %{USER}
reason = false
type = run
permit_env = (HOME|PATH)
"
        .to_string();
        let mut vec_eo: Vec<EnvOptions> = vec![];
        let mut bytes = 0;
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        let mut ro = RunOptions::new();
        ro.name = "ed".to_string();
        ro.target = "root".to_string();
        ro.command = "".to_string();
        ro.allow_env_list = Some(vec![
            "PATH".to_string(),
            "HOME".to_string(),
            "DISASTER".to_string(),
        ]);
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        assert_eq!(can(&vec_eo, &ro).permit(), false);
    }

    #[test]
    fn test_environment_not_provided_others_allowed() {
        let config = "
[ed_part_allowed]
name = %{USER}
type = run
permit_env = (HOME|PATH)
"
        .to_string();
        let mut vec_eo: Vec<EnvOptions> = vec![];
        let mut bytes = 0;
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        let mut ro = RunOptions::new();
        ro.name = "ed".to_string();
        ro.target = "root".to_string();
        ro.command = "".to_string();
        ro.allow_env_list = None;
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        assert_eq!(can(&vec_eo, &ro).permit(), true);
    }

    #[test]
    fn test_percent_user() {
        let config = "
[ed]
name = ed
type = run
target = root
regex = /bin/echo [%]\\{USER\\}
"
        .to_string();
        let mut vec_eo: Vec<EnvOptions> = vec![];
        let mut bytes = 0;
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        let mut ro = RunOptions::new();
        ro.name = "ed".to_string();
        ro.target = "root".to_string();
        ro.command = "/bin/echo %{USER}".to_string();
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        assert_eq!(can(&vec_eo, &ro).permit(), true);
    }

    #[test]
    fn test_percent_user_as_hex() {
        let config = "
[ed]
name = ed
type = run
target = root
regex = /bin/echo \\x25\\{USER\\}
"
        .to_string();
        let mut vec_eo: Vec<EnvOptions> = vec![];
        let mut bytes = 0;
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        let mut ro = RunOptions::new();
        ro.name = "ed".to_string();
        ro.target = "root".to_string();
        ro.command = "/bin/echo %{USER}".to_string();
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        assert_eq!(can(&vec_eo, &ro).permit(), true);
    }

    #[test]
    fn test_internal_backslash() {
        let config = "
[ed]
name = ed
type = run
target = root
regex = /bin/echo hello\\x5cworld
"
        .to_string();
        let mut vec_eo: Vec<EnvOptions> = vec![];
        let mut bytes = 0;
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        let mut ro = RunOptions::new();
        ro.name = "ed".to_string();
        ro.target = "root".to_string();
        ro.command = "/bin/echo hello\\world".to_string();
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        assert_eq!(can(&vec_eo, &ro).permit(), true);
    }

    #[test]
    fn test_internal_backslash_as_class() {
        let config = "
[ed]
name = ed
type = run
target = root
regex = /bin/echo hello[\\\\]world
"
        .to_string();
        let mut vec_eo: Vec<EnvOptions> = vec![];
        let mut bytes = 0;
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        let mut ro = RunOptions::new();
        ro.name = "ed".to_string();
        ro.target = "root".to_string();
        ro.command = "/bin/echo hello\\world".to_string();
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        assert_eq!(can(&vec_eo, &ro).permit(), true);
    }

    #[test]
    fn test_replace_new_args_spaces_exact_rule() {
        let config = r#"
[ed]
name = ed
type = run
target = root
exact_rule = /bin/echo hello\ world
"#
        .to_string();
        let mut vec_eo: Vec<EnvOptions> = vec![];
        let mut bytes = 0;
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        let mut ro = RunOptions::new();
        ro.name = "ed".to_string();
        ro.target = "root".to_string();
        ro.command = replace_new_args(vec!["/bin/echo".to_string(), "hello world".to_string()]);
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        assert_eq!(can(&vec_eo, &ro).permit(), true);
    }

    #[test]
    fn test_replace_new_args_spaces_rule() {
        let config = r#"
[ed]
name = ed
type = run
target = root
rule = /bin/echo hello\\ world
"#
        .to_string();
        let mut vec_eo: Vec<EnvOptions> = vec![];
        let mut bytes = 0;
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        let mut ro = RunOptions::new();
        ro.name = "ed".to_string();
        ro.target = "root".to_string();
        ro.command = replace_new_args(vec!["/bin/echo".to_string(), "hello world".to_string()]);
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        assert_eq!(can(&vec_eo, &ro).permit(), true);
    }

    #[test]
    fn test_replace_new_args_internal_backslash_spaces_rule() {
        let config = r#"
[ed]
name = ed
type = run
target = root
rule = /bin/echo hello\\ \\\\\\ world
"#
        .to_string();
        let mut vec_eo: Vec<EnvOptions> = vec![];
        let mut bytes = 0;
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        let mut ro = RunOptions::new();
        ro.name = "ed".to_string();
        ro.target = "root".to_string();
        ro.command = replace_new_args(vec!["/bin/echo".to_string(), "hello \\ world".to_string()]);
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        assert_eq!(can(&vec_eo, &ro).permit(), true);
    }

    #[test]
    fn test_default_edit_file_mode() {
        let config = r#"
[ed]
name = ed
type = edit
target = root
rule = /etc/fstab
"#
        .to_string();
        let mut vec_eo: Vec<EnvOptions> = vec![];
        let mut bytes = 0;
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        let mut ro = RunOptions::new();
        ro.name = "ed".to_string();
        ro.target = "root".to_string();
        ro.acl_type = Acltype::Edit;
        ro.command = replace_new_args(vec!["/etc/fstab".to_string()]);
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        assert_eq!(can(&vec_eo, &ro).edit_mode, None);
    }
}
