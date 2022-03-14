use chrono::NaiveDate;
use std::collections::HashMap;

#[cfg(test)]
mod test {
    use super::*;
    use pleaser::*;

    #[test]
    fn test_exact_rule() {
        let config = "[ed]
exact_name=ed
exact_target=root
exact_rule = /bin/bash
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

        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        ro.command = "/bin/bash".to_string();
        assert_eq!(can(&vec_eo, &ro).permit(), true);

        ro.command = "/bin/bashz".to_string();
        assert_eq!(can(&vec_eo, &ro).permit(), false);

        ro.command = "/".to_string();
        assert_eq!(can(&vec_eo, &ro).permit(), false);
    }

    #[test]
    fn test_exact_rule_parameters() {
        let config = "[ed]
exact_name=ed
exact_target=root
exact_rule = /bin/bash
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

        ro.command = "/bin/bash file".to_string();
        assert_eq!(can(&vec_eo, &ro).permit(), false);

        let config = "[ed]
exact_name=ed
exact_target=root
exact_rule = /bin/bash file
"
        .to_string();
        let mut vec_eo: Vec<EnvOptions> = vec![];
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        ro.command = "/bin/bash".to_string();
        assert_eq!(can(&vec_eo, &ro).permit(), false);

        ro.command = "/bin/bash file".to_string();
        assert_eq!(can(&vec_eo, &ro).permit(), true);

        let config = "[ed]
exact_name=ed
exact_target=root
exact_rule = /bin/bash echo\\ hello\\ world
"
        .to_string();
        let mut vec_eo: Vec<EnvOptions> = vec![];
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        ro.command = "/bin/bash".to_string();
        assert_eq!(can(&vec_eo, &ro).permit(), false);

        ro.command = "/bin/bash echo\\ hello\\ world".to_string();
        assert_eq!(can(&vec_eo, &ro).permit(), true);
    }

    #[test]
    fn test_exact_name() {
        let config = "[ed]
exact_name=ed
exact_target=root
exact_rule = /bin/bash
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

        ro.name = "jim".to_string();
        assert_eq!(can(&vec_eo, &ro).permit(), false);

        ro.command = "edd".to_string();
        assert_eq!(can(&vec_eo, &ro).permit(), false);
    }

    #[test]
    fn test_exact_target() {
        let config = "[ed]
exact_name=ed
exact_target=root
exact_rule = /bin/bash
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

        ro.target = "jim".to_string();
        assert_eq!(can(&vec_eo, &ro).permit(), false);

        ro.target = "edd".to_string();
        assert_eq!(can(&vec_eo, &ro).permit(), false);
    }

    #[test]
    fn test_exact_hostname() {
        let config = "[ed]
exact_name=ed
exact_target=root
exact_hostname=thing
exact_rule = /bin/bash
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
        ro.hostname = "thing".to_string();
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);
        assert_eq!(can(&vec_eo, &ro).permit(), true);

        ro.hostname = "".to_string();
        assert_eq!(can(&vec_eo, &ro).permit(), false);

        ro.hostname = "web".to_string();
        assert_eq!(can(&vec_eo, &ro).permit(), false);

        ro.hostname = "localhost".to_string();
        assert_eq!(can(&vec_eo, &ro).permit(), false);

        let config = "[ed]
exact_name=ed
exact_target=root
exact_hostname=localhost
exact_rule = /bin/bash
"
        .to_string();

        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        ro.hostname = "thing".to_string();
        assert_eq!(can(&vec_eo, &ro).permit(), true);
    }

    #[test]
    fn test_exact_dir() {
        let config = "[ed]
exact_name=ed
exact_target=root
exact_rule = /bin/sh
exact_dir = /root
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
        ro.command = "/bin/sh".to_string();
        ro.directory = Some("/root".to_string());
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        assert_eq!(can(&vec_eo, &ro).permit(), true);

        ro.directory = Some("/home".to_string());
        assert_eq!(can(&vec_eo, &ro).permit(), false);

        ro.directory = Some("/".to_string());
        assert_eq!(can(&vec_eo, &ro).permit(), false);
    }

    #[test]
    fn test_exact_name_precedence() {
        let config = "[ed]
exact_name=ed
name = zz
exact_target=root
exact_rule = /bin/bash
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

        ro.name = "zz".to_string();
        assert_eq!(can(&vec_eo, &ro).permit(), false);

        let config = "[ed]
exact_name=
name=zz
exact_target=root
exact_rule = /bin/bash
"
        .to_string();
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        ro.name = "zz".to_string();
        assert_eq!(can(&vec_eo, &ro).permit(), false);
    }

    #[test]
    fn test_exact_rule_precedence() {
        let config = "[ed]
exact_name=ed
exact_target=root
exact_rule = /bin/sh
rule = /bin/bash
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
        ro.command = "/bin/sh".to_string();
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        assert_eq!(can(&vec_eo, &ro).permit(), true);

        ro.command = "/bin/bash".to_string();
        assert_eq!(can(&vec_eo, &ro).permit(), false);
    }

    #[test]
    fn test_exact_target_precedence() {
        let config = "[ed]
exact_name=ed
exact_target=root
target=bob
exact_rule = /bin/sh
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
        ro.command = "/bin/sh".to_string();
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        assert_eq!(can(&vec_eo, &ro).permit(), true);

        ro.target = "bob".to_string();
        assert_eq!(can(&vec_eo, &ro).permit(), false);
    }

    #[test]
    fn test_exact_dir_precedence() {
        let config = "[ed]
exact_name=ed
exact_target=root
exact_rule = /bin/sh
exact_dir = /root
dir = .*
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
        ro.command = "/bin/sh".to_string();
        ro.directory = Some("/root".to_string());
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        assert_eq!(can(&vec_eo, &ro).permit(), true);

        ro.directory = Some("/home".to_string());
        assert_eq!(can(&vec_eo, &ro).permit(), false);
    }
}
