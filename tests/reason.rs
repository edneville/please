use chrono::NaiveDate;
use std::collections::HashMap;

#[cfg(test)]
mod test {
    use super::*;
    use pleaser::*;

    #[test]
    fn test_reason_abscence() {
        let config = "[ed]
exact_name=ed
exact_target=root
exact_rule = /bin/bash
reason = true
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
        let can_do = can(&vec_eo, &ro);
        assert_eq!((can_do).permit, true);
        assert_eq!(reason_ok(&can_do, &ro, "please"), false);
    }

    #[test]
    fn test_reason_present() {
        let config = "[ed]
exact_name=ed
exact_target=root
exact_rule = /bin/bash
reason = true
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
        ro.reason = Some("simple reason".to_string());

        ro.command = "/bin/bash".to_string();
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);
        let can_do = can(&vec_eo, &ro);
        assert_eq!((can_do).permit, true);
        assert_eq!(reason_ok(&can_do, &ro, "please"), true);
    }

    #[test]
    fn test_reason_present_bad_match() {
        let config = "[ed]
exact_name=ed
exact_target=root
exact_rule = /bin/bash
reason = bigdb
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
        ro.reason = Some("simple reason".to_string());

        ro.command = "/bin/bash".to_string();
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);
        let can_do = can(&vec_eo, &ro);
        assert_eq!((can_do).permit, true);
        assert_eq!(reason_ok(&can_do, &ro, "please"), false);
    }

    #[test]
    fn test_reason_present_good_match() {
        let config = "[ed]
exact_name=ed
exact_target=root
exact_rule = /bin/bash
reason = bigdb
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
        ro.reason = Some("bigdb".to_string());
        ro.command = "/bin/bash".to_string();

        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);
        let can_do = can(&vec_eo, &ro);
        assert_eq!((can_do).permit, true);
        assert_eq!(reason_ok(&can_do, &ro, "please"), true);
    }

    #[test]
    fn test_reason_present_good_host_match() {
        let config = "[ed]
exact_name=ed
exact_target=root
exact_rule = /sbin/poweroff
reason = .*%{HOSTNAME}.*
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
        ro.reason = Some("power off localhost".to_string());
        ro.command = "/sbin/poweroff".to_string();

        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);
        let can_do = can(&vec_eo, &ro);
        assert_eq!((can_do).permit, true);
        assert_eq!(reason_ok(&can_do, &ro, "please"), true);

        ro.reason = Some("power off".to_string());
        assert_eq!(reason_ok(&can_do, &ro, "please"), false);

        ro.reason = Some("localhost".to_string());
        assert_eq!(reason_ok(&can_do, &ro, "please"), true);
    }
}
