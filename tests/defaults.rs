use chrono::NaiveDate;
use std::collections::HashMap;

#[cfg(test)]
mod test {
    use super::*;
    use pleaser::*;

    #[test]
    fn test_basic_default_non_match() {
        let config = "[default:syslog_off]
name = ben
rule = .*
syslog = false

[ed]
name = ed
rule = .*
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
        let can = can(&vec_eo, &ro);
        assert_eq!(can.syslog.is_some(), false);
    }

    #[test]
    fn test_basic_default_syslog() {
        let config = "[default:syslog_off]
name = .*
rule = .*
syslog = false

[ed]
name = ed
rule = .*
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
        let can = can(&vec_eo, &ro);
        assert_eq!(can.syslog.is_some(), true);
        assert_eq!(can.syslog.unwrap(), false);
    }

    #[test]
    fn test_basic_default_timeout() {
        let config = "[default]
name = .*
rule = .*

[ed]
name = ed
rule = .*
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
        let can = can(&vec_eo, &ro);
        assert_eq!(can.permit(), true);
        assert_eq!(can.timeout.is_none(), true);
    }

    #[test]
    fn test_layered_match() {
        let config = "[default:syslog_off]
name = ed
rule = .*
syslog = false

[default:require_pass]
name = ed
rule = .*
require_pass = true

[default:timeout]
name = ed
rule = .*
timeout = 30

[ed]
name = ed
rule = .*
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
        let can = can(&vec_eo, &ro);
        assert_eq!(can.syslog.is_some(), true);
        assert_eq!(can.syslog.unwrap(), false);
        assert_eq!(can.require_pass.is_some(), true);
        assert_eq!(can.require_pass.unwrap(), true);
        assert_eq!(can.timeout.is_some(), true);
        assert_eq!(can.timeout.unwrap(), 30);
    }

    #[test]
    fn test_layered_fail_match() {
        let config = "[default:syslog_off]
name = ed
rule = .*
syslog = false

[default:require_pass]
name = ed
rule = /nopes
require_pass = true

[default:timeout]
name = ed
rule = .*
notafter = 20191231
timeout = 30

[ed]
name = ed
rule = .*
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
        let can = can(&vec_eo, &ro);
        assert_eq!(can.syslog.is_some(), true);
        assert_eq!(can.syslog.unwrap(), false);
        assert_eq!(can.require_pass.is_none(), true);
        assert_eq!(can.timeout.is_none(), true);
    }

    #[test]
    fn test_generic_match() {
        let config = "[default:syslog_off]
rule = .*
name = .*
syslog = false
permit = false

[ed]
name = ed
rule = .*
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
        let can = can(&vec_eo, &ro);
        assert_eq!(can.syslog.is_some(), true);
        assert_eq!(can.syslog.unwrap(), false);
        assert_eq!(can.permit(), false);
    }

    #[test]
    fn test_generic_true_match() {
        let config = "[default:syslog_off]
rule = .*
name = .*
syslog = false

[ed]
name = ed
rule = .*
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
        let can = can(&vec_eo, &ro);
        assert_eq!(can.syslog.is_some(), true);
        assert_eq!(can.syslog.unwrap(), false);
        assert_eq!(can.permit(), true);
    }

    #[test]
    fn test_multilpe_non_match() {
        let config = "[default:syslog_off]
rule = /bin/bash
exact_name = ben
syslog = false

[default:timeout_off]
rule = /bin/sh
name = .*
timeout = 100

[default:require_pass]
hostname = webby
name = .*
permit = false

[ed]
name = ed
rule = .*
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
        let can = can(&vec_eo, &ro);
        assert_eq!(can.syslog.is_none(), true);
        assert_eq!(can.timeout.is_none(), true);
        assert_eq!(can.permit(), true);
    }
}
