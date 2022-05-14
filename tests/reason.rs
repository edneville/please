use std::collections::HashMap;
mod basic_ro;

#[cfg(test)]
mod test {
    use super::*;
    use basic_ro::*;
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
        let mut ro = basic_ro("ed", "root");

        ro.command = "/bin/bash".to_string();
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);
        let can_do = can(&vec_eo, &ro);
        assert_eq!((can_do).permit(), true);
        assert_eq!(reason_ok(&can_do, &ro), false);
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
        let mut ro = basic_ro("ed", "root");
        ro.reason = Some("simple reason".to_string());

        ro.command = "/bin/bash".to_string();
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);
        let can_do = can(&vec_eo, &ro);
        assert_eq!((can_do).permit(), true);
        assert_eq!(reason_ok(&can_do, &ro), true);
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
        let mut ro = basic_ro("ed", "root");
        ro.reason = Some("simple reason".to_string());

        ro.command = "/bin/bash".to_string();
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);
        let can_do = can(&vec_eo, &ro);
        assert_eq!((can_do).permit(), true);
        assert_eq!(reason_ok(&can_do, &ro), false);
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
        let mut ro = basic_ro("ed", "root");
        ro.reason = Some("bigdb".to_string());
        ro.command = "/bin/bash".to_string();

        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);
        let can_do = can(&vec_eo, &ro);
        assert_eq!((can_do).permit(), true);
        assert_eq!(reason_ok(&can_do, &ro), true);
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
        let mut ro = basic_ro("ed", "root");
        ro.reason = Some("power off localhost".to_string());
        ro.command = "/sbin/poweroff".to_string();

        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);
        let can_do = can(&vec_eo, &ro);
        assert_eq!((can_do).permit(), true);
        assert_eq!(reason_ok(&can_do, &ro), true);

        ro.reason = Some("power off".to_string());
        assert_eq!(reason_ok(&can_do, &ro), false);

        ro.reason = Some("localhost".to_string());
        assert_eq!(reason_ok(&can_do, &ro), true);
    }
}
