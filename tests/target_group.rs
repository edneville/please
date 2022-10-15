use std::collections::HashMap;
mod basic_ro;

#[cfg(test)]
mod test {
    use super::*;
    use basic_ro::*;
    use pleaser::*;

    #[test]
    fn test_target_group_rule() {
        let config = "[ed]
exact_name=ed
exact_target=root
exact_rule = /bin/bash
target_group = potato
"
        .to_string();

        let mut bytes = 0;
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        let mut vec_eo: Vec<EnvOptions> = vec![];
        let mut ro = basic_ro("ed", "root");
        ro.target_group = Some("potato".to_string());

        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        basic_cmd(&mut ro, &"/bin/bash".to_string());
        assert_eq!(can(&vec_eo, &mut ro).permit(), true);

        ro.target_group = Some("potatoes".to_string());
        assert_eq!(can(&vec_eo, &mut ro).permit(), false);

        ro.target_group = None;
        assert_eq!(can(&vec_eo, &mut ro).permit(), false);
    }

    #[test]
    fn test_exact_target_group_rule() {
        let config = "[ed]
exact_name=ed
exact_target=root
exact_rule = /bin/bash
exact_target_group = potato
"
        .to_string();

        let mut bytes = 0;
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        let mut vec_eo: Vec<EnvOptions> = vec![];
        let mut ro = basic_ro("ed", "root");
        ro.target_group = Some("potato".to_string());

        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        basic_cmd(&mut ro, &"/bin/bash".to_string());
        assert_eq!(can(&vec_eo, &mut ro).permit(), true);

        ro.target_group = Some("potatoes".to_string());
        assert_eq!(can(&vec_eo, &mut ro).permit(), false);

        ro.target_group = None;
        assert_eq!(can(&vec_eo, &mut ro).permit(), false);
    }

    #[test]
    fn test_target_group_edit() {
        let config = "
[please_ini]
name = ed
group = false
regex = /etc/please.ini
type = edit
target_group = oracle
"
        .to_string();
        let mut vec_eo: Vec<EnvOptions> = vec![];
        let mut bytes = 0;
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        let mut ro = basic_ro("ed", "root");
        basic_cmd(&mut ro, &"/etc/please.ini".to_string());
        ro.target_group = Some("oracle".to_string());
        ro.acl_type = Acltype::Edit;
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        assert_eq!(can(&vec_eo, &mut ro).permit(), true);

        basic_cmd(&mut ro, &"".to_string());
        assert_eq!(can(&vec_eo, &mut ro).permit(), false);
    }

    #[test]
    fn test_target_group_run() {
        let config = "
[please_ini]
name = ed
group = false
regex = /etc/missing
type = run
target_group = oracle
"
        .to_string();
        let mut vec_eo: Vec<EnvOptions> = vec![];
        let mut bytes = 0;
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        let mut ro = basic_ro("ed", "root");
        basic_cmd(&mut ro, &"/etc/missing".to_string());
        ro.target_group = Some("oracle".to_string());
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        assert_eq!(can(&vec_eo, &mut ro).permit(), false);

        ro.command = "".to_string();
        basic_cmd(&mut ro, &"".to_string());
        assert_eq!(can(&vec_eo, &mut ro).permit(), false);
    }

    // group has no effect in list context
    #[test]
    fn test_target_group_list() {
        let config = "
[please_ini]
name = ed
group = false
regex = /etc/please.ini
type = list
target_group = oracle
"
        .to_string();
        let mut vec_eo: Vec<EnvOptions> = vec![];
        let mut bytes = 0;
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        let mut ro = basic_ro("ed", "root");
        basic_cmd(&mut ro, &"/etc/please.ini".to_string());
        ro.target_group = Some("oracle".to_string());
        ro.acl_type = Acltype::List;
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        assert_eq!(can(&vec_eo, &mut ro).permit(), true);

        basic_cmd(&mut ro, &"".to_string());
        assert_eq!(can(&vec_eo, &mut ro).permit(), true);
    }

    #[test]
    fn test_target_group_run_given_but_not_configured() {
        let config = "
[please_ini]
name = ed
group = false
regex = /etc/please.ini
type = edit
"
        .to_string();
        let mut vec_eo: Vec<EnvOptions> = vec![];
        let mut bytes = 0;
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        let mut ro = basic_ro("ed", "root");
        basic_cmd(&mut ro, &"/etc/please.ini".to_string());
        ro.target_group = Some("oracle".to_string());
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        assert_eq!(can(&vec_eo, &mut ro).permit(), false);
    }
}
