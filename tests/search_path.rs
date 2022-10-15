use std::collections::HashMap;
mod basic_ro;

#[cfg(test)]
mod test {
    use super::*;
    use basic_ro::*;
    use pleaser::*;

    #[test]
    fn test_search_path() {
        let config = "[ed]
exact_name=ed
exact_target=root
exact_rule = /bin/bash
search_path = :
"
        .to_string();

        let mut bytes = 0;
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        let mut vec_eo: Vec<EnvOptions> = vec![];
        let mut ro = basic_ro("ed", "root");

        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        basic_cmd(&mut ro, &"bash".to_string());
        assert_eq!(can(&vec_eo, &mut ro).permit(), false);
    }

    #[test]
    fn test_search_empty_path() {
        let config = "[ed]
exact_name=ed
exact_target=root
exact_rule = /bin/bash
search_path =
"
        .to_string();

        let mut bytes = 0;
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        let mut vec_eo: Vec<EnvOptions> = vec![];
        let mut ro = basic_ro("ed", "root");

        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        basic_cmd(&mut ro, &"bash".to_string());
        assert_eq!(can(&vec_eo, &mut ro).permit(), false);
    }

    #[test]
    fn test_search_unlikely_to_exist_dir() {
        let config = "[ed]
exact_name=ed
exact_target=root
rule = .*/bash
search_path = /nonexistent
"
        .to_string();

        let mut bytes = 0;
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        let mut vec_eo: Vec<EnvOptions> = vec![];
        let mut ro = basic_ro("ed", "root");

        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        basic_cmd(&mut ro, &"bash".to_string());
        assert_eq!(can(&vec_eo, &mut ro).permit(), false);
    }

    #[test]
    fn test_search_bin() {
        let config = "[ed]
exact_name=ed
exact_target=root
rule = .*/bash
search_path = /bin
"
        .to_string();

        let mut bytes = 0;
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        let mut vec_eo: Vec<EnvOptions> = vec![];
        let mut ro = basic_ro("ed", "root");

        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        basic_cmd(&mut ro, &"bash".to_string());
        let c = can(&vec_eo, &mut ro);
        assert_eq!(c.permit(), true);
        assert_eq!(ro.command, "/bin/bash");
    }

    #[test]
    fn test_search_bin_default() {
        let config = "
[default_all]
name = .*
target = root
rule = .*
search_path = /bin 

[ed]
exact_name=ed
exact_target=root
rule = .*/bash
"
        .to_string();

        let mut bytes = 0;
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        let mut vec_eo: Vec<EnvOptions> = vec![];
        let mut ro = basic_ro("ed", "root");

        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        basic_cmd(&mut ro, &"bash".to_string());
        let c = can(&vec_eo, &mut ro);
        assert_eq!(ro.command, "/bin/bash");
        assert_eq!(c.permit(), true);
    }

    #[test]
    fn test_search_bin_default_sbin() {
        let config = "
[default:all]
name = .*
target = .*
rule = .*
search_path = /sbin

[ed]
name=ed
target=root
rule = .*/e2fsck
"
        .to_string();

        let mut bytes = 0;
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        let mut vec_eo: Vec<EnvOptions> = vec![];
        let mut ro = basic_ro("ed", "root");

        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        basic_cmd(&mut ro, &"e2fsck".to_string());
        let c = can(&vec_eo, &mut ro);
        dbg!(&c);
        assert_eq!(c.permit(), true);
        assert_eq!(ro.command, "/sbin/e2fsck");
        assert_eq!(c.search_path, Some("/sbin".to_string()));
    }
}
