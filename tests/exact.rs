use std::collections::HashMap;
mod basic_ro;

#[cfg(test)]
mod test {
    use super::*;
    use basic_ro::*;
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
        let mut ro = basic_ro("ed", "root");

        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        basic_cmd(&mut ro, &"/bin/bash".to_string());
        assert_eq!(can(&vec_eo, &mut ro).permit(), true);

        ro = RunOptions::new();
        basic_cmd(&mut ro, &"/bin/bashz".to_string());
        assert_eq!(can(&vec_eo, &mut ro).permit(), false);

        ro = RunOptions::new();
        basic_cmd(&mut ro, &"/".to_string());
        assert_eq!(can(&vec_eo, &mut ro).permit(), false);
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
        let mut ro = basic_ro("ed", "root");

        basic_cmd(&mut ro, &"/bin/bash".to_string());
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);
        assert_eq!(can(&vec_eo, &mut ro).permit(), true);

        basic_cmd(&mut ro, &"/bin/bash file".to_string());
        assert_eq!(can(&vec_eo, &mut ro).permit(), false);

        let config = "[ed]
exact_name=ed
exact_target=root
exact_rule = /bin/bash file
"
        .to_string();
        let mut vec_eo: Vec<EnvOptions> = vec![];
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        basic_cmd(&mut ro, &"/bin/bash".to_string());
        assert_eq!(can(&vec_eo, &mut ro).permit(), false);

        basic_cmd(&mut ro, &"/bin/bash file".to_string());
        assert_eq!(can(&vec_eo, &mut ro).permit(), true);

        let config = r#"[ed]
exact_name=ed
exact_target=root
exact_rule = /bin/bash echo\ hello\ world
"#
        .to_string();
        let mut vec_eo: Vec<EnvOptions> = vec![];
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        basic_cmd(&mut ro, &"/bin/bash".to_string());
        assert_eq!(can(&vec_eo, &mut ro).permit(), false);

        //ro.command = "/bin/bash echo\\ hello\\ world".to_string();
        ro.new_args = vec!["/bin/bash".to_string(), r#"echo hello world"#.to_string()];
        assert_eq!(can(&vec_eo, &mut ro).permit(), true);
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
        let mut ro = basic_ro("ed", "root");
        basic_cmd(&mut ro, &"/bin/bash".to_string());

        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);
        assert_eq!(can(&vec_eo, &mut ro).permit(), true);

        ro.name = "jim".to_string();
        assert_eq!(can(&vec_eo, &mut ro).permit(), false);

        ro.command = "edd".to_string();
        assert_eq!(can(&vec_eo, &mut ro).permit(), false);
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
        let mut ro = basic_ro("ed", "root");

        basic_cmd(&mut ro, &"/bin/bash".to_string());
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);
        assert_eq!(can(&vec_eo, &mut ro).permit(), true);

        ro.target = "jim".to_string();
        assert_eq!(can(&vec_eo, &mut ro).permit(), false);

        ro.target = "edd".to_string();
        assert_eq!(can(&vec_eo, &mut ro).permit(), false);
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
        let mut ro = basic_ro("ed", "root");
        basic_cmd(&mut ro, &"/bin/bash".to_string());
        ro.hostname = "thing".to_string();
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);
        assert_eq!(can(&vec_eo, &mut ro).permit(), true);

        ro.hostname = "".to_string();
        assert_eq!(can(&vec_eo, &mut ro).permit(), false);

        ro.hostname = "web".to_string();
        assert_eq!(can(&vec_eo, &mut ro).permit(), false);

        ro.hostname = "localhost".to_string();
        assert_eq!(can(&vec_eo, &mut ro).permit(), false);

        let config = "[ed]
exact_name=ed
exact_target=root
exact_hostname=localhost
exact_rule = /bin/bash
"
        .to_string();

        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        ro.hostname = "thing".to_string();
        assert_eq!(can(&vec_eo, &mut ro).permit(), true);
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
        let mut ro = basic_ro("ed", "root");
        basic_cmd(&mut ro, &"/bin/sh".to_string());
        ro.directory = Some("/root".to_string());
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        assert_eq!(can(&vec_eo, &mut ro).permit(), true);

        ro.directory = Some("/home".to_string());
        assert_eq!(can(&vec_eo, &mut ro).permit(), false);

        ro.directory = Some("/".to_string());
        assert_eq!(can(&vec_eo, &mut ro).permit(), false);
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
        let mut ro = basic_ro("ed", "root");
        basic_cmd(&mut ro, &"/bin/bash".to_string());
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        assert_eq!(can(&vec_eo, &mut ro).permit(), true);

        ro.name = "zz".to_string();
        assert_eq!(can(&vec_eo, &mut ro).permit(), false);

        let config = "[ed]
exact_name=
name=zz
exact_target=root
exact_rule = /bin/bash
"
        .to_string();
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        ro.name = "zz".to_string();
        assert_eq!(can(&vec_eo, &mut ro).permit(), false);
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
        let mut ro = basic_ro("ed", "root");
        basic_cmd(&mut ro, &"/bin/sh".to_string());
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        assert_eq!(can(&vec_eo, &mut ro).permit(), true);

        basic_cmd(&mut ro, &"/bin/bash".to_string());
        assert_eq!(can(&vec_eo, &mut ro).permit(), false);
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
        let mut ro = basic_ro("ed", "root");
        basic_cmd(&mut ro, &"/bin/sh".to_string());
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        assert_eq!(can(&vec_eo, &mut ro).permit(), true);

        ro.target = "bob".to_string();
        assert_eq!(can(&vec_eo, &mut ro).permit(), false);
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
        let mut ro = basic_ro("ed", "root");
        basic_cmd(&mut ro, &"/bin/sh".to_string());
        ro.directory = Some("/root".to_string());
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        assert_eq!(can(&vec_eo, &mut ro).permit(), true);

        ro.directory = Some("/home".to_string());
        assert_eq!(can(&vec_eo, &mut ro).permit(), false);
    }

    #[test]
    fn test_exact_target_group() {
        let config = "[ed]
group = true
exact_target=root
exact_rule = /bin/sh
exact_name = audio
"
        .to_string();

        let mut bytes = 0;
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        let mut vec_eo: Vec<EnvOptions> = vec![];
        let mut ro = basic_ro("ed", "root");
        basic_cmd(&mut ro, &"/bin/sh".to_string());
        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        assert_eq!(can(&vec_eo, &mut ro).permit(), false);

        ro.groups.insert(String::from("audio"), 1);
        assert_eq!(can(&vec_eo, &mut ro).permit(), true);
    }

    #[test]
    fn test_exact_rule_internal_backslash() {
        let config = r#"[ed]
exact_name=ed
exact_target=root
exact_rule = /bin/bash echo\ hello\ \\\\\ world
"#
        .to_string();

        let mut bytes = 0;
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        let mut vec_eo: Vec<EnvOptions> = vec![];
        let mut ro = basic_ro("ed", "root");

        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        ro.new_args = vec![
            "/bin/bash".to_string(),
            r#"echo hello \\ world"#.to_string(),
        ];
        assert_eq!(can(&vec_eo, &mut ro).permit(), true);
    }
}
