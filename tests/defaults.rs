use std::collections::HashMap;
mod basic_ro;

#[cfg(test)]
mod test {
    use super::*;
    use basic_ro::*;
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
        let mut ro = basic_ro("ed", "root");

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
        let mut ro = basic_ro("ed", "root");

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
        let mut ro = basic_ro("ed", "root");

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
        let mut ro = basic_ro("ed", "root");

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
        let mut ro = basic_ro("ed", "root");

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
        let mut ro = basic_ro("ed", "root");

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
        let mut ro = basic_ro("ed", "root");

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
        let mut ro = basic_ro("ed", "root");

        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        ro.command = "/bin/bash".to_string();
        let can = can(&vec_eo, &ro);
        assert_eq!(can.syslog.is_none(), true);
        assert_eq!(can.timeout.is_none(), true);
        assert_eq!(can.permit(), true);
    }

    #[test]
    fn test_edit_mode_keep() {
        let config = "
[default:edit_mode]
name = .*
rule = .*
editmode = keep
type = edit
permit = false

[ed]
name = ed
rule = .*
type = edit
"
        .to_string();

        let mut bytes = 0;
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        let mut vec_eo: Vec<EnvOptions> = vec![];
        let mut ro = basic_ro("ed", "root");
        ro.acl_type = Acltype::Edit;

        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        ro.command = "/bin/bash".to_string();
        let can = can(&vec_eo, &ro);
        assert_eq!(can.edit_mode, Some(EditMode::Keep(true)));
        assert_eq!(can.permit(), false);
    }

    #[test]
    fn test_edit_mode_keep_none() {
        let config = "
[default:edit_mode]
name = thing
rule = .*
editmode = keep
type = edit
permit = false

[ed]
name = ed
rule = .*
type = edit
"
        .to_string();

        let mut bytes = 0;
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        let mut vec_eo: Vec<EnvOptions> = vec![];
        let mut ro = basic_ro("ed", "root");
        ro.acl_type = Acltype::Edit;

        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        ro.command = "/bin/bash".to_string();
        let can = can(&vec_eo, &ro);
        assert_eq!(can.edit_mode, None);
        assert_eq!(can.permit(), true);
    }

    #[test]
    fn test_edit_mode_non_keep() {
        let config = "
[default:edit_mode]
name = ed
rule = .*
type = edit
editmode = 111
exitcmd = /bin/false
reason = blah

[ed]
name = ed
rule = .*
type = edit
"
        .to_string();

        let mut bytes = 0;
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        let mut vec_eo: Vec<EnvOptions> = vec![];
        let mut ro = basic_ro("ed", "root");
        ro.acl_type = Acltype::Edit;

        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        ro.command = "/bin/bash".to_string();
        let can = can(&vec_eo, &ro);
        assert_eq!(can.edit_mode, Some(EditMode::Mode(0o111)));
        assert_eq!(can.permit(), true);
        assert_eq!(can.exitcmd, Some("/bin/false".to_string()));
        assert_eq!(can.reason, Some(ReasonType::Text("blah".to_string())));
    }

    #[test]
    fn test_edit_default_other_user() {
        let config = "
[default:edit_mode]
name = ed
rule = .*
type = edit
editmode = 111

[ed]
name = ed
rule = .*
type = edit

[noted]
name = noted
rule = .*
type = edit
"
        .to_string();

        let mut bytes = 0;
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        let mut vec_eo: Vec<EnvOptions> = vec![];
        let mut ro = basic_ro("ed", "root");
        ro.name = "noted".to_string();
        ro.acl_type = Acltype::Edit;

        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        ro.command = "/bin/bash".to_string();
        let can = can(&vec_eo, &ro);
        assert_eq!(can.edit_mode, None);
        assert_eq!(can.permit(), true);
        assert_eq!(can.exitcmd, None);
        assert_eq!(can.reason, None);
    }

    #[test]
    fn test_default_require_pass() {
        let config = "

[ed]
name = ed
rule = .*
"
        .to_string();

        let mut bytes = 0;
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        let mut vec_eo: Vec<EnvOptions> = vec![];
        let mut ro = basic_ro("ed", "root");
        ro.name = "ed".to_string();
        ro.acl_type = Acltype::Run;

        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        ro.command = "/bin/bash".to_string();
        let can = can(&vec_eo, &ro);
        assert_eq!(can.edit_mode, None);
        assert_eq!(can.permit(), true);
        assert_eq!(can.exitcmd, None);
        assert_eq!(can.reason, None);
        assert_eq!(can.require_pass(), true);
    }

    #[test]
    fn test_default_require_pass_inherit() {
        let config = "
[default_all]
name = .*
rule = .*
require_pass = false
"
        .to_string();

        let mut bytes = 0;
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        let mut vec_eo: Vec<EnvOptions> = vec![];
        let mut ro = basic_ro("ed", "root");
        ro.name = "ed".to_string();
        ro.acl_type = Acltype::Run;

        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        ro.command = "/bin/bash".to_string();
        let can = can(&vec_eo, &ro);
        assert_eq!(can.edit_mode, None);
        assert_eq!(can.permit(), true);
        assert_eq!(can.exitcmd, None);
        assert_eq!(can.reason, None);
        assert_eq!(can.require_pass(), false);

        let config = "
[default_all]
name = .*
rule = .*
require_pass = false
last = true

[ed]
name = ed
rule = /bin/bash
require_pass = true
"
        .to_string();

        let mut bytes = 0;
        let mut ini_list: HashMap<String, bool> = HashMap::new();
        let mut vec_eo: Vec<EnvOptions> = vec![];

        read_ini_config_str(&config, &mut vec_eo, &ro, false, &mut bytes, &mut ini_list);

        ro.command = "/bin/bash".to_string();
        let can = pleaser::can(&vec_eo, &ro);
        assert_eq!(can.permit(), true);
        assert_eq!(can.require_pass(), false);
        assert_eq!(can.last, Some(true));
        assert_eq!(can.reason, None);
        assert_eq!(can.syslog, None);
        assert_eq!(can.exitcmd, None);
        assert_eq!(can.edit_mode, None);
        assert_eq!(can.section, "default_all".to_string());
    }
}
