use chrono::NaiveDate;
use pleaser::*;

pub fn basic_ro(name: &str, target: &str) -> RunOptions {
    let mut ro = RunOptions::new();
    ro.date = NaiveDate::from_ymd(2020, 1, 1).and_hms(0, 0, 0);
    ro.name = name.to_string();
    ro.target = target.to_string();
    ro.acl_type = Acltype::Run;
    ro.hostname = "localhost".to_string();

    ro
}

pub fn basic_cmd(ro: &mut RunOptions, cmd: &str) {
    ro.new_args = cmd.split_whitespace().map(|s| s.to_string()).collect();
    if ro.new_args.len() == 0 {
        ro.new_args = vec!["".to_string()];
    }
}
