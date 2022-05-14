use chrono::NaiveDate;
use pleaser::*;

pub fn basic_ro(name: &str, target: &str) -> RunOptions {
    let mut ro = RunOptions::new();
    ro.date = NaiveDate::from_ymd(2020, 1, 1).and_hms(0, 0, 0);
    ro.name = name.to_string();
    ro.target = target.to_string();
    ro.acl_type = Acltype::Run;

    ro
}
