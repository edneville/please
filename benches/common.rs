#![feature(test)]
extern crate test;

use chrono::*;
use test::Bencher;

use pleaser::util::{can, list, read_ini_config_str, regex_build, EnvOptions, RunOptions, ACLTYPE};

#[bench]
fn test_regex_build_user_expansion_bench(b: &mut Bencher) {
    let mut regex_re = regex_build("/var/www/html/%{USER}/page.html", "ed", "/", "none").unwrap();
    b.iter(|| {
        regex_re = regex_build("/var/www/html/%{USER}/page.html", "ed", "/", "none").unwrap();
    });

    assert_eq!(regex_re.as_str(), "^/var/www/html/ed/page.html$");
}

#[bench]
fn test_read_str(b: &mut Bencher) {
    let config = "
[ed]
name=ed
target=root
notbefore=20200101
notafter=20201231
regex =^.*$
"
    .to_string();

    let mut ro = RunOptions::new();
    ro.name = "ed".to_string();
    ro.target = "root".to_string();
    ro.acl_type = ACLTYPE::RUN;
    ro.command = "/bin/bash".to_string();

    let mut vec_eo: Vec<EnvOptions> = vec![];

    b.iter(|| {
        read_ini_config_str(&config, &mut vec_eo, "ed", false);
    });
}

#[bench]
fn test_read_absent_str(b: &mut Bencher) {
    let config = "
"
    .to_string();

    let mut ro = RunOptions::new();
    ro.name = "ed".to_string();
    ro.target = "root".to_string();
    ro.acl_type = ACLTYPE::RUN;
    ro.command = "/bin/bash".to_string();

    let mut vec_eo: Vec<EnvOptions> = vec![];

    b.iter(|| {
        read_ini_config_str(&config, &mut vec_eo, "ed", false);
    });
}
#[bench]
fn test_too_early(b: &mut Bencher) {
    let config = "
[ed]
name=ed
target=root
notbefore=20200101
notafter=20201231
regex =^.*$
"
    .to_string();

    let mut ro = RunOptions::new();
    ro.name = "ed".to_string();
    ro.target = "root".to_string();
    ro.acl_type = ACLTYPE::RUN;
    ro.command = "/bin/bash".to_string();
    ro.date = NaiveDate::from_ymd(2019, 12, 31).and_hms(0, 0, 0);

    let mut vec_eo: Vec<EnvOptions> = vec![];
    read_ini_config_str(&config, &mut vec_eo, "ed", false);

    b.iter(|| {
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, false);
    });
}

#[bench]
fn test_within(b: &mut Bencher) {
    let config = "
[ed]
name=ed
target=root
notbefore=20200101
notafter=20201231
regex =^.*$
"
    .to_string();
    let mut ro = RunOptions::new();
    ro.name = "ed".to_string();
    ro.target = "root".to_string();
    ro.acl_type = ACLTYPE::RUN;
    ro.command = "/bin/bash".to_string();
    ro.date = NaiveDate::from_ymd(2020, 12, 31).and_hms(0, 0, 0);

    let mut vec_eo: Vec<EnvOptions> = vec![];
    read_ini_config_str(&config, &mut vec_eo, "ed", false);

    b.iter(|| {
        assert_eq!(can(&vec_eo, &ro).unwrap().permit, true);
    });
}

#[bench]
fn test_list(b: &mut Bencher) {
    let config = "
[ed]
name=ed
target=root
notbefore=20200101
notafter=20201231
regex =^.*$
"
    .to_string();
    let mut ro = RunOptions::new();
    ro.name = "ed".to_string();
    ro.target = "root".to_string();
    ro.acl_type = ACLTYPE::RUN;
    ro.command = "/bin/bash".to_string();
    ro.date = NaiveDate::from_ymd(2020, 12, 31).and_hms(0, 0, 0);

    let mut vec_eo: Vec<EnvOptions> = vec![];
    read_ini_config_str(&config, &mut vec_eo, "ed", false);

    b.iter(|| {
        list(&vec_eo, &ro);
    });
}
