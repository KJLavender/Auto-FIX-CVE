use regex::Regex;
use smallvec::{smallvec, SmallVec};

fn main() {
    let re = Regex::new(r"^\d{4}-\d{2}-\d{2}$").unwrap();
    let mut dates: SmallVec<[&str; 4]> = smallvec![];
    dates.insert_many(0, vec!["2026-10-20"]);
    println!("{}", dates.iter().all(|d| re.is_match(d)));
}
