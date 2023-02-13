
pub fn print_long_hex(title: String, str: String, width: usize) -> String {
    use std::str;
    let mut result = String::new();
    let subs = str
        .as_bytes()
        .chunks(width)
        .map(str::from_utf8)
        .collect::<Result<Vec<&str>, _>>()
        .unwrap();
    result += &format!("{}", title);
    for (idx, substr) in subs.iter().enumerate() {
        if idx > 0 {
            result += &format!("{: <1$}", "", title.len());
        }
        result += &format!("{}\n", substr);
    }

    if subs.len() == 0 {
        result += &format!("\n");
    }
    result
}