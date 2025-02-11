use std::env::args;


fn get_version() -> String {
    return "0.1.0".to_string();
}

fn main() {
    
    // check if --version flag is passed
    if args().any(|x| x == "--version") {
        println!("mlab-cli {}", get_version());
        return;
    }
}
