#![forbid(unsafe_code)]

fn main() {
    if let Err(error) = foxprox_cli::run_foxproxsetup_from_env() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}
