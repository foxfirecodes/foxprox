fn main() {
    let args = match foxprox_cli::parse_setup_args(std::env::args().skip(1)) {
        Ok(args) => args,
        Err(foxprox_cli::CliError::Usage(message)) => {
            eprintln!("{message}");
            std::process::exit(2);
        }
        Err(error) => {
            eprintln!("foxproxsetup: {error}");
            std::process::exit(1);
        }
    };

    if let Err(error) = foxprox_cli::run_setup(args) {
        eprintln!("foxproxsetup: {error}");
        std::process::exit(1);
    }
}
