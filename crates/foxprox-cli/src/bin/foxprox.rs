fn main() {
    let args = match foxprox_cli::parse_launcher_args(std::env::args().skip(1)) {
        Ok(args) => args,
        Err(foxprox_cli::CliError::Usage(message)) => {
            eprintln!("{message}");
            std::process::exit(2);
        }
        Err(error) => {
            eprintln!("foxprox: {error}");
            std::process::exit(1);
        }
    };

    match foxprox_cli::run_launcher(args) {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("foxprox: {error}");
            std::process::exit(1);
        }
    }
}
