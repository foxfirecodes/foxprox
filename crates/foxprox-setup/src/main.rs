use foxprox_setup::{parse_setup_args, run_setup, RealSetupBackend};

fn main() {
    let args = match parse_setup_args(std::env::args().skip(1)) {
        Ok(args) => args,
        Err(error) => {
            eprintln!("foxproxsetup argument error: {error:?}");
            std::process::exit(2);
        }
    };

    let mut backend = RealSetupBackend::new();
    if let Err(error) = run_setup(&args, &mut backend) {
        eprintln!("foxproxsetup failed: {error}");
        std::process::exit(1);
    }
}
