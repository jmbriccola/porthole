mod cli;
mod client;
mod doctor;
mod output;
mod run;

use clap::Parser;

fn main() {
    let cli = cli::Cli::parse();
    match run::run(&cli) {
        Ok(code) => std::process::exit(code as i32),
        Err(error) => {
            if cli.json {
                println!("{}", output::json_error(&error));
            } else {
                eprintln!("porthole: {error}");
            }
            std::process::exit(error.exit_code() as i32);
        }
    }
}
