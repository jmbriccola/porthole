mod cli;
mod output;
mod run;

use clap::Parser;

fn main() {
    let cli = cli::Cli::parse();
    if let Err(error) = run::run(&cli) {
        if cli.json {
            println!("{}", output::json_error(&error));
        } else {
            eprintln!("porthole: {error}");
        }
        std::process::exit(error.exit_code() as i32);
    }
}
