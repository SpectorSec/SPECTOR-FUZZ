use clap::{Parser, Subcommand};
use spectorfuzz::evm::{evm_main, EvmArgs};
use spectorfuzz::logger;

pub fn init_sentry() {
    let _guard = sentry::init((
        "https://96f3517bd77346ea835d28f956a84b9d@o4504503751344128.ingest.sentry.io/4504503752523776",
        sentry::ClientOptions {
            release: sentry::release_name!(),
            ..Default::default()
        },
    ));
}

#[derive(Parser)]
#[command(author, version=env!("GIT_VERSION_INFO"), about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[allow(clippy::large_enum_variant)]
#[derive(Subcommand, Debug)]
enum Commands {
    Evm(EvmArgs),
}

fn main() {
    init_sentry();
    logger::init();

    let args = Cli::parse();
    match args.command {
        Commands::Evm(args) => {
            evm_main(args);
        }
    }
}
