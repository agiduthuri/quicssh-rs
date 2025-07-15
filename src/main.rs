// Import client module containing QUIC client functionality
mod client;
// Import server module containing QUIC server functionality
mod server;

// Import log4rs components for logging configuration
use log4rs::append::console::{ConsoleAppender, Target};
use log4rs::append::file::FileAppender;
use log4rs::config::{Appender, Config, Root};
use log4rs::encode::pattern::PatternEncoder;

// Import clap for command line argument parsing
use clap::{Parser, Subcommand};
// Import logging functionality
use log::{error, LevelFilter};
// Import standard library components
use std::{path::PathBuf, str};

// Define the main CLI structure using clap derive macros
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    // Define subcommands (server or client)
    #[command(subcommand)]
    command: Commands,
    // Optional log file path parameter
    #[clap(value_parser, long = "log")]
    log_file: Option<PathBuf>,
    // Optional log level parameter (defaults to Error)
    #[clap(long)]
    log_level: Option<LevelFilter>,
}

// Define the available subcommands
#[derive(Subcommand, Debug)]
enum Commands {
    // Server subcommand with server-specific options
    Server(server::Opt),
    // Client subcommand with client-specific options
    Client(client::Opt),
}

// Main function - entry point of the application
fn main() {
    // Parse command line arguments using clap
    let args = Cli::parse();

    // Determine log level - use provided level or default to Error
    let level = match args.log_level {
        Some(log_level) => log_level,
        None => LevelFilter::Error,
    };
    
    // Configure logging based on whether a log file was specified
    let config = match args.log_file {
        // If log file is specified, create file appender configuration
        Some(log_file) => {
            // Create file appender with default pattern encoder
            let logfile = FileAppender::builder()
                .encoder(Box::<PatternEncoder>::default())
                .build(log_file)
                .unwrap();

            // Build configuration with file appender
            Config::builder()
                .appender(Appender::builder().build("logfile", Box::new(logfile)))
                .build(Root::builder().appender("logfile").build(level))
                .unwrap()
        }
        // If no log file specified, use stderr console appender
        None => {
            // Create console appender targeting stderr
            let stderr = ConsoleAppender::builder()
                .encoder(Box::<PatternEncoder>::default())
                .target(Target::Stderr)
                .build();
            
            // Build configuration with console appender
            Config::builder()
                .appender(Appender::builder().build("stderr", Box::new(stderr)))
                .build(Root::builder().appender("stderr").build(level))
                .unwrap()
        }
    };

    // Initialize the logging system with the configured settings
    log4rs::init_config(config).unwrap();

    // Execute the appropriate command based on user input
    match args.command {
        // Run server with the provided server options
        Commands::Server(server) => {
            let err = server::run(server);
            match err {
                Ok(_) => {}
                // Log any errors that occur during server execution
                Err(e) => {
                    error!("Error: {:#?}", e);
                }
            }
        }
        // Run client with the provided client options
        Commands::Client(client) => {
            let err = client::run(client);
            match err {
                Ok(_) => {}
                // Log any errors that occur during client execution
                Err(e) => {
                    error!("Error: {:#?}", e);
                }
            }
        }
    }
}
