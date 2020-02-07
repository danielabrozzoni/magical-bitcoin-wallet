extern crate clap;
extern crate dirs;
extern crate env_logger;
extern crate log;
extern crate magical_bitcoin_wallet;
extern crate rustyline;

use std::fs;
use std::path::PathBuf;
use std::str::FromStr;

use clap::{App, AppSettings, Arg, ArgMatches, SubCommand};

use rustyline::error::ReadlineError;
use rustyline::Editor;

#[allow(unused_imports)]
use log::{debug, error, info, trace, LevelFilter};

use bitcoin::Network;
use magical_bitcoin_wallet::bitcoin;
use magical_bitcoin_wallet::sled;
use magical_bitcoin_wallet::{Client, ExtendedDescriptor, Wallet};

fn prepare_home_dir() -> PathBuf {
    let mut dir = PathBuf::new();
    dir.push(&dirs::home_dir().unwrap());
    dir.push(".magical-bitcoin");

    if !dir.exists() {
        info!("Creating home directory {}", dir.as_path().display());
        fs::create_dir(&dir).unwrap();
    }

    dir.push("database.sled");
    dir
}

fn main() {
    env_logger::init();

    let app = App::new("Magical Bitcoin Wallet")
        .version(option_env!("CARGO_PKG_VERSION").unwrap_or("unknown"))
        .author(option_env!("CARGO_PKG_AUTHORS").unwrap_or(""))
        .about("A modern, lightweight, descriptor-based wallet")
        .subcommand(
            SubCommand::with_name("get_new_address").about("Generates a new external address"),
        )
        .subcommand(SubCommand::with_name("sync").about("Syncs with the chosen Electrum server"))
        .subcommand(
            SubCommand::with_name("list_unspent").about("Lists the available spendable UTXOs"),
        )
        .subcommand(
            SubCommand::with_name("get_balance").about("Returns the current wallet balance"),
        );

    let mut repl_app = app.clone().setting(AppSettings::NoBinaryName);

    let app = app
        .arg(
            Arg::with_name("network")
                .short("n")
                .long("network")
                .value_name("NETWORK")
                .help("Sets the network")
                .takes_value(true)
                .default_value("testnet")
                .possible_values(&["testnet", "regtest"]),
        )
        .arg(
            Arg::with_name("wallet")
                .short("w")
                .long("wallet")
                .value_name("WALLET_NAME")
                .help("Selects the wallet to use")
                .takes_value(true)
                .default_value("main"),
        )
        .arg(
            Arg::with_name("server")
                .short("s")
                .long("server")
                .value_name("SERVER:PORT")
                .help("Sets the Electrum server to use")
                .takes_value(true)
                .default_value("tn.not.fyi:55001"),
        )
        .arg(
            Arg::with_name("descriptor")
                .short("d")
                .long("descriptor")
                .value_name("DESCRIPTOR")
                .help("Sets the descriptor to use for the external addresses")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("change_descriptor")
                .short("c")
                .long("change_descriptor")
                .value_name("DESCRIPTOR")
                .help("Sets the descriptor to use for internal addresses")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("v")
                .short("v")
                .multiple(true)
                .help("Sets the level of verbosity"),
        )
        .subcommand(SubCommand::with_name("repl").about("opens an interactive shell"));

    let matches = app.get_matches();

    // TODO
    // let level = match matches.occurrences_of("v") {
    //     0 => LevelFilter::Info,
    //     1 => LevelFilter::Debug,
    //     _ => LevelFilter::Trace,
    // };

    let network = match matches.value_of("network") {
        Some("regtest") => Network::Regtest,
        Some("testnet") | _ => Network::Testnet,
    };

    let descriptor = matches
        .value_of("descriptor")
        .map(|x| ExtendedDescriptor::from_str(x).unwrap())
        .unwrap();
    let change_descriptor = matches
        .value_of("change_descriptor")
        .map(|x| ExtendedDescriptor::from_str(x).unwrap());
    debug!("descriptors: {:?} {:?}", descriptor, change_descriptor);

    let database = sled::open(prepare_home_dir().to_str().unwrap()).unwrap();
    let tree = database
        .open_tree(matches.value_of("wallet").unwrap())
        .unwrap();
    debug!("database opened successfully");

    let client = Client::new(matches.value_of("server").unwrap()).unwrap();
    let wallet = Wallet::new(descriptor, change_descriptor, network, tree, client);

    // TODO: print errors in a nice way
    let handle_matches = |matches: ArgMatches<'_>| {
        if let Some(_sub_matches) = matches.subcommand_matches("get_new_address") {
            println!("{}", wallet.get_new_address().unwrap().to_string());
        } else if let Some(_sub_matches) = matches.subcommand_matches("sync") {
            wallet.sync(None, None).unwrap();
        } else if let Some(_sub_matches) = matches.subcommand_matches("list_unspent") {
            for utxo in wallet.list_unspent().unwrap() {
                println!("{} value {} SAT", utxo.outpoint, utxo.txout.value);
            }
        } else if let Some(_sub_matches) = matches.subcommand_matches("get_balance") {
            println!("{} SAT", wallet.get_balance().unwrap());
        }
    };

    if let Some(_sub_matches) = matches.subcommand_matches("repl") {
        let mut rl = Editor::<()>::new();

        // if rl.load_history("history.txt").is_err() {
        //     println!("No previous history.");
        // }

        loop {
            let readline = rl.readline(">> ");
            match readline {
                Ok(line) => {
                    if line.trim() == "" {
                        continue;
                    }

                    rl.add_history_entry(line.as_str());
                    let matches = repl_app.get_matches_from_safe_borrow(line.split(" "));
                    if let Err(err) = matches {
                        println!("{}", err.message);
                        continue;
                    }

                    handle_matches(matches.unwrap());
                }
                Err(ReadlineError::Interrupted) => continue,
                Err(ReadlineError::Eof) => break,
                Err(err) => {
                    println!("{:?}", err);
                    break;
                }
            }
        }

    // rl.save_history("history.txt").unwrap();
    } else {
        handle_matches(matches);
    }
}
