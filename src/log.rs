use std::{fmt::Display, panic::Location};

use colored::Colorize;

enum Level {
    INFO,
    DEBUG,
    WARNING,
    ERROR,
}

fn log_stdout<S: AsRef<str> + Display>(level: Level, message: S, caller: &Location<'_>) {
    let timestamp = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ");
    let formatted_message = match level {
        Level::INFO => format!("{timestamp} INFO ({caller}):  {message}").green(),
        Level::DEBUG => format!("{timestamp} DEBUG ({caller}):  {message}").blue(),
        Level::WARNING => format!("{timestamp} WARNING ({caller}):  {message}").yellow(),
        Level::ERROR => format!("{timestamp} ERROR ({caller}):  {message}").red(),
    };

    println!("{formatted_message}");
}

#[track_caller]
pub fn info<S: AsRef<str> + Display>(message: S) {
    let caller = std::panic::Location::caller();
    log_stdout(Level::INFO, message, caller);
}

#[track_caller]
pub fn debug<S: AsRef<str> + Display>(message: S) {
    let caller = std::panic::Location::caller();
    log_stdout(Level::DEBUG, message, caller);
}

#[track_caller]
pub fn warning<S: AsRef<str> + Display>(message: S) {
    let caller = std::panic::Location::caller();
    log_stdout(Level::WARNING, message, caller);
}

#[track_caller]
pub fn error<S: AsRef<str> + Display>(message: S) {
    let caller = std::panic::Location::caller();
    log_stdout(Level::ERROR, message, caller);
}
