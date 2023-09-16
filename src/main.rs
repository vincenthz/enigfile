use anyhow::Context;

use clap::{Parser, Subcommand};
use enigfile::{decrypt_file, encrypt_file, EitherReport, Reporter, ReporterNone};
use std::fs::File;
use std::path::PathBuf;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Sets a custom config file
    // #[arg(short, long, value_name = "FILE")]
    // config: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Perform password-based symmetric encryption of a file and create a new encrypted file
    Encrypt {
        /// Path of file to encrypt
        from: PathBuf,
        /// Destination file to create containing encrypted data
        to: PathBuf,
        /// Explicit password specified as command line argument. When missing will prompt user
        password: Option<String>,
        /// Quieten the iterative output of decryption, by hiding the progress bar
        #[arg(long, default_value_t = false)]
        no_status: bool,
    },
    /// Perform password-based symmetric decryption of a previously encrypted file and create a new decrypted file
    Decrypt {
        /// Path of file to decrypt
        from: PathBuf,
        /// Destination file to create containing the decrypted data
        to: PathBuf,
        /// Explicit password specified as command line argument. When missing will prompt user
        password: Option<String>,
        /// Quieten the iterative output of decryption, by hiding the progress bar
        #[arg(long, default_value_t = false)]
        no_status: bool,
    },
}

fn ask_password() -> anyhow::Result<String> {
    use inquire::{validator::Validation, Password, PasswordDisplayMode};

    let validator = |input: &str| {
        if input.chars().count() < 1 {
            Ok(Validation::Invalid(
                "Password must have at least 1 characters.".into(),
            ))
        } else {
            Ok(Validation::Valid)
        }
    };

    let name = Password::new("Password:")
        .with_display_toggle_enabled()
        .with_display_mode(PasswordDisplayMode::Hidden)
        .with_custom_confirmation_message("Password (confirm):")
        .with_custom_confirmation_error_message("The passwords don't match.")
        .with_validator(validator)
        .with_formatter(&|_| String::from("Password accepted"))
        .with_help_message("Use a password")
        .prompt();

    match name {
        Ok(s) => Ok(s),
        Err(e) => Err(e.into()),
    }
}

fn file_size(metadata: &std::fs::Metadata) -> Option<u64> {
    #[cfg(not(target_os = "windows"))]
    {
        use std::os::unix::prelude::MetadataExt;
        Some(metadata.size())
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::MetadataExt;
        Some(metadata.file_size())
    }
}

fn get_password(password: Option<String>) -> anyhow::Result<String> {
    match password {
        Some(password) => Ok(password),
        None => ask_password(),
    }
}

pub struct ReporterProgress(Option<indicatif::ProgressBar>);

impl Reporter for ReporterProgress {
    fn chunk_start(&self, _data_read: u64, _chunk_number: usize) {
        if let Some(bar) = &self.0 {
            bar.inc(1)
        }
    }
}

fn get_progress(
    no_status: bool,
    meta: &std::fs::Metadata,
) -> anyhow::Result<EitherReport<ReporterNone, ReporterProgress>> {
    if no_status {
        return Ok(EitherReport::right(ReporterNone));
    }

    let total_chunks = file_size(&meta).map(|sz| sz / enigfile::CHUNK_SIZE as u64);
    let pb = total_chunks.map(|t| indicatif::ProgressBar::new(t));

    // set the bar style to percentage and some blue color (if there's a progress bar)
    if let Some(bar) = &pb {
        bar.set_style(indicatif::ProgressStyle::with_template(
            "[{elapsed_precise}] {wide_bar:2.cyan/blue} {percent}% ",
        )?);
    }
    Ok(EitherReport::left(ReporterProgress(pb)))
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Encrypt {
            from,
            to,
            password,
            no_status,
        } => {
            let mut input = File::open(&from)
                .with_context(|| format!("Failed to open input file {}", from.to_string_lossy()))?;
            let mut output = File::create(&to).with_context(|| {
                format!("Failed to create output file {}", to.to_string_lossy())
            })?;

            let password = get_password(password)?;

            let meta = input.metadata()?;
            if !meta.is_file() {
                anyhow::bail!("input is not a file")
            }

            let report = get_progress(no_status, &meta)?;

            encrypt_file(&report, password.as_bytes(), &mut input, &mut output)?;
            Ok(())
        }
        Command::Decrypt {
            from,
            to,
            password,
            no_status,
        } => {
            let mut input = File::open(&from)
                .with_context(|| format!("Failed to open input file {}", from.to_string_lossy()))?;
            let mut output = File::create(&to).with_context(|| {
                format!("Failed to create output file {}", to.to_string_lossy())
            })?;

            let password = get_password(password)?;

            let meta = input.metadata()?;
            if !meta.is_file() {
                anyhow::bail!("input is not a file")
            }

            let report = get_progress(no_status, &meta)?;

            decrypt_file(&report, password.as_bytes(), &mut input, &mut output)?;
            Ok(())
        }
    }
}
