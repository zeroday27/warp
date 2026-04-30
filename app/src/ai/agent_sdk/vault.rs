use std::io::{self, IsTerminal as _, Write};

use ::ai::vault as ai_vault;
use anyhow::Result;
use inquire::{InquireError, Password};
use warp_cli::vault::{VaultCommand, VaultFileArgs};

pub fn run(command: VaultCommand) -> Result<()> {
    match command {
        VaultCommand::Encrypt(args) => encrypt(args),
        VaultCommand::Decrypt(args) => decrypt(args),
        VaultCommand::View(args) => view(args),
    }
}

fn encrypt(args: VaultFileArgs) -> Result<()> {
    let password = read_cli_password()?;
    ai_vault::encrypt_file(&args.file_path, &password)
}

fn decrypt(args: VaultFileArgs) -> Result<()> {
    let password = read_cli_password()?;
    ai_vault::decrypt_file(&args.file_path, &password)
}

fn view(args: VaultFileArgs) -> Result<()> {
    let password = read_cli_password()?;
    let contents = std::fs::read_to_string(&args.file_path)?;
    let plaintext = ai_vault::decrypt_to_string_with_password(&contents, &password)?;
    io::stdout().write_all(plaintext.as_bytes())?;
    Ok(())
}

fn read_cli_password() -> Result<zeroize::Zeroizing<String>> {
    match ai_vault::read_password(None) {
        Ok(password) => Ok(password),
        Err(ai_vault::VaultError::MissingPassword) => prompt_for_password(),
        Err(err) => Err(err.into()),
    }
}

fn prompt_for_password() -> Result<zeroize::Zeroizing<String>> {
    if !io::stdin().is_terminal() {
        return Err(anyhow::anyhow!(
            "Vault password is required; set WARP_VAULT_PASSWORD in non-interactive mode"
        ));
    }

    match Password::new("Vault password:")
        .with_display_toggle_enabled()
        .without_confirmation()
        .prompt()
    {
        Ok(password) => Ok(zeroize::Zeroizing::new(password)),
        Err(InquireError::OperationCanceled | InquireError::OperationInterrupted) => {
            Err(anyhow::anyhow!("Vault operation canceled"))
        }
        Err(err) => Err(err.into()),
    }
}
