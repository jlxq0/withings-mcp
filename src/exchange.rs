//! `withings-mcp exchange` — trade an authorisation code for a refresh token.
//!
//! An authorisation code lives minutes, so this path has to exist before the
//! code does rather than after. It runs from a terminal, needs no listener,
//! no deployment and no state file, and it writes nothing anywhere.
//!
//! The three secret values are read from **stdin**, one per line, so none of
//! them reaches a shell history, a process listing, or an environment a child
//! process inherits. Everything else is a flag.
//!
//! ```text
//! printf '%s\n%s\n%s\n' "$CLIENT_ID" "$CLIENT_SECRET" "$CODE" \
//!   | withings-mcp exchange --redirect-uri https://example/oauth/callback
//! ```
//!
//! The refresh token it prints is the credential the deployment is given, and
//! it is the only copy: Withings rotates on every refresh, so re-running this
//! needs a new code and therefore a new browser round trip.

use std::io::{BufRead as _, IsTerminal as _, Write as _};

use anyhow::{Context as _, Result, bail};

use crate::withings_client::{
    AUTHORIZE_URL, ClientCredentials, DEFAULT_API_BASE_URL, SCOPE, WithingsClient, authorize_url,
};

/// Read three secrets from stdin and exchange them.
pub async fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(2).collect();
    let options = Options::parse(&args)?;

    if options.authorize_url {
        let client_id = read_line("client id")?;
        println!(
            "{}",
            authorize_url(&client_id, &options.redirect_uri, &options.state)
        );
        return Ok(());
    }

    let (client_id, client_secret, code) = read_secrets()?;
    let client = WithingsClient::new(&options.api_base_url)?;
    let credentials = ClientCredentials {
        client_id,
        client_secret,
    };
    let tokens = client
        .exchange_code(&credentials, &code, &options.redirect_uri)
        .await
        .context("exchange the authorisation code")?;

    // stdout carries the credential and nothing else, so it can be piped
    // straight into a password manager. Everything explanatory goes to
    // stderr.
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "{}", tokens.refresh_token)?;
    stdout.flush()?;

    eprintln!(
        "userid:  {}",
        tokens.userid.as_deref().unwrap_or("<not returned>")
    );
    eprintln!(
        "scope:   {}",
        tokens.scope.as_deref().unwrap_or("<not returned>")
    );
    eprintln!("expires: access token in {}s", tokens.expires_in);
    eprintln!();
    eprintln!(
        "The line on stdout is the refresh token. Withings rotates it on every refresh, so \
         this value is only good until the server first refreshes; after that the server's \
         own store holds the live one and this copy is dead."
    );
    Ok(())
}

struct Options {
    api_base_url: String,
    redirect_uri: String,
    state: String,
    authorize_url: bool,
}

impl Options {
    fn parse(args: &[String]) -> Result<Self> {
        let mut options = Self {
            api_base_url: DEFAULT_API_BASE_URL.to_owned(),
            redirect_uri: String::new(),
            state: String::new(),
            authorize_url: false,
        };
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--redirect-uri" => {
                    options.redirect_uri = next_value(&mut iter, "--redirect-uri")?;
                }
                "--api-base-url" => {
                    options.api_base_url = next_value(&mut iter, "--api-base-url")?;
                }
                "--state" => options.state = next_value(&mut iter, "--state")?,
                "--authorize-url" => options.authorize_url = true,
                "--help" | "-h" => {
                    print_help();
                    std::process::exit(0);
                }
                other => bail!("unknown argument {other:?}; try --help"),
            }
        }
        if options.redirect_uri.is_empty() {
            bail!("--redirect-uri is required and must match the value registered with Withings");
        }
        if options.authorize_url && options.state.is_empty() {
            bail!("--state is required with --authorize-url");
        }
        Ok(options)
    }
}

fn next_value<'a>(iter: &mut impl Iterator<Item = &'a String>, flag: &str) -> Result<String> {
    iter.next()
        .map(ToOwned::to_owned)
        .with_context(|| format!("{flag} needs a value"))
}

fn print_help() {
    println!(
        "withings-mcp exchange --redirect-uri <uri> [--api-base-url <url>]\n\
         \n\
         Reads three lines from stdin: client id, client secret, authorisation code.\n\
         Prints the refresh token on stdout and nothing else; the summary goes to stderr.\n\
         Writes no file and needs no running server.\n\
         \n\
         withings-mcp exchange --authorize-url --redirect-uri <uri> --state <value>\n\
         \n\
         Reads one line from stdin: the client id. Prints the URL to open in a browser.\n\
         Scope is {SCOPE}; the authorisation page is {AUTHORIZE_URL}."
    );
}

/// Read the three secrets, one per line.
fn read_secrets() -> Result<(String, String, String)> {
    if std::io::stdin().is_terminal() {
        eprintln!("reading three lines from stdin: client id, client secret, authorisation code");
    }
    let client_id = read_line("client id")?;
    let client_secret = read_line("client secret")?;
    let code = read_line("authorisation code")?;
    Ok((client_id, client_secret, code))
}

fn read_line(what: &str) -> Result<String> {
    let mut line = String::new();
    let read = std::io::stdin()
        .lock()
        .read_line(&mut line)
        .with_context(|| format!("read {what} from stdin"))?;
    if read == 0 {
        bail!("stdin ended before the {what} was read");
    }
    let line = line.trim().to_owned();
    if line.is_empty() {
        bail!("the {what} line was empty");
    }
    Ok(line)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn the_redirect_uri_is_required_because_withings_matches_it_exactly() {
        assert!(Options::parse(&args(&[])).is_err());
        let options =
            Options::parse(&args(&["--redirect-uri", "https://example/oauth/callback"])).unwrap();
        assert_eq!(options.redirect_uri, "https://example/oauth/callback");
        // The default base URL is the one a run with no `--api-base-url`
        // gets, which is the only version of it a person actually uses.
        assert_eq!(options.api_base_url, DEFAULT_API_BASE_URL);
        assert!(!options.authorize_url);
    }

    #[test]
    fn an_authorize_url_run_needs_a_state_value() {
        assert!(
            Options::parse(&args(&[
                "--authorize-url",
                "--redirect-uri",
                "https://example/oauth/callback"
            ]))
            .is_err()
        );
        let options = Options::parse(&args(&[
            "--authorize-url",
            "--redirect-uri",
            "https://example/oauth/callback",
            "--state",
            "s",
        ]))
        .unwrap();
        assert!(options.authorize_url);
    }

    #[test]
    fn unknown_arguments_and_missing_values_are_refused() {
        assert!(Options::parse(&args(&["--nope"])).is_err());
        assert!(Options::parse(&args(&["--redirect-uri"])).is_err());
    }
}
