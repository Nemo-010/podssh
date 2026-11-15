//! The credentials of the Dev Tunnels road (T-785) against the stand-in of
//! `pod-devtunnel`: with no token file a tunnel that allows anonymous access
//! is reached, and one that does not is refused with the form named; a
//! tunnel's access token from its private file passes; both files named is
//! a setting that podssh refuses before anything connects. No token reaches
//! a failure's text.

#![cfg(all(feature = "devtunnel-standin", unix))]

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::Duration;

use pod_core::Class;
use pod_devtunnel::standin::{Plan, Standin};
use podssh_relay::devtunnel::{self, credential_from, lines, Credential, Road};
use podssh_ws::{ProxyChoice, Trust};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const USER_TOKEN: &str = "made-up-user-token-of-the-credentials-test";
const ACCESS_TOKEN: &str = "made-up-access-token-of-the-credentials-test";
const LIMIT: Duration = Duration::from_secs(20);
const ECHO_PORT: u16 = 22;

async fn standin(anonymous: bool, access: Option<&str>) -> Standin {
    let mut plan = Plan::echo("github", USER_TOKEN);
    plan.anonymous = anonymous;
    plan.access = access.map(str::to_string);
    Standin::start(plan).await.expect("the stand-in")
}

/// The road to the stand-in's tunnel with `credential`. Direct: a proxy of
/// the host must not carry a dial to the loopback.
fn road(standin: &Standin, credential: Credential) -> Road {
    let mut settings = devtunnel::settings(Some(&standin.base())).expect("the stand-in's base");
    settings.timeout = LIMIT;
    settings.backoff = |_| Duration::ZERO;
    Road::new("standin-box", credential, settings, Trust::Default, ProxyChoice::Direct).expect("a tunnel name")
}

/// A private file of this test, holding `text`.
fn private_file(name: &str, text: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-devtunnel-credentials-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    std::fs::write(&path, text).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    path
}

/// One byte there and back through `road`'s echo.
async fn echoes(road: &Road) {
    let mut stream = tokio::time::timeout(LIMIT, road.open(ECHO_PORT, lines::quiet()))
        .await
        .expect("the open within its limit")
        .unwrap_or_else(|e| panic!("open with {}: {}", road.form(), e.chain()));
    stream.write_all(b"k").await.unwrap();
    let mut back = [0u8; 1];
    tokio::time::timeout(LIMIT, stream.read_exact(&mut back)).await.expect("the echo").unwrap();
    assert_eq!(&back, b"k");
}

#[tokio::test]
async fn devtunnel_with_no_token_file_an_anonymous_tunnel_is_reached() {
    let credential = credential_from(None, None).expect("no file is no failure");
    assert_eq!(credential.form(), "no token");
    echoes(&road(&standin(true, None).await, credential)).await;
}

#[tokio::test]
async fn devtunnel_with_no_token_a_tunnel_without_anonymous_access_is_refused_by_its_form() {
    let standin = standin(false, None).await;
    let refused = road(&standin, Credential::Anonymous).open(ECHO_PORT, lines::quiet()).await.unwrap_err();
    assert_eq!(refused.class, Class::Refused, "{}", refused.chain());
    assert!(refused.chain().contains("no token"), "the form is not named: {}", refused.chain());
}

#[tokio::test]
async fn devtunnel_an_access_token_from_its_file_passes_and_no_failure_shows_it() {
    let standin = standin(false, Some(ACCESS_TOKEN)).await;
    let file = private_file("access", &format!("# devtunnel token standin-box --scopes connect\n{ACCESS_TOKEN}\n"));
    let credential = credential_from(None, Some(file.display().to_string())).expect("the access file");
    assert_eq!(credential.form(), "a tunnel access token");
    let road = road(&standin, credential);
    assert!(!format!("{road:?}").contains(ACCESS_TOKEN));
    echoes(&road).await;

    // Another access token is refused, and the refusal shows no token.
    let other = private_file("other", "made-up-other-access-token\n");
    let wrong = credential_from(None, Some(other.display().to_string())).unwrap();
    let refused = self::road(&standin, wrong).open(ECHO_PORT, lines::quiet()).await.unwrap_err();
    assert_eq!(refused.class, Class::Refused);
    assert!(!refused.chain().contains("made-up"), "{}", refused.chain());
}

#[test]
fn devtunnel_both_files_named_is_a_setting_refused_before_any_connect() {
    let user = private_file("user-both", &format!("github {USER_TOKEN}\n"));
    let access = private_file("access-both", &format!("{ACCESS_TOKEN}\n"));
    let both = credential_from(Some(user.display().to_string()), Some(access.display().to_string())).unwrap_err();
    assert_eq!(both.class, Class::Config);
    assert!(both.chain().contains(devtunnel::TOKEN_FILE_ENV) && both.chain().contains(devtunnel::ACCESS_FILE_ENV));
    let user_only = credential_from(Some(user.display().to_string()), None).unwrap();
    assert_eq!(user_only.form(), "a GitHub user token");
    // A file that others can read is refused, as ssh refuses a key.
    std::fs::set_permissions(&access, std::fs::Permissions::from_mode(0o644)).unwrap();
    let open = credential_from(None, Some(access.display().to_string())).unwrap_err();
    assert_eq!(open.class, Class::Config);
    assert!(open.chain().contains(devtunnel::ACCESS_FILE_ENV) && !open.chain().contains("made-up"));
}
