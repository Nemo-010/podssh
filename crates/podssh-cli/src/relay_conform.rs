//! `podssh relay conform --relay-host HOST[:PORT] [--target HOST:PORT]
//! [--reverse] [--json]` (T-713): whether one relay host keeps the contract
//! of `docs/relay.md`, by using it, so that the CI of another relay (a
//! Worker's, GitHub PodUtils/podcrates#35) and a deployment can gate on it.
//! `relay spec` compares a published document with facts; this asks the
//! relay itself. Each check is one object: its id, the clause of the
//! contract (a section of `docs/relay.md`), a verdict (`pass`, `fail` or
//! `skip`), the words and the time. The exit is 0 with no fail, 1 with one,
//! and 69 when the host did not answer.
//!
//! The host is the one that `--relay-host` names, never the default relay
//! unasked: the run mints tokens and makes a pair there. Each token lives in
//! this process alone and is never printed; the pair of `--reverse` is the
//! check's own, stopped at the end, also after a failure.

use std::io::Write;
use std::time::{Duration, Instant};

use podssh_relay::relay::Relay;
use podssh_ws::Trust;
use serde_json::{json, Value};

use crate::exitmap::Fault;
use crate::relay_cmd::{block_on, RelayArgs};
use crate::relay_settings::Refusal;

/// The limit on each request, upgrade and wait for a frame.
pub(crate) const STEP: Duration = Duration::from_secs(10);
/// The limit on a whole run: above the longest idle cut that a run waits
/// for, the keepalive and the reverse road's limits together, so that it
/// never cuts the stop of the check's pair.
const RUN_LIMIT: Duration = Duration::from_secs(600);

/// The clauses of the contract: the head of each section's title of
/// `docs/relay.md`, before its colon and with no work id.
pub(crate) mod clause {
    pub const RELAY: &str = "The relay";
    pub const FORWARD: &str = "The forward path";
    pub const TOKENS: &str = "Tokens";
    pub const LIMITS: &str = "Limits that users see";
    pub const OPTIONS: &str = "Connect options (query string)";
    pub const CLOSES: &str = "Errors and close codes";
    pub const DIAGNOSTICS: &str = "Diagnostics";
    pub const REVERSE: &str = "The reverse path";
    pub const ROLE_REVERSE: &str = "The relay role's reverse road";
    pub const LAYER: &str = "The relay role's resumable layer";
}

/// A check's verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    Pass,
    Fail,
    Skip,
}

impl Verdict {
    fn word(self) -> &'static str {
        match self {
            Verdict::Pass => "pass",
            Verdict::Fail => "fail",
            Verdict::Skip => "skip",
        }
    }
}

/// One check: what it checked, against which clause, and how it went.
#[derive(Debug, Clone)]
pub(crate) struct Check {
    pub id: &'static str,
    pub clause: &'static str,
    pub verdict: Verdict,
    pub detail: String,
    pub ms: u64,
}

impl Check {
    /// A check that began at `started`; its words on one line, as a relay's
    /// body can hold anything.
    pub(crate) fn new(
        id: &'static str,
        clause: &'static str,
        verdict: Verdict,
        detail: impl Into<String>,
        started: Instant,
    ) -> Check {
        let detail = podssh_ws::text::one_line(&detail.into());
        Check { id, clause, verdict, detail, ms: started.elapsed().as_millis() as u64 }
    }

    pub(crate) fn pass(id: &'static str, clause: &'static str, detail: impl Into<String>, started: Instant) -> Check {
        Check::new(id, clause, Verdict::Pass, detail, started)
    }

    pub(crate) fn fail(id: &'static str, clause: &'static str, detail: impl Into<String>, started: Instant) -> Check {
        Check::new(id, clause, Verdict::Fail, detail, started)
    }

    pub(crate) fn skip(id: &'static str, clause: &'static str, detail: impl Into<String>) -> Check {
        Check::new(id, clause, Verdict::Skip, detail, Instant::now())
    }

    fn json(&self) -> Value {
        json!({ "id": self.id, "clause": self.clause, "verdict": self.verdict.word(), "detail": self.detail,
                "ms": self.ms })
    }

    fn line(&self) -> String {
        format!("{} {} ({}) {} ms: {}", self.verdict.word(), self.id, self.clause, self.ms, self.detail)
    }
}

/// The checks of a run, in their order, and whether the host answered.
#[derive(Debug, Default)]
pub(crate) struct Report {
    pub checks: Vec<Check>,
    /// The host did not answer at all: no relay to judge (69).
    pub unreachable: bool,
}

impl Report {
    pub(crate) fn push(&mut self, check: Check) {
        self.checks.push(check);
    }

    fn count(&self, verdict: Verdict) -> usize {
        self.checks.iter().filter(|c| c.verdict == verdict).count()
    }

    /// 69 for a host that did not answer, else 1 for a fail, else 0.
    pub(crate) fn exit(&self) -> i32 {
        if self.unreachable {
            Fault::RelayUnreachable.code()
        } else if self.count(Verdict::Fail) > 0 {
            1
        } else {
            0
        }
    }
}

/// What a run checks, and where.
pub(crate) struct Plan {
    pub relay: Relay,
    pub trust: Trust,
    /// The target of the sessions that the relay dials, when one was named.
    pub target: Option<(String, u16)>,
    pub reverse: bool,
}

/// The target of the checks that need none dialed: `--target`, else the
/// reference of `podssh ping`; a session of `?dial=lazy` to it that sends
/// no byte never reaches it.
pub(crate) fn lazy_target(plan: &Plan) -> (String, u16) {
    match &plan.target {
        Some(target) => target.clone(),
        None => (crate::ping::relay::REFERENCE.0.to_string(), crate::ping::relay::REFERENCE.1),
    }
}

/// Run `podssh relay conform`; returns the exit code.
pub fn run(args: &RelayArgs, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let plan = match plan(args) {
        Ok(plan) => plan,
        Err(refusal) => return refusal.report("relay conform", err),
    };
    let mut report = Report::default();
    let ran = block_on(async { tokio::time::timeout(RUN_LIMIT, checks(&plan, &mut report)).await });
    match ran {
        Err(refusal) => return refusal.report("relay conform", err),
        Ok(Err(_)) => report.push(Check::fail(
            "run",
            clause::RELAY,
            format!("the run passed its limit of {} s", RUN_LIMIT.as_secs()),
            Instant::now(),
        )),
        Ok(Ok(())) => {}
    }
    let code = report.exit();
    if args.json {
        let checks: Vec<Value> = report.checks.iter().map(Check::json).collect();
        let target = plan.target.as_ref().map(|(host, port)| podssh_ws::dial::authority(host, *port));
        let doc = json!({
            "schema": 1, "podssh": crate::help::version(), "relay": plan.relay.name(), "target": target,
            "reverse": plan.reverse, "checks": checks, "passed": report.count(Verdict::Pass),
            "failed": report.count(Verdict::Fail), "skipped": report.count(Verdict::Skip), "exit": code,
        });
        let _ = writeln!(out, "{doc}");
    } else {
        for check in &report.checks {
            let _ = writeln!(out, "{}", check.line());
        }
        let _ = writeln!(
            out,
            "{}: {} passed, {} failed, {} skipped",
            plan.relay.name(),
            report.count(Verdict::Pass),
            report.count(Verdict::Fail),
            report.count(Verdict::Skip)
        );
        if report.unreachable {
            let _ = writeln!(err, "podssh relay conform: {} did not answer", plan.relay.name());
        }
    }
    code
}

/// The host, its trust and the target, from the command line. The host is
/// the one named: the run mints and pairs there, so the default relay is
/// checked only when a person names it.
fn plan(args: &RelayArgs) -> Result<Plan, Refusal> {
    let Some(named) = args.relay_host.as_deref() else {
        return Err(Refusal::usage(
            "conform needs --relay-host HOST[:PORT]: it mints tokens there, and checks only a host that you name",
        ));
    };
    if named.contains(',') {
        return Err(Refusal::usage(format!("conform checks one host, and --relay-host {named} names several")));
    }
    let target = match &args.target {
        Some(t) => Some(
            crate::proxy::parse_target(Some(t), None)
                .map_err(|why| Refusal::usage(format!("conform: --target {t}: {why}")))?,
        ),
        None => None,
    };
    let (relays, trust) = crate::relay_diag::settings(args)?;
    Ok(Plan { relay: relays.primary().clone(), trust, target, reverse: args.reverse })
}

/// Each check in its order: the documents, the forward road, then the
/// reverse road when asked. A host that does not answer ends the run.
async fn checks(plan: &Plan, report: &mut Report) {
    let offers = crate::relay_conform_forward::documents(plan, report).await;
    if report.unreachable {
        return;
    }
    crate::relay_conform_forward::run(plan, &offers, report).await;
    if plan.reverse {
        crate::relay_conform_reverse::run(plan, &offers, report).await;
    } else {
        report.push(Check::skip("reverse", clause::REVERSE, "not asked: --reverse"));
    }
}

/// What the relay offers beside the contract, from its `/relays.json`: each
/// extension's checks come from its own offer, and none is a skip.
#[derive(Debug, Default, Clone)]
pub(crate) struct Offers {
    /// The limits that it publishes, `limits` of `/relays.json`.
    pub idle_ms: Option<u64>,
    /// `reverse.halt`: the owner's halt of a pair.
    pub halt: bool,
    /// `forward`: the forward road in the resumable layer.
    pub layer: bool,
}

impl Offers {
    pub(crate) fn of(doc: &Value) -> Offers {
        Offers {
            idle_ms: doc["limits"]["idle_timeout_ms"].as_u64(),
            halt: doc["reverse"]["halt"].as_bool() == Some(true),
            layer: doc["forward"].is_object(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_exit_is_69_for_no_answer_then_1_for_a_fail_then_0() {
        let now = Instant::now();
        let mut report = Report::default();
        report.push(Check::pass("a", "Tokens", "ok", now));
        report.push(Check::skip("b", "Tokens", "not offered"));
        assert_eq!(report.exit(), 0);
        report.push(Check::fail("c", "Tokens", "wrong", now));
        assert_eq!(report.exit(), 1);
        report.unreachable = true;
        assert_eq!(report.exit(), Fault::RelayUnreachable.code());
    }

    #[test]
    fn a_check_keeps_its_words_on_one_line() {
        let check = Check::fail("x", "Tokens", "403\r\nforward: missing\u{1b}[31m", Instant::now());
        assert!(!check.detail.contains(['\r', '\n', '\u{1b}']), "{}", check.detail);
        let v = check.json();
        assert_eq!((v["id"].as_str(), v["verdict"].as_str()), (Some("x"), Some("fail")));
    }

    #[test]
    fn the_offers_come_from_the_relays_own_document() {
        let doc = json!({ "limits": { "idle_timeout_ms": 5000 }, "reverse": { "halt": true }, "forward": {} });
        let offers = Offers::of(&doc);
        assert_eq!((offers.idle_ms, offers.halt, offers.layer), (Some(5000), true, true));
        let none = Offers::of(&json!({ "limits": {} }));
        assert_eq!((none.idle_ms, none.halt, none.layer), (None, false, false));
    }
}
