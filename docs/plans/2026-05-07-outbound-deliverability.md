# Outbound Deliverability — HELO Hostname + MX Randomization

Two latent issues in the outbound delivery path. Surfaced while debugging Yahoo's `421 4.7.0 [TSS04]` defers (commits `8d64b9b`, `a6a1cde`, `385c15c`).

---

## Fix 1 — Configurable HELO/EHLO hostname

### What's wrong

`smtp-server/src/worker/pool.rs:71-77` builds the outbound transport with `builder_dangerous(domain)` and never calls `.hello_name(...)`. lettre falls back to `gethostname()`, which inside a container/VM is something like `hedwig-7d4c8b5f-xyz` or `ip-10-0-1-42` — not a public FQDN.

Strict receivers (Yahoo, AOL, many corporate gateways) require:
- EHLO is a public FQDN
- The connecting IP has a PTR record matching that FQDN (FCrDNS)

We fail those checks silently and get intermittent deferrals from Yahoo/AOL while Gmail (which doesn't care) accepts the same mail. May contribute to a fraction of the TSS04 hits we attribute to reputation.

### What to do

Add `helo_hostname: Option<String>` to the `[server]` config and pass it to lettre's `.hello_name(ClientId::Domain(...))`.

**Files:**
- `smtp-server/src/config.rs` — new field
- `smtp-server/src/callbacks.rs` — read + forward
- `smtp-server/src/worker/mod.rs` — carry into PoolManager constructor
- `smtp-server/src/worker/pool.rs` — apply `.hello_name(...)` when set
- `config.example.toml`, `config.example.huml` — document the field
- `dev/config.test-throttle.toml` — set to `hedwig.local` so the e2e exercises it
- `docs/PRODUCTION_HARDENING.md` — note as a deployment requirement

**Sketch (`pool.rs`):**

```rust
use lettre::transport::smtp::extension::ClientId;

let mut builder = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(domain)
    .port(25)
    .tls(lettre::transport::smtp::client::Tls::Required(tls_params))
    .timeout(Some(std::time::Duration::from_secs(10)))
    .pool_config(pool_cfg);
if let Some(name) = self.helo_hostname.as_deref() {
    builder = builder.hello_name(ClientId::Domain(name.to_string()));
}
let transport = builder.build();
```

Same conditional in the `outbound_local` branch above. Apply to both branches.

**Default behavior unchanged:** if `helo_hostname` is unset, lettre keeps using `gethostname()` — existing deployments don't regress until they opt in.

**Worth adding:** at startup, if `helo_hostname` is set but doesn't contain a `.`, log a warning. It's almost certainly wrong.

### Verifying

Use the existing throttle harness (`385c15c`). Set `helo_hostname = "hedwig.local"` in `dev/config.test-throttle.toml`, restart the stack, send a message:

```
docker compose -p hedwig-throttle logs fake-throttle | grep EHLO
```

Should show `EHLO hedwig.local`. Without the fix you'd see whatever `gethostname` returned inside the smtp container.

### References

- RFC 5321 §4.1.1.1, §4.1.4
- Yahoo Postmaster: https://postmaster.yahooinc.com/error-codes
- lettre: `lettre::transport::smtp::extension::ClientId`, `AsyncSmtpTransportBuilder::hello_name`

---

## Fix 2 — Randomize MX selection within equal priority

### What's wrong

`smtp-server/src/worker/mod.rs:562-565`:

```rust
let mut mx = mx_lookup.iter().collect::<Vec<&MX>>();
mx.sort_by_key(|a| a.preference());
```

`sort_by_key` is **stable**. For domains with multiple equal-preference MX records (Yahoo: `mta5/mta6/mta7.am0.yahoodns.net` all at preference 1) the iteration order is whatever the resolver returned, and that order is then captured into `mx_cache` for the entire DNS TTL.

Net effect: we hammer one MX of an equal-priority set repeatedly until the cache TTL expires. This:

1. **Violates RFC 5321 §5.1**, which says equal-priority MXes MUST be randomized "to spread the load across multiple mail exchangers."
2. **Compounds throttling**: if mta5 is throttling our IP, every retry also lands on mta5.
3. **Hides per-MX issues**: a misconfigured MX in the set looks like a total outage to us.

Gmail isn't affected because their MXes have distinct preferences (5/10/20/30/40), so the stable sort is naturally deterministic and correct.

### What to do

Shuffle the MX list, then stable-sort by priority. The shuffle randomizes within ties; the stable sort preserves the priority ordering.

```rust
use rand::seq::SliceRandom;

let mut mx: Vec<&MX> = mx_lookup.iter().collect();
mx.shuffle(&mut rand::thread_rng());
mx.sort_by_key(|a| a.preference());
```

Two lines. Do it on every consume (not at cache-insert time) so each delivery genuinely randomizes — otherwise the first shuffle's result sticks for the whole DNS TTL.

**Files:**
- `smtp-server/src/worker/mod.rs` — the two new lines
- `smtp-server/Cargo.toml` — add `rand` if not already there (check first; might be transitive)

### Verifying

Easiest: temporarily change `dev/Corefile` so `throttle.test` returns three equal-priority MXes pointing at three different fake servers (or one fake-throttle plus mailpit twice with different aliases), send 30 messages, count distribution. With the fix it should be roughly 10/10/10; without, all 30 hit the same MX.

### References

- RFC 5321 §5.1
- `rand::seq::SliceRandom::shuffle`

---

## Risk

Both fixes are local to the outbound path and compose cleanly with the recently-fixed defer-vs-bounce classification. Neither touches storage, queue semantics, or inbound SMTP.

- HELO: opt-in via config, no default change.
- MX randomization: behavior change for any domain with equal-priority MXes. Strictly an improvement.
