# Changelog

## 2.0.0 — 2026-10-22

The first release since 1.5.0. It collects the entries below that were never published separately (1.7.0, 1.6.1, 1.6.0); read them for the details. Every Catz Connect SDK (TypeScript, Go, PHP, Rust, Dart/Flutter) is released as 2.0.0 together.

**Highlights**

- Message status, retry-safe sends (`SendExtras` idempotency key), `reference`, test keys, hosted OTP, the management API and the push device registry (`devapi`).
- WhatsApp approved templates and media; Email topics and tracking; push broadcasts, topics and scheduled pushes; cross-channel opt-outs.
- `send_with_options` (`SendOptions`: base URL, insecure-http opt-in); https-only base URLs; `EnvValues`' `Debug` output is redacted.
- `SendPayload` keeps the fields it had: the new per-message options are in `SendExtras`, so existing struct literals still compile.

**Upgrading from 1.5.x**

- **https only** (since the 1.6.0 entry): a plain `http://` base URL to a host other than `localhost`, `127.0.0.1`, `::1` or `10.0.2.2` is refused before a request is sent; opt in to plain http for a test server only.
- The API answers a request whose timestamp is more than 30 s off with HTTP 400 `clock_skew` (was 401): keep the sending host's clock in sync (NTP).
- Everything else is backward compatible: existing sends post the same body.

## 1.7.0 (unreleased, included in 2.0.0)

**Compatibility.** `SendPayload` has exactly the fields it had in 1.6, so
`SendPayload { … }` literals that list every field (no
`..Default::default()`) still compile. The new per-message options live in
`types::SendExtras` (`#[non_exhaustive]`, built with `SendExtras::new()` and
its methods) and go with `CatzConnect::send_with_extras(input, extras, env)`,
`send_full(input, extras, env, options)` or
`build_payload_with_extras(&input, &extras)`; `send`, `send_with_options` and
`build_payload` are unchanged.

**Message status, retry-safe sends, test keys, hosted OTP, management API, push device registry, WhatsApp templates.**

- `PushDevices::opened_with_token(publishable_key, message_id, Some(token))`:
  reports an open with the device's FCM token (verified; the first verified
  report fires `push.opened`). `opened` (no token) still records the open,
  but no webhook fires for it.
- `SendExtras::idempotency_key` (Idempotency-Key header + field),
  `SendExtras::reference`, `SendExtras::whatsapp` (`whatsapp::WhatsAppOptions`
  with `WhatsAppBody::{Positional, Named}`, header, buttons, media) and
  `SendExtras::tracking` (Email). WhatsApp templates are `Template::Named(<Meta name>)`;
  media messages `Template::Custom` with `media`.
- `devapi::Messages`, `devapi::Otp`, `devapi::Manage`, `devapi::PushDevices`,
  `devapi::codes` (+ `is_retryable`); `CatzError::api_details()`.
- `webhook::EVENTS`, `webhook::parse_event[_at]` (`test` is true for test-key events).


**Cross-channel opt-outs, topics and push broadcasts** (servers with per-channel suppressions):

- `SendExtras::topic` (Email subscription topic key) and `SendExtras::push`
  (`types::PushOptions { broadcast, topic, send_at }`); the answer's `data`
  has `broadcast_id`. New `devapi::PushApi`: `broadcast`, `cancel`,
  `subscribe`, `unsubscribe`, `topics` (server keys only).
- `PushDevices::subscribe_topics` / `unsubscribe_topics`.
- `ListMessagesInput::broadcast_id`.
- `Manage::add_suppression` / `remove_suppression` (`SuppressionInput`: every
  channel, email `topic`, or `id`).
- `codes::INVALID_TOPIC`, `TOPIC_EMAIL_ONLY`, `RECIPIENT_SUPPRESSED`,
  `WHATSAPP_OPTED_OUT`, `NOT_CANCELABLE`, `NOT_RESENDABLE`, `CONTENT_GONE`;
  `webhook::EVENTS` adds `email.complained`, `email.unsubscribed`,
  `push.opened`, `sms.inbound`, `sms.opt_out`, `whatsapp.opt_out`.

## 1.6.1 (unreleased, included in 2.0.0)

- `CatzConnect::send_with_options(input, env, SendOptions)`: the send path
  gets the same per-call switches as `Calls` — `with_base_url` (wins over
  `CATZCONNECT_BASE_URL`) and `allow_insecure_http(true)` (opt-in for a plain
  `http://` base URL to a non-local host). `send` is unchanged
  (`SendOptions::default()`).
- Note: the API now answers a request whose timestamp is more than 30 s from
  its clock with HTTP 400 and `code: "clock_skew"` (was 401). Keep the
  sending host's clock in sync (NTP).

## 1.6.0 (unreleased, included in 2.0.0)

**Security options.**

- **https only.** A plain `http://` `CATZCONNECT_BASE_URL` (or
  `Calls::with_base_url`) to a host other than `localhost`, `127.0.0.1`,
  `::1` or `10.0.2.2` now fails with `CatzError::Validation` before a request
  is sent (it used to send the API key in clear text). Opt in with
  `CATZCONNECT_ALLOW_INSECURE_HTTP=1` or `Calls::allow_insecure_http(true)`.
- `EnvValues`' `Debug` output no longer contains the API key or the private
  key (it is a manual impl now; `Debug` is still implemented).

Earlier versions: see the git history.
