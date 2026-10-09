# The Confidior Trust Model

Who do you trust when you see a Confidior badge, and how does that change across trust levels?

## Why this document exists

The Confidior badge looks like a security credential. It has a level (0-5), a risk (LOW/MEDIUM/HIGH/CRITICAL), attestation dimensions (measurement, debug, TCB, freshness), and a data-commitment hash binding it to the bundle. But in its simplest form, the badge is not what most people assume it is. This document says exactly what it is, what it isn't, and when the difference matters.

**Read this if:** you're auditing a Confidior badge, evaluating whether to use the tool, considering the engine's current outputs for compliance, or writing documentation that references the badge.

## TL;DR

The badge is a credit score until you get a fully cryptographic trust chain. **No single party is the root of trust** in the final design. Not Confidior, not the operator, not the cloud provider. The chain is built so that the *minimum* number of parties must be trusted, and each one is auditable.

| Question | Present (signed) | Near future (countersigned) | Far future (fully cryptographic) |
|---|---|---|---|
| Does the badge prove the engine ran? | Yes (math verifies) | Yes (math verifies) | Yes (math verifies + SNARK proves) |
| Does the badge prove who ran it? | Yes, operator's persistent key | Yes, operator + Confidior | Yes, verifiable from reproducible build |
| Does the badge prove it existed at time T? | Yes, Rekor inclusion proof | Yes, Rekor inclusion proof | Yes, Rekor inclusion proof |
| Does the badge prove the operator is honest? | No (self-signed) | **No** (counter-signature is "we ran it", not "we trust the operator") | No, but the build is reproducible so any honest operator gives the same result |
| Does the badge prove the workload is what you expect? | No | Yes (full Measurement CI) | Yes (Measurement CI + reproducible build) |
| Should I trust it? | Trust the operator's key + Rekor (public log) + the open-source engine code | Trust Confidior's reviewers + everything from the Present (signed) level | Trust the math, the silicon, the spec, the code. No party. |

**Present (signed) framing:** the badge is signed by an operator (whose key you have) and anchored to a public transparency log. The engine is open-source. No third party involved.

**Near future framing:** same as above, plus an independent third party (Confidior) counter-signs to say "we ran the same engine on the same evidence and got the same result."

**Far future framing:** the math is the trust. Reproducible builds + SNARK proofs eliminate the operator and the third party from the trust chain.

## "Zero trust": what's actually possible

**Full zero-trust is not achievable.** You always have to trust *something*: the CPU vendor's TEE module, the cryptography research community, the spec, the verifier code. But we can compress the trust chain drastically.

The minimum trust stack for "fully cryptographic" attestation:

1. **Trust the CPU vendor's TEE module.** Intel/AMD have the most to lose from lying. Their silicon + microcode + spec must do what they say. The vendor-published measurement is the canonical anchor.
2. **Trust the cryptography research community.** The math is sound.
3. **Trust the open-source engine code.** Anyone can audit. Reproducible builds let anyone re-derive the measurement.
4. **Trust the reproducible build infrastructure.** Anyone can re-derive the measurement from source.

That's it. No operator. No Confidior. No Rekor. Just silicon, math, code, and the build.

The path to that minimum stack:

| Trust level | Trust compression |
|---|---|---|
| **Present (unsigned)** | Trust the operator. Trust the ephemeral key (which is throwaway). Trust whoever sent you the bundle. |
| **Present (signed)** | Trust the operator's stable key. Trust Rekor (public, auditable). Trust the open-source engine. No Confidior involved. |
| **Near future** | All of Present (signed) + trust Confidior's key. (This *adds* a trust assumption, doesn't remove one.) |
| **Future** | All of Near future + multi-party countersigning (Confidior + Veraison + academic partner, M-of-N). One party being compromised is no longer fatal. |
| **Far future (reproducible)** | Reproducible builds (anyone re-derives the measurement) + boot-time measurement verification (the measurement is meaningful because you know what code it corresponds to). The operator's honesty is no longer needed. |
| **Far future (fully cryptographic)** | SNARK proof of correct execution. The engine's output is mathematically proven, not just signed. Anyone can verify the proof. No party needs to be trusted. |

**The "fully cryptographic" path is the Far future.** The current Present (signed) level already removes Confidior from the trust chain. That was the point.

## What the badge proves today (unsigned)

The unsigned badge proves exactly one thing: **someone ran some version of the Confidior engine on some evidence, and got this result.**

Specifically:

- Yes: **The bundle is well-formed.** The hashedrekord-anchored bundle has a valid Ed25519 signature. The math works.
- Yes: **The badge is tied to the bundle.** The badge SVG has a `data-commitment` attribute containing `sha256(bundle_id:level:signature[:dimension=value...])` (truncated to 16 hex chars). Tampering with the bundle or the dimension scores breaks the commitment.
- Yes: **The engine produced this output.** The bundle includes the full evaluation: assurance level, residual risk, boundary statement, attack list, C5 mappings.
- No: **You don't know who signed it.** The signing key is generated fresh per evaluation and discarded. There's no public key registry, no way to verify "this came from Confidior instance X."
- No: **You don't know when it was signed.** The bundle has a `timestamp` field, but the operator controls it. No external timestamp authority.
- No: **You don't know if the operator is honest.** Anyone can run the open-source engine, generate a fresh keypair, and sign "Level 5, Confidior Certified." From a verifier's perspective, this is indistinguishable from a real Confidior evaluation.
- No: **You don't know the workload's runtime behavior.** Boot-time measurement verification exists (`confidior measure`, captured vs expected, computed vs published) but is not yet widely tested; runtime behavior inside the enclave is not verified.
- No: **The bundle isn't anchored anywhere public.** (Present (signed): yes, anchored to public Sigstore Rekor via hashedrekord; payload content never revealed.)

**In one sentence:** in unsigned mode, the badge proves the *evaluation happened*, not *who did it, when, or whether they're trustworthy*.

## What full cryptographic credibility requires

The full chain, in order. Without all five, the badge is decorative.

### 1. Operator's persistent key

The operator generates a stable keypair (e.g., on first run, persisted to disk), uses it for all bundles, and publishes the public key somewhere verifiable (their website, a git repo, a keyserver).

- **What it enables:** verifier checks "this bundle was signed by key X, and I know what X is."
- **What it doesn't:** it doesn't tell you who X is. A persistent key tied to an anonymous email is still anonymous.
- **Present (signed) status:** done. `--key-path` flag persists the keypair to disk. Public key hex is embedded in each signature.

### 2. Auto-Rekor anchoring

After signing, the bundle is submitted to Sigstore Rekor (free, public, 99.5% SLO). The Rekor entry UUID + signed entry timestamp are embedded in the bundle.

- **What it enables:** anyone can query Rekor and confirm the bundle existed at time T, and isn't a replay.
- **What it doesn't:** it doesn't tell you whether the bundle's *content* is true. It proves "this specific bundle was anchored at this time," nothing about whether the operator was honest.
- **Present (signed) status:** done. Automatically submitted after `create_signed_bundle()` when `--key-path` is used. Uses hashedrekord entry type (content never revealed to Rekor). Verified against live Rekor API (HTTP 201, tested 2026-07-15).

### 3. Inclusion proof in the bundle

The Rekor entry UUID + signed entry timestamp are part of the bundle's signed payload, not a separate field.

- **What it enables:** verifier doesn't need to query Rekor to check the anchor. The proof is in the bundle itself.
- **What it doesn't:** same as #2. Inclusion proves time-of-existence, not truth-of-content. It also does not prove the log signed the tree on its own, that is the checkpoint's half.
- **Present (signed) status:** done, both halves. `RekorEntry` carries the log entry *and* the material to re-verify it: the entry body (the leaf preimage, without which the proof cannot be evaluated at all), the RFC 9162 inclusion proof returned with the submission, and the log's signed checkpoint (`src/core/merkle.py` + `src/core/notes.py`). A reader with the log's public key in their trust root can rebuild the Merkle root from the audit path and check the checkpoint signature without trusting Confidior, no network access needed, and `confidior verify` now prints that result on its own output line. With no such key, the checkpoint check returns "unjudged", and the anchor reads as unproven rather than proven.

### 3b. SCITT receipts (RFC 9943 / RFC 9942)

SCITT is the standard this anchoring pattern comes from, and RFC 9943 shipped in June 2026. A receipt is the same two facts as a Rekor anchor, an inclusion proof and a signature over the root, in a COSE container.

- **What it enables:** a transparency service other than Rekor can issue the receipt, and the receipt verifies against a key the operator named. `src/export/scitt.py` verifies receipts and emits Signed Statements in the standard's shape for a TS to register.
- **What it doesn't:** the engine runs no transparency service of its own, so it issues no receipts and participates in no registration policy. Verifying a receipt proves a TS issued it; it says nothing about the truth of the statement inside.
- **Present (signed) status:** verification done, emission done, registration not started. Nothing yet consumes a receipt from a live TS, because the only deployed instance we can reach is Sigstore's Rekor, and its checkpoints already verify directly.

### 4. Public key registry for Confidior

In the Near future, Confidior counter-signs bundles with a Confidior-controlled key. The public key is published on `confidior.com`, signed by a long-term identity key (e.g., via Sigstore's keyless signing).

- **What it enables:** verifier checks "this bundle was reviewed by Confidior's key, and I know what that key is."
- **What it doesn't:** it doesn't make the operator's evidence honest. Confidior counter-signing means "Confidior ran this engine on this evidence," not "the evidence is true."
- **Present (unsigned) status:** N/A. No Confidior-hosted service yet.
- **Near future plan:** Hosted Verify API is the first hosted service component. That's where Confidior's signing identity first exists.

### 5. Confidior counter-signature

The hosted Confidior service takes the operator-signed bundle, verifies it, and re-signs it with Confidior's key. The bundle now has two signatures: operator's (proves operator ran it) and Confidior's (proves Confidior reviewed it).

- **What it enables:** end-to-end credibility. The verifier checks: operator's signature (proves it ran), Rekor inclusion (proves when), Confidior's signature (proves Confidior reviewed), operator's public key (proves who's running it).
- **What it doesn't:** the evidence is still operator-supplied. Confidior can attest "we ran our engine on this evidence," not "the evidence is true." That's the engine's job.
- **Present (unsigned) status:** N/A.
- **Near future plan:** Hosted Verify API tiers provide this.

## Present (signed): minimum-viable credibility

What we shipped to give the badge *some* cryptographic assurance beyond the unsigned baseline:

- **Operator's persistent key** (step 1): `--key-path` flag persists the keypair. Lets operators sign with a stable identity.
- **Auto-Rekor** (step 2): automatically submitted after signing. Uses hashedrekord entry type.
- **Inclusion proof in bundle** (step 3): RekorEntry attached to the bundle signature.
- **Documented trust model** (this document): done.

What the Present (signed) level does NOT add:
- Confidior counter-signing (requires hosted service, that's the Near future)
- Public key registry for Confidior (no Confidior service to sign with yet)

**Present (signed) trust level:** "the operator who signed this is the operator whose public key I have. The bundle was anchored to a public transparency log at the timestamp in the bundle. The operator is the only party that reviewed the evidence; Confidior has not."

This is meaningfully stronger than unsigned (which has no persistence and no anchoring) but weaker than Near future (which has Confidior's review).

## Near future: additional trust layer (not full credibility)

When the Hosted Verify API launches, Confidior counter-signs operator-signed bundles:

- Operator signs with persistent key (Present (signed))
- Confidior re-signs with Confidior key
- Bundle is auto-anchored to Rekor
- Inclusion proof is in the bundle
- Public key registry on `confidior.com` documents all keys
- Verifier checks: operator's signature, Confidior's signature, Rekor entry, key registry

**What Near future ADDS:** an independent third party (Confidior) reviews the bundle. Two pairs of eyes: the operator's and Confidior's. Compromise of the operator's key alone is no longer fatal. Confidior can refuse to counter-sign a suspicious bundle.

**What Near future does NOT achieve:** "full cryptographic credibility." Near future *adds* a trust assumption (Confidior's key), it doesn't remove one. If Confidior is compromised or coerced, Near future trust is broken. To actually get to "trust the math" requires Far future (reproducible builds + SNARK).

**Honest framing:** Near future is for users who want a third-party review of operator-signed bundles. It is *not* the end of the trust chain. Far future (reproducible builds) and Far future (fully cryptographic) are.

## The temporal model: is this still trustworthy?

Every verdict is a point-in-time statement. The temporal model tracks whether it's
still valid:

- **Staleness**, the TCB lag check (`confidior measure --tcb`): how many months the platform's
  TCB is behind the CVE fix threshold. A verdict graded against a stale TCB is honest only if
  the lag is stated.
- **Liveness**, is the platform still producing evidence? A dead or silent platform is a
  different trust question than a graded one.
- **CVE invalidation**, when a new attack lands (NVD/OpenCVE feed), the verdict re-grades. The
  "was F, now D" re-grade is the temporal model in action: the fix landed, the verdict updated.

**The product shape:** the point-in-time verdict is the assessment; the continuous verdict is
the subscription. The temporal model is what makes the badge a living artifact instead of a
static PDF.

## The verification log: what Confidior has verified

The verification log is the public record of what Confidior has independently verified, with
boundaries stated:

- **Tinfoil**, published TDX measurements independently reproduced: computed-vs-published
  MATCH 4/4 platforms (MRTD + RTMR0 byte-identical). Evidence: `data/vendor-evidence/tinfoil/verdict.json`.
- **RedPill**, live TDX attestation fetched from the public endpoint, verified end-to-end:
  ALLOW Level 2, HIGH, 51/100, Rekor anchored. The quote is public by design (remote
  attestation exists so anyone can verify).

**What the log proves:** the method works on real evidence. **What it does not prove:** a
track record, two verifications is a proof-of-concept, not a history. The log grows with each
verification (Phala, VoltageGPU, AWS, more platforms, more quotes), and the boundaries are
stated the same way as the results.

## Reading an ALLOW/CRITICAL/SCORE result

Three signals land on a single badge and they are not the same signal:

- **ALLOW / DENY**, the policy decision. The default policy permits any quote with assurance level ≥ 2 and debug disabled. A quote can be ALLOWed at the policy layer regardless of risk grade.
- **CRITICAL / HIGH / MEDIUM / LOW**, the residual-risk label. For TDX today, unmitigated software-applicable attacks apply; the default cloud-admin threat model excludes physical-layer attacks.
- **The numeric score (`51/100`, `D`)**, the weighted aggregate of five dimensions. The threat dimension is reduced by applicable software attacks, which drags the score toward grade-D territory. The score is threat-model-relative: the same evidence grades differently under a physical-capable threat model.

A verdict of "ALLOW, HIGH, 51/100" is the engine saying "this quote is real and passes the policy, but the platform grades D against the default threat model because of applicable software attacks." That combination is the honest answer; it is not a contradiction. The presentation will improve in future revisions: the grading system is evolving toward more granular sub-scores (per-attack cost, per-platform mitigation status, fresh-data weighting), and the policy system will gain profile-tied defaults (the present default is intentionally lenient, operators tighten it). Until then, this doc is the canonical explanation of how to read a Confidior verdict.

## How to use this in practice

### If you're an operator running Confidior in the Present (signed) configuration

Your bundles are signed with your persistent key (from `--key-path`) and auto-anchored to Rekor. The badge proves "I (whose key you have) ran Confidior on this evidence, and the bundle existed at this time." Nothing more about your honesty. The engine is open-source; if the verifier cares, they can re-run it themselves.

- **Present (signed):** use `--key-path` to load a stable keypair. Publish the public key on your website. Bundle recipients can now check "this came from you" against the key they have for you.
- **Near future:** your bundles are Confidior counter-signed automatically. Confidior's reviewers have run the same engine on the same evidence. Two-party review.

### If you're a verifier receiving a Confidior bundle in the Present (signed) level

You can:
- You can verify the Ed25519 signature on the bundle using the operator's published public key (proves it wasn't tampered with + the operator signed it)
- You can verify the SHA256 commitment in the badge (proves the badge is tied to the bundle)
- You can query Rekor with the inclusion proof (proves the bundle existed at time T)
- You can read the engine's output (assurance level, residual risk, boundary statement, attack list, C5 mappings)
- You can audit the engine source code yourself (it's open-source; verify the math yourself)
- You cannot verify when it was signed (Rekor gives time-of-existence, not a notarized timestamp)
- You cannot verify the operator is honest (only Confidior counter-signing does that, in the Near future)

**Rule of thumb:** if you trust the operator's key and you've read the engine source, the bundle is good. If you don't know the operator, treat it as a draft. The math is verifiable; the operator's intent is not.

### If you're a compliance auditor

Present (signed) bundles are not suitable for compliance submissions on their own. Use them as:
- A starting point for an internal assessment
- Evidence that the operator is doing due diligence (timestamped, signed, anchored)
- A draft to inform a human auditor's review

Near future and beyond bundles will be suitable for compliance submissions, subject to the engine's evidentiary limitations.

### If you're considering using Confidior for your own product

| Use case | Present (signed) OK? | Near future needed? | Far future (fully crypto) needed? |
|---|---|---|---|
| Internal risk grading (you trust the operator) | Yes | No | No |
| "Our product is Confidior-graded" (public claim) | Partial, with key + Rekor | Yes | No |
| Compliance submission to a regulator | No | Partial | Yes |
| Customer-facing security badge | Partial, with key + Rekor + trust model | Yes | No |
| Engineering decision (which TEE provider to use) | Yes (internal only) | No | No |
| Third-party verifiable attestation (no single party trusted) | No | No | Yes |

## The credibility chain: visual

The chain has *two parallel paths*: operator-side and Confidior-side. They converge at "fully cryptographic."

```
Operator-side (Present / signed):
  Step 1: Operator's persistent key
    ↓
  Step 2: Auto-Rekor anchoring
    ↓
  Step 3: Inclusion proof in bundle
    ↓
  "Operator-signed, Rekor-anchored, auditable engine"

Confidior-side (Near future, ADDS a trust layer):
  Step 4: Public key registry for Confidior
    ↓
  Step 5: Confidior counter-signature
    ↓
  "+ Independent third-party review"

Beyond (Far future, REMOVES trust assumptions):
  Step 6: Reproducible builds (operator no longer trusted)
    ↓
  Step 7: Boot-time measurement is meaningful (because you know what code it corresponds to)
    ↓
  Step 8: SNARK proof of correct execution (no party needs to be trusted)
    ↓
  "Fully cryptographic, zero-trust"
```

Present (signed) completes operator-side (steps 1-3). Near future adds Confidior-side (steps 4-5). The "fully cryptographic" path is Far future (steps 6-8).

The mistake this doc used to make: framing Near future as "full credibility." It isn't. Near future *adds* a trust assumption; Far future *removes* trust assumptions. The chain doesn't end at Near future.

## Honest framing for the launch story

For Show HN, README, and the case study, the trust model should be communicated as:

> "The Confidior badge is a credit score, not a credential. In the unsigned version, you trust the operator who signed it. Once countersigning arrives, the badge is also signed by Confidior and anchored to a public transparency log, giving it full cryptographic auditability. Today's badge is the draft; tomorrow's is the notarized document."

This framing is consistent across the engine's documentation.

## What this document does NOT cover

- What the engine can grade against the evidence
- What's pending in the execution log
- The strategic roadmap (planned internally)
- Boot-time measurement verification

## When to revise this document

Revise when:
- Present (signed) ships (update that section to reflect what landed)
- Near future launches (update that section with the actual public key + Rekor workflow)
- The trust model changes (e.g., Confidior decides to add a third-party auditor)
- A new attack on the trust model emerges (e.g., Sigstore Rekor is compromised)

Do not revise when:
- Tactical decisions change
- A specific test fails

## Validated

- 2026-07-15 against the source code: `src/export/dsse.py` (Ed25519 signing, hashedrekord anchoring), `src/export/rekor.py` (live Rekor API: HTTP 201, Log Index 2172048414), `src/core/taxonomy.py` (`EvidenceBundle` schema), `tests/` (163 tests, 0 failures)
- 2026-07-31 revalidated: 226 tests, 0 failures (dev); 216 on a fresh clone (10 local-only scraper tests excluded); badge commitment now includes sorted dimension pairs via `compute_badge_commitment()`
- 2026-10-08 revalidated: 356 tests, 0 failures; `ruff check src tests` clean. The verdict now carries a version manifest (engine, schema, weight profile, policy, rubric, knowledge base), so a bundle names the inputs that produced it
- 2026-10-09 revalidated: 361 tests, 0 failures; `ruff check src tests` clean. The bundle now carries a signed `references[]` list (engine, schema, weights, rubric, knowledge base, policy, input) inside the payload, so the signature covers the derivation list and not only the verdict; `policy_version` is the hash of the rules actually evaluated. Also: `to_dict()`/`from_dict()` no longer drop `platform_score`, `quote_score`, `evidence_class` and `scoring_attacks`, so a reloaded bundle matches the live verdict. And every bundle the CLI and web UI write now verifies against its own signature: the compliance mappings and display dimensions are set before signing instead of after. Badge commitments are unchanged (they hash bundle id + level + signature hex + dimensions, not the payload)
