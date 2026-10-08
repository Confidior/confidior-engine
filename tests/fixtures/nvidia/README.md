# NVIDIA GPU attestation fixtures

Two of these files are real captured data. One is fabricated. The distinction
matters: a synthetic fixture can prove an adapter *rejects* something, but never
that it accepts something.

## `nvidia_hopper_sample.json` (real)

NVIDIA's own published sample GPU attestation evidence.

- Source: <https://raw.githubusercontent.com/NVIDIA/attestation-sdk/main/common-test-data/serialized_test_evidence/hopper_evidence.json>
- Repo: `NVIDIA/attestation-sdk`, Apache-2.0.
- Shape: a JSON list with one entry, keys `{arch, certificate, evidence, nonce}`.
- `arch` is `HOPPER`, which is the same architecture RedPill declares in its
  `nvidia_payload` field, so this is the shape that field would carry.

Note that this file is **not** a valid NRAS request body. NRAS v4 expects
`{nonce, arch, evidence_list: [{evidence, certificate}]}`. Posting the sample
verbatim produces a schema rejection that is easy to misread as a bad GPU. Use
`build_nras_request()` to reshape it.

## `nras_recorded_response.json` (real)

A real HTTP 200 response from
`https://nras.attestation.nvidia.com/v4/attest/gpu`, captured 2026-10-09 by
submitting the reshaped Hopper sample above.

It is worth keeping because it is a negative verdict that is **not a failure**.
The outer JWT carries `x-nvidia-overall-att-result: false`, while the per-GPU
JWT shows the GPU's own attestation report fully verified (parsed, signature
verified, cert chain FWID matched, nonce matched, arch check passed). The
negative verdict comes from driver and VBIOS RIM collateral that was never
fetched, leaving those claims unverifiable rather than failed.

`read_nras_claims()` separates those two cases. Reading the boolean alone would
produce "GPU attestation failed", which the evidence does not support.

## `sample_gpu.json.hex` (fabricated)

Synthetic and deliberately invalid: a truncated hex-encoded JSON stub with an
`"attestation": "fake"` field. It exists so `test_adapters.py` can assert the
adapter **refuses** input rather than accepting anything well-formed.

Do not use it as a positive fixture. It cannot verify and is not meant to.
