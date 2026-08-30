# Security Analysis

## Model

Security findings must consider four things:

1. observed state;
2. current Microsoft/vendor recommendation;
3. compatibility evidence;
4. operator intent.

A setting that differs from Microsoft's default/recommendation may be intentional and necessary.

## Do not auto-enforce

Never silently enable/disable:

- BitLocker/device encryption;
- Secure Boot;
- TPM provisioning/clearing;
- VBS/Device Guard/HVCI/Memory Integrity;
- Smart App Control;
- LSA protection;
- Defender real-time/cloud/tamper protection;
- firewall policy/profiles;
- credential/security policy.

## Intentional deviations

If the operator deliberately disabled a feature for a known compatibility requirement:

- verify that the feature is actually in the stated state;
- research the current compatibility/security tradeoff;
- classify as 🟡 `INTENTIONAL` unless there is separate evidence of active risk;
- document the reason;
- optionally suggest safer alternatives or newer compatible software/hardware without forcing the change.

## Code Integrity

Do not treat every Code Integrity error as Windows corruption.

Determine whether the event is:

- a kernel-mode driver load/signature failure;
- a protected-process signing-level block;
- an application DLL/module issue;
- a historical component that is no longer present;
- policy behavior working as designed.

Cross-check current file presence, signature, product owner, process context, and recurrence.

## Defender findings

Distinguish:

- current threat detections;
- stale detection history;
- explicit exclusions;
- platform/signature freshness;
- protection feature state.

Do not expose secrets or sensitive file content in reports unnecessarily.
