# Security Analysis

Load only when a security finding exists. Code Integrity triage is doctrine item
6 in `diagnostic-doctrine.md` and is not repeated here.

## The model

A security finding is not "differs from Microsoft default". It is the
combination of:

1. observed effective state;
2. current Microsoft/vendor recommendation;
3. compatibility evidence;
4. operator intent.

A setting that deviates from the default may be intentional and necessary.

## Never auto-enforce

Do not silently enable or disable:

- BitLocker / device encryption;
- Secure Boot;
- TPM provisioning or clearing;
- VBS / Device Guard / HVCI / Memory Integrity;
- Smart App Control;
- LSA protection;
- Defender real-time, cloud or tamper protection;
- firewall policy or profiles;
- credential or security policy.

Report the state and the tradeoff. The operator decides.

## Intentional deviations

When a feature was deliberately disabled for a known compatibility requirement:

- verify the feature really is in the stated state, not assumed to be;
- research the current compatibility and security tradeoff;
- classify as `INTENTIONAL` unless there is separate evidence of active risk;
- document the reason in the finding;
- optionally suggest safer alternatives or newer compatible hardware/software,
  without forcing the change.

## Defender

Distinguish clearly between:

- current threat detections;
- stale detection history;
- explicit exclusions (these are a finding in their own right - an exclusion the
  operator does not remember adding deserves a question);
- platform and signature freshness;
- protection feature state.

## Reporting

Do not put secrets, recovery keys, certificate private material or sensitive
file contents into reports. `TRIAGE.md` may be pasted into a hosted chat; assume
anything in a report is going somewhere you do not control. `-Redact` exists for
this.
