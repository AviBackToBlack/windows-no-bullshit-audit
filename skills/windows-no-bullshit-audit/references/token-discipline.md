# Token and Context Discipline

The operator pays for this audit in context window and usage quota. A deep audit
that exhausts the quota halfway through is a failed audit, no matter how good
the first half was.

**The rule that governs every other rule here:** never trade a correct
conclusion for tokens. Always trade thoroughness theater for tokens.

## The one principle

Deterministic work belongs in PowerShell. Judgement belongs in the model.

Counting events, grouping by provider, filtering to non-Microsoft signers,
comparing counters to thresholds and formatting tables are deterministic. Doing
them by reading raw rows costs hundreds of thousands of tokens and is *less*
reliable than a script. If you catch yourself reading data in order to compute
something, write the computation instead.

## Evidence access protocol

This is not advice. Treat it as a hard constraint.

1. **Read `TRIAGE.md` and, when you need exact values, `TRIAGE.json`.** These
   are the intended inputs. They are capped and complete enough to triage from.
2. **Never read another evidence file in full.** Not once, not "just to check".
3. **Raw evidence is queried, never loaded.** Always project columns and always
   bound the row count:

   ```powershell
   # good
   Import-Csv "$run\05-Events\event-signatures.csv" |
     Where-Object { $_.ProviderName -eq 'storahci' } |
     Select-Object -First 10 ProviderName,EventId,Count,FirstSeen,LastSeen

   # good
   Select-String -Path "$run\01-Integrity\CBS.log" -Pattern 'Cannot repair' -Context 0,2 |
     Select-Object -First 20

   # good
   Get-WinEvent -FilterHashtable @{LogName='System';ProviderName='storahci';Id=129} -MaxEvents 20 |
     Select-Object TimeCreated,Id,Message
   ```

4. **Never run these:** `Get-Content` on `*.csv`, `*.log`, `*.nfo`, `*.etl`,
   `*.evtx`, `dxdiag.txt`, `energy.html`, `autoruns.xml`, or any `cat`/`type`
   equivalent. `Get-WinEvent` without both a filter and `-MaxEvents`.
   `Format-List *` on a collection.
5. **Cap every probe's visible output** to roughly 50 lines or 4 KB. If a probe
   might exceed that, write it to the run directory and print only the reduction.
6. **Never echo raw command output into the conversation.** Report the reduced
   result and the file path.
7. **One probe, one question.** If a probe cannot change a finding's
   classification, do not run it.
8. **Batch independent probes** into a single invocation that writes files and
   prints a short digest, rather than one command per turn.

## Delegated mode (no local execution)

This is the common case on hosted chat surfaces, and the easiest place to waste
an entire quota.

- Ask for **`TRIAGE.md` only**. It is roughly 10-15 KB.
- Do **not** ask for the ZIP. It contains 20 MB event logs and multi-MB CSVs.
  Request specific files only when a specific question requires them, and then
  ask for the *output of a query*, not the file.
- When you need more, send the operator one copy-pasteable PowerShell block that
  prints a small answer. Not a file to upload.
- Give the operator every command they need for the next step in a single
  message. Round trips are the most expensive thing in delegated mode.

## Prompt cache hygiene

- Load the always-applicable references once, early, in a fixed order. Do not
  re-read them.
- Load a domain reference only when a finding in that domain actually exists.
- Do not re-read `TRIAGE.json` after summarizing it into audit state.
- Once a finding is classified, store the classification plus an *evidence
  pointer* (file and filter), never the evidence itself. Do not reopen it.
- Never regenerate `REPORT.md` inside the model. Write one small
  `findings/<id>.json` per finding and run `scripts/assemble-report.ps1` once at
  the end. Rewriting a growing report every turn costs the whole report in
  output tokens and again in input tokens on the next turn.

## Bounded investigation

The audit stage is deterministic and cheap. Investigation is not, so it needs a
budget.

- Work a **severity-ordered** queue. Investigate the top items, and defer the
  tail explicitly and visibly rather than grinding through everything.
- Default budget per finding: **at most 3 local probes and 2 web searches.**
  Exceeding it requires telling the operator why and getting agreement.
- Prefer one discriminating test over three confirming ones.
- Cache research verdicts in `research-cache.json` keyed by component and
  version. Never research the same driver twice.
- Verify with the narrowest scope that could falsify the repair. Use
  `verify-after-repair.ps1 -Only <scope>`. The slow Integrity and Storage scopes
  are for repairs that actually touched the component store or the filesystem.

## Delegation to a subagent

Where the runtime supports subagents or background tasks, use one for bulk
evidence work: grepping large logs, scanning the driver store, cross-referencing
inventories. The raw output stays in the subagent's context and only the
conclusion reaches the main thread. This is the single largest context saving
available and it costs nothing in quality.

Where the runtime does not, achieve the same effect by writing a small reducer
script, running it, and reading only its output.

## What good looks like

A fast baseline plus triage should cost roughly 10-15k tokens of input. A full
audit of a machine with a handful of real findings should land in the tens of
thousands, not the hundreds of thousands. If you are approaching a compaction,
something in this document is being ignored.

## What is never sacrificed for tokens

- Target attestation.
- The pre-flight safety gate.
- Independent post-repair verification.
- Recording `UNKNOWN` instead of guessing.
- Telling the operator about a finding you chose to defer.

Cutting any of these to save tokens is not optimization, it is a wrong answer
delivered cheaply.
