# DF-017 login and file activity investigation

**All records, accounts, hosts, addresses and file paths are invented. The referenced files themselves are not supplied.**

## Case brief

A training evidence portal recorded repeated login failures and file-access
events on 20 October 2026. Determine which successful sessions meet the stated
rule and what subsequent downloads are recorded. Prioritise a session for
review without assuming an intrusion or attributing activity to a person.

The exports are deliberately unsorted and contain duplicate and malformed
records. Their timestamps use Z and +01:00 offsets. Assume both sources use
the same session-ID namespace. Clock accuracy, log completeness and the
real-world identity behind an account have not been independently established.

## Run from this folder

Python 3.10 or newer, standard library only. No notebook, pip install or API key.

| Purpose | macOS or Linux | Windows PowerShell |
| --- | --- | --- |
| Run starter or full analysis | `python3 analyze_case.py` | `py analyze_case.py` |
| Run login stage only | `python3 analyze_case.py --stage logins` | `py analyze_case.py --stage logins` |
| Check function 1 | `python3 check_solution.py LoginChecks` | `py check_solution.py LoginChecks` |
| Check function 2 | `python3 check_solution.py DownloadChecks` | `py check_solution.py DownloadChecks` |
| Run all checks | `python3 check_solution.py` | `py check_solution.py` |

If Windows does not recognise `py`, use `python` after checking that
`python --version` reports Python 3.10 or newer. Otherwise install Python 3.

Implement only `find_login_sequences` and `correlate_downloads` in
`analyze_case.py`. Their docstrings are the exact contracts. The supplied
loader, evidence, manifest and tests remain unchanged.

## Rules and field meanings

1. For every SUCCESS at T, group on `(username, source_ip, host)` and count
   FAIL events where **T - 5 minutes <= time < T**. Flag at least three.
   Each success is evaluated independently; earlier successes do not reset
   the window. A failure may support more than one alert.
2. Join file events using **username AND host AND session_id**. Keep only
   `action == "DOWNLOAD"`, `result == "SUCCESS"`, and **T <= time <= T + 10 minutes**.
   Count events, even if their paths repeat. Sum their integer bytes values.
   Retain alerts with zero matches. Sort by descending byte total, then time
   and success event ID. This ranking measures recorded volume, not guilt.
3. `event_id` identifies one event within its source. `session_id` links the
   two sources. `bytes` is the transfer size recorded by the application;
   independent transfer completion and destination evidence are not supplied.

## Evidence handling supplied for you

`evidence_tools.py` verifies the original CSV byte hashes against
`evidence_manifest.json`, trims outer whitespace, validates rows, requires
explicit timezone offsets, converts times to UTC and byte strings to integers,
and removes identical repeated event IDs. It records duplicate and rejected
CSV row numbers in `audit.json`. Conflicting versions of an ID stop analysis.
Rejected rows remain in the source; they are excluded from computed findings.

The starter writes `audit.json` before stopping at the first TODO. Function 1
adds `login_alerts.json`; the completed program adds `summary.json`. Rerun after
every change: old output files can be stale. A hash match demonstrates agreement
with this supplied baseline; it does not establish authenticity or completeness.
`.gitattributes` preserves CSV bytes through Git on all operating systems.

## Verified results -- complete this section

| Source | Data rows excluding header | Accepted unique | Duplicate | Rejected |
| --- | --- | --- | --- | --- |
| auth_log.csv | 60 | 54 | 1 (row 21) | 5 (rows 26, 32, 36, 47, 50) |
| file_log.csv | 35 | 30 | 1 row(20) | 4 (rows 5, 11, 30, 36) |

- SHA-256 check outcome and what it establishes: 
"sha256": {
    "auth_log.csv": "9011778a7687a41e54da4ba96bd6597bf74252c9715572e2daac2615bebfc3d7",
    "file_log.csv": "394afab97ca10d01347051f4862bf6b04f5937df41cd3d334c85898faa4feb73"
  }
it establishes the integrity of the data
- One rejected event ID and the exact rejection reason: 
A900 from auth_log.csv rejected : Invalid isoformat string: 'not-a-time'
- Number of flagged successful sessions: 
3 successful sessions 

| Success ID | Account | Session | Supporting failure IDs | Download IDs | Event count | Total bytes |
| --- | --- | --- | --- | --- | --- | --- |
| A005 | analyst01 | S-104 | A002, A003, A004 | F001, F002, F003 | 3 | 5509120 |
| A018 | analyst02 | S-304 | A015, A016, A017 | F013 | 1 | 2048 |
| A014 | backup_svc | S-204 | A011, A012, A013 | none | 0 | 0 |


## Manual evidence check -- do this without asking AI to count for you

For the highest-volume flagged session, find every supporting failure, the
success and every qualifying download in the original CSV files. Record their
original timestamps and UTC equivalents. Add rows as needed.

| Source and event ID | Original timestamp | UTC timestamp | What the row records |
| --- | --- | --- | --- |
| auth_log.csv A002 (row 41) | 2026-10-20T08:58:00Z | 2026-10-20T08:58:00Z | FAIL |
| auth_log.csv A003 (row 12) | 2026-10-20T09:00:00Z | 2026-10-20T09:00:00Z | FAIL |
| auth_log.csv A004 (row 10) | 2026-10-20T10:01:00+01:00 | 2026-10-20T09:01:00Z | FAIL |
| auth_log.csv A005 (row 61) | 2026-10-20T09:03:00Z | 2026-10-20T09:03:00Z | SUCCESS |
| file_log.csv F001 (row 3) | 2026-10-20T09:05:00Z | 2026-10-20T09:05:00Z | DOWNLOAD SUCCESS | 
| file_log.csv F002 (row 24) | 2026-10-20T10:07:00+01:00 | 2026-10-20T09:07:00Z | DOWNLOAD SUCCESS |
| file_log.csv F003 (row 17) | 2026-10-20T09:13:00Z | 2026-10-20T09:13:00Z | DOWNLOAD SUCCESS |


- Manual sum of download bytes, showing the addition: 5242880 + 262144 + 4096 = 5509120
- A001 versus A002: which qualifies for the A005 window and why? : 
2026-10-20T09:03:00Z for AA05 which means between : 08:58:00 and 09:03:00
Or A001 is : 08:57:59 and A002 : 08:58:00 so A002 will be qualified
- F003 versus F004: which qualifies for the A005 follow-up and why?
2026-10-20T09:03:00Z for AA05 which means between : 09:03:00 and 09:13:00
F003 : 2026-10-20T09:13:00Z
F004 : 2026-10-20T09:13:01Z
F003 will be qualified not F004
- Why F005 is excluded even though the account matches: 
Because session_id of F005 = S_OTHER while session_id of A005 = S-104
- One +01:00 timestamp and its equivalent UTC time: 
2026-10-20T10:07:00+01:00 equivalent : 2026-10-20T09:07:00Z
- One limitation of excluding malformed records: 
F900,2026-10-20T09:06:00,analyst01,DF-PORTAL01,S-104,DOWNLOAD,/training/case-017/evidence_export.zip,5242880,SUCCESS
This line for instance it misses the Z though everything else is matching

## Checks actually run

Command, date and actual final result (paste output, including failures if any):

```text
└─$ python3 check_solution.py
test_supplied_case (__main__.CaseChecks.test_supplied_case) ... ok
test_closed_window_includes_zero_and_ten_minutes (__main__.DownloadChecks.test_closed_window_includes_zero_and_ten_minutes) ... ok
test_configurable_followup (__main__.DownloadChecks.test_configurable_followup) ... ok
test_does_not_mutate_either_input (__main__.DownloadChecks.test_does_not_mutate_either_input) ... ok
test_empty (__main__.DownloadChecks.test_empty) ... ok
test_keeps_alert_with_no_downloads (__main__.DownloadChecks.test_keeps_alert_with_no_downloads) ... ok
test_ranking_event_ties_and_repeated_paths (__main__.DownloadChecks.test_ranking_event_ties_and_repeated_paths) ... ok
test_requires_session_account_host_action_and_success (__main__.DownloadChecks.test_requires_session_account_host_action_and_success) ... ok
test_conflicting_ids_are_not_silently_discarded (__main__.EvidenceChecks.test_conflicting_ids_are_not_silently_discarded) ... ok
test_equivalent_time_offsets_and_missing_offset (__main__.EvidenceChecks.test_equivalent_time_offsets_and_missing_offset) ... ok
test_hash_mismatch_stops_analysis (__main__.EvidenceChecks.test_hash_mismatch_stops_analysis) ... ok
test_supplied_quality_counts_and_duplicates (__main__.EvidenceChecks.test_supplied_quality_counts_and_duplicates) ... ok
test_account_ip_and_host_must_all_match (__main__.LoginChecks.test_account_ip_and_host_must_all_match) ... ok
test_does_not_mutate_input (__main__.LoginChecks.test_does_not_mutate_input) ... ok
test_empty (__main__.LoginChecks.test_empty) ... ok
test_failures_without_success_are_not_alerts (__main__.LoginChecks.test_failures_without_success_are_not_alerts) ... ok
test_outside_equal_and_future_failures_do_not_count (__main__.LoginChecks.test_outside_equal_and_future_failures_do_not_count) ... ok
test_parameters_and_each_success_window (__main__.LoginChecks.test_parameters_and_each_success_window) ... ok
test_ties_and_output_order (__main__.LoginChecks.test_ties_and_output_order) ... ok
test_unsorted_rows_and_evidence_order (__main__.LoginChecks.test_unsorted_rows_and_evidence_order) ... ok
test_window_includes_exactly_five_minutes (__main__.LoginChecks.test_window_includes_exactly_five_minutes) ... ok

----------------------------------------------------------------------
Ran 21 tests in 0.002s

OK
```

All 21 supplied checks should pass. Passing these checks is limited validation
of the stated classroom rule, not certification of a forensic tool.

## AI interpretation and our final finding

Prompt 3 response about the overstated claim (keep the actual response):

Unsupported parts (96 words):

“Largest download total” is true only for analyst01 among flagged sessions (5,509,120 bytes vs 2,048 and 0). Nothing shows the rule covers all activity.
“Belongs to the attacker” asserts identity and intent. The summary says matches don’t prove intrusion or identity.
“Stole evidence” asserts theft. Rows record downloads, not file contents, purpose, or destination.
“Prove” is too strong. The rule only flags sessions for review.
Matching SHA-256 values show the files are unchanged from the hashed copies. They don’t show the logs are authentic or complete. Rejected rows (9) and duplicates (2) exist too.

Cautious rewrite:

Session S-104 (analyst01, from 203.0.113.44) has the largest download total among the three flagged sessions, 3 downloads totaling 5,509,120 bytes after three failures and a success, so it merits priority review. The logs alone do not establish who was behind the activity, their intent, what the files contained, or that the logs are complete, since matching hashes show only that the analyzed files are unchanged, and some rows were rejected or duplicated.

One claim we corrected or independently verified, with event IDs: We checked the A005 download window by hand. F003 (09:13:00Z) is included and F004 (09:13:01Z) is excluded, which confirms the closed window T <= time <= T + 10 minutes. We also corrected our results table, where backup_svc had the wrong success ID (A018 instead of A014).

Final 180-220 word finding, reviewed and edited by the pair:

Finding: Session S-104 (DF-017, training data)

Observed: On 20 Oct 2026, account analyst01 from 203.0.113.44 on DF-PORTAL01 logged three failures (A002-A004) followed by a success (A005) at 09:03:00Z. Three successful DOWNLOAD events followed in session S-104 (F001, F002, F003), spanning 09:05:00Z-09:13:00Z and totalling 5,509,120 bytes. Under the stated rule, this session ranks first by recorded volume, so it merits priority review.

Comparison: S-304 (analyst02; failures A015-A017, success A018 at 10:05:00Z) shows one download, F013, of 2,048 bytes. S-204 (backup_svc) shows none.

Inference (tentative): The sequence is consistent with credential guessing followed by data collection. It is equally consistent with a legitimate user mistyping a password and then retrieving authorised case files. An account or IP does not identify a person.

Limitations: Nine rows were rejected, including F900, an analyst01/S-104 download with no timezone offset. It is excluded, so totals may be incomplete. Also, bytes are application-recorded; completion and destination are unsupported, and clock accuracy and log completeness are unverified.

Next requests: (1) Network or transfer logs showing completion and destination for F001-F003. (2) Help-desk or password-reset records and access authorisation for analyst01, plus DF-PORTAL01 clock-synchronisation records.


It must cite evidence IDs, separate observation from inference, include a
comparison session, two limitations, one benign explanation and two next
evidence requests. Do not claim that an account or IP identifies a person.

## AI use and pair review

- Names of both partners: Samuel Berthoule
- GenAI tool/ChatGPT date and displayed model: Claude Sonnet 5.5 Medium
- Prompts used and what they produced: Prompt 1 produced find_login_sequences; Prompt 2 produced correlate_download; Prompt 3 reviewed a claim and flagged identity, theft and hash claims as unsupported; Prompt 4 drafted the final finding.
- One follow-up question or correction, with a short response excerpt: 
- Results of code and evidence checks performed: python3 check_solution.py gave Ran 21 tests, OK. We manually checked the S-104 timeline against both original CSVs and the byte total (5509120) matches summary.json. Hashes match the manifest.


## Submit

Submit one public repository URL per pair through the course route. Include the ten
starter project files and the newly generated `audit.json`, `login_alerts.json`,
and `summary.json`. Complete this README. The repository needs a starting
commit and a finished commit. The accompanying student guide gives the
90-minute schedule; `GitHub_CLI_Guide.docx` covers setup and upload.
Only synthetic exercise files belong in this repository. Keep credentials out.

Optional stretch after the core task: use the interactive Python console to
compare `min_failures=2` with `min_failures=3`, without changing the defaults or
original evidence. Which extra session appears, and does that change what you
can conclude? Record this separately from the required default output.
