# Project summary (for CV, LinkedIn and interviews)

## One line

Built an LLM application that turns raw security evidence into evidence-cited incident postmortems,
with code-based validation, an independent verifier, a reviewer agent and a pre-registered evaluation;
live Streamlit demo and PDF export.

## CV bullets (pick 2-3)

- Built an incident-postmortem generator (Python, Pydantic, Anthropic API) where deterministic code
  extracts all facts and the LLM may only cite numbered evidence records; 1401/1401 citations confirmed
  by an independent verifier and 120/120 hand-checked hallucination traps avoided on 6 synthetic incidents.
- Designed a 10-measure evaluation suite with answer keys and predictions written before each run and
  3 held-out incidents: category and severity correct in 18/18 reports across 3 runs, MITRE ATT&CK
  recall 94% with 0 forbidden techniques.
- Added a reviewer agent that checks whether each cited record supports its claim; it caught 28/29
  planted errors and exposed overstated certainty in ~1 in 11 claims, which a prompt fix cut from 7 to 1
  on the re-tested incidents.
- Shipped a public Streamlit dashboard (demo mode, no API spend), PDF export with a timeline chart,
  BM25 policy retrieval (A/B tested), and 352 tests running in GitHub Actions.

## 60-second interview version

1. Problem: an LLM can draft a postmortem, but in security a fluent wrong answer is dangerous
   (invented IPs, overstated certainty, wrong times).
2. Design: code extracts facts; the model only cites numbered records; three checking layers
   (validator, verifier, reviewer agent), each measured by what it can and cannot catch.
3. Evidence: pre-registered predictions, held-out incidents, failures kept in the record.
4. Best finding: the code checks proved every quote was real, but a reviewer agent showed real quotes
   supporting overconfident claims; one measured prompt fix reduced it.
5. Limits I state up front: synthetic data I wrote myself, same model family, mostly one run per incident.

## Questions to be ready for

- Why BM25 and not embeddings? (53 sections; recall measured at 84.7%; embeddings only if recall drops)
- Why one agent, not eight? (only one gap needed an LLM; the other stages are tested code)
- How do you know the reviewer is right? (planted errors, plus hand judgement of every flag: 6 of 132
  looked like false alarms)
- What would you do with real data? (independent incidents, repeated runs, a reviewer from a different
  model family)
