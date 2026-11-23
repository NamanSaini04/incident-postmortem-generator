"""Phase 4 tests: timeline building, evaluation scoring and messy variants."""
import json
from datetime import timedelta

import pytest

from pmgen.evaluate import run_all, score_folder, score_timeline
from pmgen.ingest import ingest_folder
from pmgen.provenance import excerpt_matches
from pmgen.samples import DATA_DIR, list_incidents, load_ground_truth
from pmgen.schemas import TimeBasis
from pmgen.timeline import build_timeline
from pmgen.variants import VARIANTS, make_variant

INCIDENTS = list_incidents()


def _tl(inc):
    return build_timeline(ingest_folder(DATA_DIR / inc))


def _tl_from(tmp_path, files: dict[str, str]):
    for name, text in files.items():
        (tmp_path / name).write_text(text, encoding="utf-8")
    return build_timeline(ingest_folder(tmp_path, incident_id="T"))


# --- timeline on bundled incidents -------------------------------------------

@pytest.mark.parametrize("inc", INCIDENTS)
def test_events_sorted_and_cited(inc):
    tl = _tl(inc)
    times = [e.timestamp for e in tl.events]
    assert times == sorted(times)
    for e in tl.events:
        for s in e.sources:
            assert excerpt_matches(s, DATA_DIR / inc)


def test_same_event_in_two_logs_is_merged():
    tl = _tl("INC-2026-002")
    ev = next(e for e in tl.events if any(s.locator == "events[2]" for s in e.sources))
    assert {(s.file, s.locator) for s in ev.sources} == {("edr_events.json", "events[2]"), ("proxy_logs.csv", "row 1")}


def test_time_only_notes_get_date_and_flag():
    tl = _tl("INC-2026-001")
    ev = next(e for e in tl.events if e.sources[0].locator == "line 3")
    assert ev.timestamp.isoformat() == "2026-10-06T09:52:00+00:00"
    assert ev.time_basis is TimeBasis.DATE_INFERRED
    assert ev.confidence == 0.8 and "only date" in ev.rationale


def test_naive_timestamp_marked_timezone_assumed():
    tl = _tl("INC-2026-003")
    ev = next(e for e in tl.events if e.sources[0].locator == "line 3")
    assert ev.time_basis is TimeBasis.TIMEZONE_ASSUMED and "assumed UTC" in ev.rationale


# --- edge cases ----------------------------------------------------------------

def test_different_users_same_second_not_merged(tmp_path):
    tl = _tl_from(tmp_path, {"auth.csv": "timestamp,user,src_ip\n"
                             "2026-01-01T10:00:00Z,alice,203.0.113.9\n"
                             "2026-01-01T10:00:01Z,bob,203.0.113.9\n"})
    assert len(tl.events) == 2


def test_user_in_one_log_host_in_other_still_merges(tmp_path):
    tl = _tl_from(tmp_path, {"a.csv": "timestamp,user,src_ip\n2026-01-01T10:00:00Z,alice,203.0.113.9\n",
                             "b.csv": "timestamp,src_host,dest_ip\n2026-01-01T10:00:01Z,WS-1,203.0.113.9\n"})
    assert len(tl.events) == 1 and len(tl.events[0].sources) == 2


def test_events_outside_window_not_merged(tmp_path):
    tl = _tl_from(tmp_path, {"a.csv": "timestamp,src_ip\n2026-01-01T10:00:00Z,203.0.113.9\n"
                                      "2026-01-01T10:00:05Z,203.0.113.9\n"})
    assert len(tl.events) == 2


def test_multi_day_time_only_note_is_low_confidence(tmp_path):
    tl = _tl_from(tmp_path, {"a.csv": "timestamp,src_ip\n2026-01-01T10:00:00Z,203.0.113.9\n"
                                      "2026-01-03T10:00:00Z,203.0.113.9\n",
                             "notes.txt": "09:15 Host isolated\n"})
    ev = next(e for e in tl.events if e.time_basis is TimeBasis.DATE_INFERRED)
    assert ev.confidence == 0.4 and str(ev.timestamp.date()) == "2026-01-03"
    assert any("date guessed" in w for w in tl.warnings)


def test_time_only_without_any_dates_goes_to_undated(tmp_path):
    tl = _tl_from(tmp_path, {"notes.txt": "09:15 Host isolated\n"})
    assert tl.events == [] and len(tl.undated) == 1


# --- evaluation ----------------------------------------------------------------

def test_all_cases_score_perfectly():
    """Regression guard: if a change breaks the timeline, this fails with the case name."""
    for s in run_all():
        assert (s.key_event_recall, s.timestamp_accuracy, s.order_accuracy) == (1.0, 1.0, 1.0), s


def test_scorer_detects_missing_wrong_time_and_bad_order():
    gt = load_ground_truth("INC-2026-001")
    bad = _tl("INC-2026-001").model_copy(deep=True)
    bad.events[6].timestamp += timedelta(hours=2)
    bad.events = [e for e in bad.events if not any(s.locator == "alerts[1]" for s in e.sources)]
    bad.events[1], bad.events[3] = bad.events[3], bad.events[1]
    s = score_timeline(gt, bad)
    assert s.missed == ["forwarding_rule_created"]
    assert s.wrong_time == ["attacker_login"]
    assert s.order_accuracy < 1.0


# --- variants ------------------------------------------------------------------

@pytest.mark.parametrize("inc", INCIDENTS)
@pytest.mark.parametrize("name", VARIANTS)
def test_variant_ground_truth_still_points_at_right_records(tmp_path, inc, name):
    folder, gt = make_variant(inc, name, tmp_path)
    for ev in gt.timeline:
        assert excerpt_matches(ev.source, folder), (name, ev.key)


def test_shuffle_actually_moves_rows(tmp_path):
    folder, gt = make_variant("INC-2026-001", "shuffled", tmp_path)
    assert (folder / "auth_logs.csv").read_text() != (DATA_DIR / "INC-2026-001" / "auth_logs.csv").read_text()
    assert gt.model_dump() != load_ground_truth("INC-2026-001").model_dump()


def test_offset_variant_same_utc_times(tmp_path):
    folder, gt = make_variant("INC-2026-001", "offset_tz", tmp_path)
    assert "+05:30" in (folder / "auth_logs.csv").read_text()
    assert score_folder(folder, gt, "x").timestamp_accuracy == 1.0


def test_duplicate_alert_is_merged(tmp_path):
    folder, _ = make_variant("INC-2026-001", "dup_alert", tmp_path)
    assert len(json.loads((folder / "siem_alerts.json").read_text())["alerts"]) == 3
    assert len(build_timeline(ingest_folder(folder)).events) == len(_tl("INC-2026-001").events)


# --- Phase 5b: date headings in notes, midnight rollover, merged-event timing ----------

def test_date_heading_anchors_time_only_notes():
    """INC-004 evidence spans two days; '23:52' must stay on the heading's date, not the latest date."""
    tl = _tl("INC-2026-004")
    ev = next(e for e in tl.events if e.sources[0].locator == "line 3" and e.sources[0].file == "ir_notes.txt")
    assert ev.timestamp.isoformat() == "2026-11-10T23:52:00+00:00"
    assert ev.confidence == 0.8 and "line 2" in ev.rationale


def test_clock_going_backwards_rolls_to_next_day(tmp_path):
    tl = _tl_from(tmp_path, {"a.csv": "timestamp,src_ip\n2026-01-01T23:00:00Z,203.0.113.9\n",
                             "notes.txt": "Log date 2026-01-01\n23:50 Host isolated\n00:10 Password reset\n"})
    times = [e.timestamp.isoformat() for e in tl.events if e.time_basis is TimeBasis.DATE_INFERRED]
    assert times == ["2026-01-01T23:50:00+00:00", "2026-01-02T00:10:00+00:00"]


def test_merged_event_time_accepts_any_source_within_window():
    s = score_folder(DATA_DIR / "INC-2026-004", load_ground_truth("INC-2026-004"), "x")
    assert s.wrong_time == []
