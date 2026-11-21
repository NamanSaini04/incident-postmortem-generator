"""Phase 3 tests: extraction must find every IOC (recall), produce no junk
(precision), and every result must trace back to its exact record."""
import pytest

from pmgen.extract import extract_bundle, normalise_timestamp, unique_values
from pmgen.ingest import ingest_folder, load_file
from pmgen.provenance import excerpt_matches
from pmgen.samples import DATA_DIR, list_incidents, load_ground_truth
from pmgen.schemas import EntityType, EvidenceBundle

INCIDENTS = list_incidents()


def _extract_text(tmp_path, text, name="notes.txt"):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    bundle = EvidenceBundle(incident_id="T", documents=[load_file(p)])
    return extract_bundle(bundle), unique_values(extract_bundle(bundle))


@pytest.fixture(scope="module", params=INCIDENTS)
def incident(request):
    inc = request.param
    return inc, extract_bundle(ingest_folder(DATA_DIR / inc))


# --- against ground truth ---------------------------------------------------

def test_recall_every_ground_truth_ioc_is_extracted(incident):
    inc, entities = incident
    found = unique_values(entities)
    for etype, values in load_ground_truth(inc).iocs.items():
        missing = set(values) - found.get(etype, set())
        assert not missing, f"{inc}: missed {etype.value} {missing}"


def test_every_entity_traces_to_its_record(incident):
    inc, entities = incident
    for e in entities:
        assert excerpt_matches(e.source, DATA_DIR / inc), f"{inc}: {e.value!r} not in {e.source}"


def test_no_junk_domains(incident):
    _, entities = incident
    domains = unique_values(entities).get(EntityType.DOMAIN, set())
    junk_suffixes = (".exe", ".dll", ".csv", ".ps1", ".docm", ".log", ".txt")
    assert not [d for d in domains if d.endswith(junk_suffixes)]
    users = unique_values(entities).get(EntityType.USER, set())
    assert not (domains & users), "a username was mistaken for a domain"


def test_ground_truth_timestamps_are_extracted(incident):
    """Every structured-source ground-truth time must appear as a normalised timestamp."""
    inc, entities = incident
    ts = unique_values(entities)[EntityType.TIMESTAMP]
    for ev in load_ground_truth(inc).timeline:
        if ev.source.file.endswith(".txt"):
            continue  # time-only / naive in notes; resolved in Phase 4
        assert ev.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ") in ts, f"{inc}: {ev.key}"


# --- specific behaviours ------------------------------------------------------

def test_known_user_linked_into_analyst_notes():
    entities = extract_bundle(ingest_folder(DATA_DIR / "INC-2026-001"))
    hits = [e for e in entities if e.method == "known_entity" and e.value == "j.patel"]
    locators = {e.source.locator for e in hits}
    assert {"line 4", "line 5", "line 8"} <= locators  # revoke, reset, MFA finding


def test_nested_json_field_extracted():
    entities = extract_bundle(ingest_folder(DATA_DIR / "INC-2026-003"))
    users = {e.value for e in entities if e.entity_type is EntityType.USER and e.method == "field"}
    assert users == {"d.reyes", "cloud.secops"}  # from userIdentity.userName


def test_url_stops_at_punctuation_and_commas(tmp_path):
    _, found = _extract_text(tmp_path, "see https://evil.test/a?x=1). also http://b.test/p,next")
    assert found[EntityType.URL] == {"https://evil.test/a?x=1", "http://b.test/p"}


def test_invalid_ip_and_version_strings_ignored(tmp_path):
    _, found = _extract_text(tmp_path, "999.1.1.1 Mozilla/5.0 aws-cli/2.15.1 ok 10.0.0.5")
    assert found[EntityType.IP] == {"10.0.0.5"}


def test_ip_scope_attribute(tmp_path):
    ents, _ = _extract_text(tmp_path, "10.0.0.5 and 203.0.113.9 and 8.8.8.8")
    scopes = {e.value: e.attributes["scope"] for e in ents if e.entity_type is EntityType.IP}
    assert scopes == {"10.0.0.5": "private", "203.0.113.9": "documentation", "8.8.8.8": "public"}


def test_filenames_and_usernames_not_domains(tmp_path):
    _, found = _extract_text(tmp_path, "j.patel ran powershell.exe then upd.dll; real: bad.example")
    assert found[EntityType.DOMAIN] == {"bad.example"}


def test_email_gives_domain_too(tmp_path):
    _, found = _extract_text(tmp_path, "from Phish@Evil-Domain.TEST today")
    assert found[EntityType.EMAIL] == {"phish@evil-domain.test"}
    assert "evil-domain.test" in found[EntityType.DOMAIN]


def test_hash_lengths_not_confused(tmp_path):
    sha256, md5 = "a" * 64, "b" * 32
    _, found = _extract_text(tmp_path, f"{sha256} {md5}")
    assert found[EntityType.SHA256] == {sha256}
    assert found[EntityType.MD5] == {md5}
    assert EntityType.SHA1 not in found


def test_time_only_flagged(tmp_path):
    ents, _ = _extract_text(tmp_path, "09:52 Picked up alert")
    ts = [e for e in ents if e.entity_type is EntityType.TIMESTAMP]
    assert ts[0].value == "09:52" and ts[0].attributes == {"precision": "time_only"}


def test_naive_timestamp_flagged_not_assumed_utc(tmp_path):
    ents, _ = _extract_text(tmp_path, "2026-09-18 10:30 Email from researcher")
    ts = [e for e in ents if e.entity_type is EntityType.TIMESTAMP]
    assert len(ts) == 1  # not also reported as time-only
    assert ts[0].value == "2026-09-18T10:30:00" and ts[0].attributes == {"timezone": "missing"}


@pytest.mark.parametrize("raw,expected", [
    ("2026-10-06T09:22:15Z", "2026-10-06T09:22:15Z"),
    ("2026-10-06T14:52:15+05:30", "2026-10-06T09:22:15Z"),  # converted to UTC
    ("2026-10-06 09:22:15+00:00", "2026-10-06T09:22:15Z"),
])
def test_timestamps_normalised_to_utc(raw, expected):
    assert normalise_timestamp(raw)[0] == expected


def test_unparseable_timestamp_skipped():
    assert normalise_timestamp("yesterday") is None


def test_empty_field_values_skipped(tmp_path):
    p = tmp_path / "s3.csv"
    p.write_text("requester,key,user\n-,-,\n", encoding="utf-8")
    ents = extract_bundle(EvidenceBundle(incident_id="T", documents=[load_file(p)]))
    assert ents == []
