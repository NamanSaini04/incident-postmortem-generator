import json, sys
src, out = sys.argv[1], sys.argv[2]
b = json.load(open(src, encoding="utf-8"))
techs, version, notice = {}, None, None
for o in b["objects"]:
    if o.get("type") == "x-mitre-collection":
        version = o.get("x_mitre_version")
    if o.get("type") == "marking-definition" and o.get("definition", {}).get("statement"):
        notice = o["definition"]["statement"]
    if o.get("type") != "attack-pattern":
        continue
    ext = next((r for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
    if not ext:
        continue
    tid = ext["external_id"]
    tactics = sorted({p["phase_name"] for p in o.get("kill_chain_phases", []) if p.get("kill_chain_name") == "mitre-attack"})
    techs[tid] = {"name": o["name"], "tactics": tactics,
                  "revoked": bool(o.get("revoked")), "deprecated": bool(o.get("x_mitre_deprecated"))}
json.dump({"source": "MITRE ATT&CK Enterprise (mitre/cti enterprise-attack.json)", "version": version,
           "notice": notice, "techniques": dict(sorted(techs.items()))}, open(out, "w"), indent=0, sort_keys=False)
active = [t for t, v in techs.items() if not v["revoked"] and not v["deprecated"]]
print("version", version, "| techniques", len(techs), "| active", len(active))
print("notice:", (notice or "")[:200])
