import json
from collections import Counter

r = json.load(open("reports/scan-result.json"))
print("=== CONTEXT ===")
print("Repo:", r["context"]["repo_name"])
print("Commit:", r["context"]["commit_hash"])
print()

print("=== ELEMENTS (repo files) ===")
for e in r["elements"]:
    etype = e["element_type"]
    eco = e.get("ecosystem") or "—"
    print(f"  {etype:15} {eco:10} {e['path']}")
print()

print("=== COMPONENTS ===")
print(f"Total: {len(r['components'])}")
eco = Counter(c["ecosystem"] for c in r["components"])
print("By ecosystem:", dict(eco))
direct = sum(1 for c in r["components"] if c.get("is_direct") is True)
trans = sum(1 for c in r["components"] if c.get("is_direct") is False)
unknown = sum(1 for c in r["components"] if c.get("is_direct") is None)
print(f"Direct: {direct}, Transitive: {trans}, Unknown: {unknown}")
print()

print("=== GRAPH ===")
gm = r["agent_results"]["graph"]["metadata"]
print(f"Nodes: {gm['total_nodes']}, Edges: {gm['total_edges']}")
print(f"Direct deps: {gm['direct_dependencies']}")
print()

print("=== SAMPLE PATHS ===")
for pkg, paths in gm.get("sample_paths", {}).items():
    print(f"{pkg}:")
    for p in paths:
        print(f"  {p}")

