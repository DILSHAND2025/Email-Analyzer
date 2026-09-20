"""Analyze and format stress test evaluation results."""

import json

with open("scratch/stress_test_results.json", "r", encoding="utf-8") as f:
    results = json.load(f)

print(f"{'Filename':<44} | {'Category':<22} | {'Expected':<8} | {'Actual':<8} | {'Score':<6} | {'Status'}")
print("-" * 110)

matches = 0
for r in results:
    is_match = (r["actual"].lower() == r["expected"].lower())
    match_str = "MATCH" if is_match else "MISMATCH"
    if is_match:
        matches += 1
    print(f"{r['filename']:<44} | {r['category']:<22} | {r['expected']:<8} | {r['actual']:<8} | {r['risk_score']:<6.4f} | {match_str}")

print("-" * 110)
print(f"Total: {matches} / {len(results)} matches ({matches/len(results)*100:.1f}%)")

print("\n=== DETAILED ANALYSIS OF EACH EMAIL ===")
for r in results:
    print(f"\n[{r['filename']}] (Expected: {r['expected']}, Actual: {r['actual']}, Score: {r['risk_score']:.4f})")
    print(f"  Breakdown: ML={r['breakdown']['ml']:.4f} (40%), Auth={r['breakdown']['auth']:.4f} (20%), Att={r['breakdown']['att']:.4f} (20%), IOC={r['breakdown']['ioc']:.4f} (20%)")
    print(f"  Threat count: {r['threat_count']}")
    print("  Contributing factors:")
    for f in r["factors"]:
        print(f"    - {f}")
