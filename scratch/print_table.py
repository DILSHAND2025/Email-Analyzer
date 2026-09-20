import json

with open('scratch/stress_test_results.json', 'r', encoding='utf-8') as f:
    results = json.load(f)

header = f"| {'Filename':<42} | {'Category':<26} | {'Expected':<8} | {'Actual':<8} | {'Score':<8} | {'Status':<8} |"
sep = f"|{'-'*44}|{'-'*28}|{'-'*10}|{'-'*10}|{'-'*10}|{'-'*10}|"
print(header)
print(sep)

matches = 0
for r in results:
    m = r['actual'].lower() == r['expected'].lower()
    if m:
        matches += 1
    status = "MATCH" if m else "MISMATCH"
    print(f"| {r['filename']:<42} | {r['category']:<26} | {r['expected']:<8} | {r['actual']:<8} | {r['risk_score']:<8.4f} | {status:<8} |")

print(f"\nTotal Concordance: {matches}/{len(results)} ({matches/len(results)*100:.1f}%)")
