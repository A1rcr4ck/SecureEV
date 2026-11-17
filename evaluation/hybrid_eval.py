"""
SecureEV — Hybrid Dataset Evaluation

Runs the combined SecureEV + KAIST dataset through the Gateway
and shows the contrast that matters:

  SecureEV normal  -> should be ACCEPTED (valid HMAC)
  SecureEV attack  -> should be REJECTED (invalid/replayed)
  KAIST normal     -> will be REJECTED (no HMAC, predates auth)
  KAIST attack     -> will be REJECTED (no HMAC)

This demonstrates that authentication, not attack-pattern
matching, is what actually separates trusted EV traffic from
everything else, including unauthenticated real-world traffic
that was never malicious to begin with.
"""

import sys, os, csv
from collections import defaultdict, Counter
sys.path.insert(0, os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
))

from models.frames import CANFrame
from modules.kms import KMS
import modules.gateway_ecu as gw_module
from modules.gateway_ecu import GatewayECU

MASTER_KEY = b'secureev_master_key_32bytes!!!!!'
DATASET_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    '..', 'dataset', 'hybrid', 'secureev_hybrid_dataset.csv'
)


def load_dataset():
    with open(DATASET_PATH, 'r') as f:
        return list(csv.DictReader(f))


def run_evaluation(rows):
    # Extend the whitelist with KAIST normal CAN IDs and give
    # every ID a generous rate limit so bulk replay through the
    # Gateway isn't rejected purely on timing artifacts.
    kaist_ids = {
        int(r["can_id"], 16) for r in rows
        if r["origin"] == "kaist" and r["label"] == "normal"
    }

    orig_whitelist = gw_module.WHITELIST.copy()
    extended = {cid: 1_000_000 for cid in orig_whitelist}
    extended.update({cid: 1_000_000 for cid in kaist_ids})
    gw_module.WHITELIST.clear()
    gw_module.WHITELIST.update(extended)

    kms = KMS(MASTER_KEY)
    gw  = GatewayECU(kms)

    coarse  = defaultdict(lambda: {"total": 0, "accepted": 0, "rejected": 0})
    fine    = defaultdict(lambda: {"total": 0, "accepted": 0, "rejected": 0})
    reasons = defaultdict(Counter)

    for r in rows:
        frame = CANFrame(
            can_id=int(r["can_id"], 16),
            counter=int(r["counter"]),
            payload=bytes.fromhex(r["payload_hex"]),
            mac=bytes.fromhex(r["mac_hex"]),
            timestamp=0.0
        )
        accepted = gw.receive(frame)

        ckey = (r["origin"], r["label"])
        fkey = (r["origin"], r["label"], r["dataset"])
        coarse[ckey]["total"] += 1
        fine[fkey]["total"]   += 1

        if accepted:
            coarse[ckey]["accepted"] += 1
            fine[fkey]["accepted"]   += 1
        else:
            coarse[ckey]["rejected"] += 1
            fine[fkey]["rejected"]   += 1
            reason = gw.stats()["rejection_reasons"][-1]["reason"]
            reasons[ckey][reason] += 1

    gw_module.WHITELIST.clear()
    gw_module.WHITELIST.update(orig_whitelist)

    return coarse, fine, reasons


def print_coarse(coarse):
    print(f"\n{'='*72}")
    print("  HYBRID DATASET — COARSE RESULTS (by origin and label)")
    print(f"{'='*72}")
    print(f"  {'Origin':<10} {'Label':<8} {'Total':>8} "
          f"{'Accepted':>9} {'Rejected':>9} {'Accept%':>8}")
    print(f"  {'-'*66}")
    for (origin, label), v in sorted(coarse.items()):
        pct = v["accepted"] / v["total"] * 100 if v["total"] else 0
        print(f"  {origin:<10} {label:<8} {v['total']:>8,} "
              f"{v['accepted']:>9,} {v['rejected']:>9,} {pct:>7.1f}%")


def print_fine(fine):
    print(f"\n{'='*72}")
    print("  HYBRID DATASET — DETAILED RESULTS (by dataset subset)")
    print(f"{'='*72}")
    print(f"  {'Origin':<10} {'Label':<8} {'Dataset':<16} "
          f"{'Total':>7} {'Acc':>6} {'Rej':>6} {'Acc%':>7}")
    print(f"  {'-'*66}")
    for (origin, label, dataset), v in sorted(fine.items()):
        pct = v["accepted"] / v["total"] * 100 if v["total"] else 0
        print(f"  {origin:<10} {label:<8} {dataset:<16} "
              f"{v['total']:>7,} {v['accepted']:>6,} "
              f"{v['rejected']:>6,} {pct:>6.1f}%")


def print_reasons(reasons):
    print(f"\n{'='*72}")
    print("  REJECTION REASON BREAKDOWN")
    print(f"{'='*72}")
    for key, counter in sorted(reasons.items()):
        origin, label = key
        print(f"  {origin} / {label}:")
        for reason, count in counter.most_common():
            print(f"    {reason:<28}: {count:,}")


def print_conclusion(coarse):
    print(f"\n{'='*72}")
    print("  KEY FINDING")
    print(f"{'='*72}")
    se_normal = coarse.get(("secureev", "normal"), {"total":0,"accepted":0})
    se_attack = coarse.get(("secureev", "attack"), {"total":0,"accepted":0})
    ka_normal = coarse.get(("kaist", "normal"), {"total":0,"rejected":0})
    ka_attack = coarse.get(("kaist", "attack"), {"total":0,"rejected":0})

    print(f"  SecureEV authenticated normal traffic: "
          f"{se_normal['accepted']}/{se_normal['total']} accepted")
    print(f"  SecureEV attacker traffic:              "
          f"{se_attack.get('rejected',0)}/{se_attack['total']} rejected")
    print(f"  KAIST real-vehicle normal traffic:      "
          f"{ka_normal.get('rejected',0)}/{ka_normal['total']} rejected (no HMAC)")
    print(f"  KAIST real-vehicle attack traffic:      "
          f"{ka_attack.get('rejected',0)}/{ka_attack['total']} rejected (no HMAC)")
    print()
    print("  Authentication, not attack-pattern matching, is what")
    print("  separates trusted SecureEV traffic from everything else,")
    print("  including unauthenticated normal traffic from a real")
    print("  production vehicle that was never malicious to begin with.")
    print(f"{'='*72}\n")


if __name__ == "__main__":
    print("SecureEV — Hybrid Dataset Evaluation\n")
    rows = load_dataset()
    print(f"Loaded {len(rows):,} rows from hybrid dataset")
    coarse, fine, reasons = run_evaluation(rows)
    print_coarse(coarse)
    print_fine(fine)
    print_reasons(reasons)
    print_conclusion(coarse)