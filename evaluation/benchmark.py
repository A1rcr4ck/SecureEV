import sys
import os
sys.path.insert(0, os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
))

import time
import statistics
from bus.virtual_bus import VirtualBus
from modules.kms import KMS
from modules.bms_ecu import BMSECU
from modules.gateway_ecu import GatewayECU
from crypto.mac import compute_mac, verify_mac


MASTER_KEY = b'secureev_master_key_32bytes!!!!!'
NUM_SAMPLES = 1000
TARGET_MS   = 0.5


def benchmark_mac_computation():
    """
    Measures time to compute HMAC-SHA256 MAC
    for a single CAN frame.
    Target: < 0.5ms per frame.
    """
    kms = KMS(MASTER_KEY)
    session_key = kms.get_session_key(0x100)

    import struct
    payload = struct.pack(">HBB", 40050, 75, 85)

    latencies = []
    for i in range(NUM_SAMPLES):
        start = time.perf_counter()
        compute_mac(session_key, 0x100, i, payload)
        end = time.perf_counter()
        latencies.append((end - start) * 1000)

    return latencies


def benchmark_mac_verification():
    """
    Measures time to verify MAC at Gateway.
    """
    import struct
    kms = KMS(MASTER_KEY)
    session_key = kms.get_session_key(0x100)
    payload = struct.pack(">HBB", 40050, 75, 85)
    mac = compute_mac(session_key, 0x100, 0, payload)

    latencies = []
    for i in range(NUM_SAMPLES):
        start = time.perf_counter()
        verify_mac(session_key, 0x100, 0,
                   payload, mac)
        end = time.perf_counter()
        latencies.append((end - start) * 1000)

    return latencies


def benchmark_full_frame_pipeline():
    """
    Measures end-to-end time:
    BMS transmit + Gateway receive.
    """
    bus   = VirtualBus()
    kms   = KMS(MASTER_KEY)
    bms   = BMSECU(kms, bus)
    gw    = GatewayECU(kms)

    latencies = []
    for i in range(NUM_SAMPLES):
        start = time.perf_counter()
        frame = bms.transmit(400.0, 35.0, 85)
        gw.receive(frame)
        end = time.perf_counter()
        latencies.append((end - start) * 1000)

    return latencies


def print_results(name: str,
                  latencies: list,
                  target: float = TARGET_MS):
    mean   = statistics.mean(latencies)
    median = statistics.median(latencies)
    stdev  = statistics.stdev(latencies)
    p95    = sorted(latencies)[int(0.95 * len(latencies))]
    p99    = sorted(latencies)[int(0.99 * len(latencies))]
    worst  = max(latencies)
    passed = mean < target

    print(f"\n{'='*50}")
    print(f"  {name}")
    print(f"{'='*50}")
    print(f"  Samples  : {len(latencies)}")
    print(f"  Mean     : {mean:.4f} ms  "
          f"{'PASS' if passed else 'FAIL'} "
          f"(target < {target} ms)")
    print(f"  Median   : {median:.4f} ms")
    print(f"  Std Dev  : {stdev:.4f} ms")
    print(f"  P95      : {p95:.4f} ms")
    print(f"  P99      : {p99:.4f} ms")
    print(f"  Worst    : {worst:.4f} ms")
    return passed


if __name__ == "__main__":
    print("\nSecureEV — MAC Latency Benchmark")
    print(f"Samples per test : {NUM_SAMPLES}")
    print(f"Target           : < {TARGET_MS} ms")

    # Suppress module print output during benchmark
    import io
    import contextlib

    print("\nRunning benchmarks...")

    # MAC computation
    lat1 = benchmark_mac_computation()
    r1   = print_results("MAC Computation (HMAC-SHA256)",
                         lat1)

    # MAC verification
    lat2 = benchmark_mac_verification()
    r2   = print_results("MAC Verification", lat2)

    # Full pipeline (suppress ECU/GW print output)
    print("\nRunning full pipeline benchmark "
          "(output suppressed)...")
    with contextlib.redirect_stdout(io.StringIO()):
        lat3 = benchmark_full_frame_pipeline()
    r3 = print_results("Full Frame Pipeline "
                       "(TX + GW Receive)", lat3)

    print(f"\n{'='*50}")
    print("  BENCHMARK SUMMARY")
    print(f"{'='*50}")
    print(f"  MAC Computation  : "
          f"{'PASS' if r1 else 'FAIL'}")
    print(f"  MAC Verification : "
          f"{'PASS' if r2 else 'FAIL'}")
    print(f"  Full Pipeline    : "
          f"{'PASS' if r3 else 'FAIL'}")
    overall = r1 and r2 and r3
    print(f"\n  Overall          : "
          f"{'ALL TARGETS MET' if overall else 'SOME TARGETS MISSED'}")
    print(f"{'='*50}\n")