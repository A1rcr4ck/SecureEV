"""
SecureEV Real-Time Dashboard
Run from your secureev project root:
    pip install flask
    python3 dashboard.py
Then open: http://localhost:5000
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, Response, render_template_string
import threading
import queue
import time
import json
import random

app = Flask(__name__)
event_queue = queue.Queue()

# ── Try to import real modules, fall back to simulation ──
try:
    from bus.virtual_bus import VirtualBus
    from modules.kms import KMS
    from modules.bms_ecu import BMSECU
    from modules.motor_ecu import MotorECU
    from modules.obc_ecu import OBCECU
    from modules.gateway_ecu import GatewayECU
    from modules.tcu import TCU
    from attacker.attacker import Attacker
    REAL_MODULES = True
except ImportError:
    REAL_MODULES = False

MASTER_KEY = b'secureev_master_key_32bytes!!!!!'

stats = {
    "accepted": 0,
    "rejected": 0,
    "tcu_blocked": 0,
    "tcu_forwarded": 0,
    "epoch": 0,
    "rotations": 0,
    "attacks": 0,
    "bms_voltage": 400.0,
    "bms_temp": 35.0,
    "bms_soc": 85,
    "motor_torque": 150.0,
    "motor_speed": 1200,
    "obc_current": 16000,
}

def push(event_type, data):
    event_queue.put({"type": event_type, "data": data,
                     "time": time.strftime("%H:%M:%S")})

def run_simulation():
    global stats
    if REAL_MODULES:
        run_real_simulation()
    else:
        run_mock_simulation()

def run_real_simulation():
    global stats
    bus  = VirtualBus()
    kms  = KMS(MASTER_KEY, rotation_interval=20)
    gw   = GatewayECU(kms)
    bms  = BMSECU(kms, bus)
    motor = MotorECU(kms, bus)
    obc  = OBCECU(kms, bus, charger_allowlist=[0x01,0x02])
    tcu  = TCU(kms, gw)
    atk  = Attacker(bus)

    step = 0
    while True:
        time.sleep(0.6)
        step += 1

        # BMS transmit
        v = round(400.0 + random.uniform(-2, 2), 1)
        t = round(35.0  + random.uniform(-1, 1), 1)
        s = max(70, min(95, stats["bms_soc"] +
                        random.randint(-1, 0)))
        stats.update({"bms_voltage": v,
                      "bms_temp": t, "bms_soc": s})
        f = bms.transmit(v, t, s)
        if gw.receive(f):
            stats["accepted"] += 1
            push("accept", {
                "module": "BMS", "can_id": "0x100",
                "counter": f.counter,
                "mac": f.mac.hex(),
                "detail": f"voltage={v}V temp={t}C soc={s}%"
            })
        else:
            stats["rejected"] += 1

        # Motor transmit
        torque = round(150.0 + random.uniform(-5, 5), 1)
        stats["motor_torque"] = torque
        f2 = motor.transmit(torque, 1200, 3)
        if gw.receive(f2):
            stats["accepted"] += 1
            push("accept", {
                "module": "Motor", "can_id": "0x200",
                "counter": f2.counter,
                "mac": f2.mac.hex(),
                "detail": f"torque={torque}Nm speed=1200RPM"
            })

        # OBC transmit
        f3 = obc.transmit(16000, 0x01, 0x01)
        if f3 and gw.receive(f3):
            stats["accepted"] += 1
            push("accept", {
                "module": "OBC", "can_id": "0x300",
                "counter": f3.counter,
                "mac": f3.mac.hex(),
                "detail": "current=16000mA charger=0x01"
            })

        # Inject attack every 8 steps
        if step % 8 == 0:
            attack_type = random.choice([
                "bms_spoof", "drive_by_wire",
                "replay", "rogue_charging"
            ])
            stats["attacks"] += 1

            if attack_type == "bms_spoof":
                af = atk.bms_spoof(999.9, 200.0, 0)
                gw.receive(af)
                stats["rejected"] += 1
                push("attack", {
                    "type": "BMS Spoof",
                    "detail": "voltage=999.9V temp=200C",
                    "reason": "mac_failure",
                    "can_id": "0x100"
                })
            elif attack_type == "drive_by_wire":
                af = atk.drive_by_wire_inject(
                    500.0, 3000, 3
                )
                gw.receive(af)
                stats["rejected"] += 1
                push("attack", {
                    "type": "Drive-by-Wire Inject",
                    "detail": "torque=500Nm speed=3000RPM",
                    "reason": "mac_failure",
                    "can_id": "0x200"
                })
            elif attack_type == "replay":
                af = atk.replay(f)
                gw.receive(af)
                stats["rejected"] += 1
                push("attack", {
                    "type": "Replay Attack",
                    "detail": f"counter={f.counter}",
                    "reason": "replay_attack",
                    "can_id": "0x100"
                })
            elif attack_type == "rogue_charging":
                af = atk.rogue_charging(0xAA, 32000)
                gw.receive(af)
                stats["rejected"] += 1
                push("attack", {
                    "type": "Rogue Charging Station",
                    "detail": "charger_id=0xAA unknown",
                    "reason": "mac_failure",
                    "can_id": "0x300"
                })

        # TCU rogue OTA every 12 steps
        if step % 12 == 0:
            tcu.receive_wireless(
                "ota", b'malicious_fw', "rogue_server"
            )
            stats["tcu_blocked"] = tcu.blocked
            stats["tcu_forwarded"] = tcu.forwarded
            push("tcu_block", {
                "type": "Rogue OTA",
                "source": "rogue_server",
                "reason": "not_in_allowlist"
            })

        # Update KMS stats
        stats["epoch"]     = kms.get_epoch()
        stats["rotations"] = len(kms.get_rotation_log())

        push("stats", dict(stats))

def run_mock_simulation():
    """Fallback simulation if modules not found."""
    global stats
    step = 0
    counter = [0, 0, 0]
    macs = ["a0ed","d81c","b707","fe97","41ab","ceda"]

    while True:
        time.sleep(0.7)
        step += 1

        # BMS
        v = round(400.0 + random.uniform(-3, 3), 1)
        t = round(35.0  + random.uniform(-2, 2), 1)
        s = max(70, min(95, stats["bms_soc"] +
                        random.randint(-1, 0)))
        stats.update({"bms_voltage": v,
                      "bms_temp": t, "bms_soc": s})
        mac = random.choice(macs)
        stats["accepted"] += 1
        push("accept", {
            "module": "BMS", "can_id": "0x100",
            "counter": counter[0],
            "mac": mac,
            "detail": f"voltage={v}V temp={t}C soc={s}%"
        })
        counter[0] += 1

        # Motor
        torque = round(150.0 + random.uniform(-5,5), 1)
        stats["motor_torque"] = torque
        stats["accepted"] += 1
        push("accept", {
            "module": "Motor", "can_id": "0x200",
            "counter": counter[1],
            "mac": random.choice(macs),
            "detail": f"torque={torque}Nm speed=1200RPM"
        })
        counter[1] += 1

        # OBC
        stats["accepted"] += 1
        push("accept", {
            "module": "OBC", "can_id": "0x300",
            "counter": counter[2],
            "mac": random.choice(macs),
            "detail": "current=16000mA charger=0x01"
        })
        counter[2] += 1

        # Attack every 8 steps
        if step % 8 == 0:
            attacks = [
                ("BMS Spoof", "voltage=999.9V temp=200C",
                 "mac_failure", "0x100"),
                ("Drive-by-Wire Inject",
                 "torque=500Nm speed=3000RPM",
                 "mac_failure", "0x200"),
                ("Replay Attack",
                 f"counter={random.randint(0,5)}",
                 "replay_attack", "0x100"),
                ("Rogue Charging Station",
                 "charger_id=0xAA unknown",
                 "mac_failure", "0x300"),
            ]
            atk = random.choice(attacks)
            stats["rejected"] += 1
            stats["attacks"]  += 1
            push("attack", {
                "type": atk[0], "detail": atk[1],
                "reason": atk[2], "can_id": atk[3]
            })

        # TCU block every 12 steps
        if step % 12 == 0:
            stats["tcu_blocked"] += 1
            push("tcu_block", {
                "type": "Rogue OTA",
                "source": "rogue_server",
                "reason": "not_in_allowlist"
            })

        # Key rotation every 15 steps
        if step % 15 == 0:
            stats["epoch"]     += 1
            stats["rotations"] += 1
            push("rotation", {
                "old_epoch": stats["epoch"] - 1,
                "new_epoch": stats["epoch"]
            })

        push("stats", dict(stats))


HTML = '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SecureEV Dashboard</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    font-family: 'Courier New', monospace;
    background: #0a0f1e;
    color: #c8d8f0;
    min-height: 100vh;
    padding: 16px;
  }

  .header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 12px 20px;
    background: #0d1526;
    border: 1px solid #1e3a5f;
    border-radius: 8px;
    margin-bottom: 16px;
  }

  .header h1 {
    font-size: 18px;
    font-weight: 700;
    color: #5bc4f5;
    letter-spacing: 2px;
  }

  .header .subtitle {
    font-size: 11px;
    color: #4a7fa8;
    margin-top: 2px;
  }

  .live-dot {
    width: 8px; height: 8px;
    border-radius: 50%;
    background: #22c55e;
    box-shadow: 0 0 8px #22c55e;
    animation: pulse 1.5s infinite;
    display: inline-block;
    margin-right: 6px;
  }

  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.3; }
  }

  .grid {
    display: grid;
    grid-template-columns: 1fr 1fr 1fr;
    grid-template-rows: auto auto auto;
    gap: 12px;
  }

  .card {
    background: #0d1526;
    border: 1px solid #1e3a5f;
    border-radius: 8px;
    padding: 14px;
  }

  .card-title {
    font-size: 10px;
    letter-spacing: 2px;
    color: #4a7fa8;
    text-transform: uppercase;
    margin-bottom: 10px;
    border-bottom: 1px solid #1e3a5f;
    padding-bottom: 6px;
  }

  /* Stats row */
  .stats-row {
    grid-column: 1 / -1;
    display: grid;
    grid-template-columns: repeat(7, 1fr);
    gap: 10px;
  }

  .stat-box {
    background: #0d1526;
    border: 1px solid #1e3a5f;
    border-radius: 8px;
    padding: 12px 10px;
    text-align: center;
  }

  .stat-value {
    font-size: 26px;
    font-weight: 700;
    line-height: 1;
    margin-bottom: 4px;
  }

  .stat-label {
    font-size: 9px;
    letter-spacing: 1.5px;
    color: #4a7fa8;
    text-transform: uppercase;
  }

  .green  { color: #22c55e; }
  .red    { color: #ef4444; }
  .blue   { color: #5bc4f5; }
  .amber  { color: #f59e0b; }
  .purple { color: #a78bfa; }

  /* ECU panels */
  .ecu-panel {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .ecu-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 5px 8px;
    background: #0a1120;
    border-radius: 4px;
    font-size: 12px;
  }

  .ecu-label { color: #4a7fa8; font-size: 10px; }
  .ecu-value { font-weight: 700; }

  .bar-wrap {
    background: #0a1120;
    border-radius: 4px;
    height: 6px;
    margin-top: 4px;
    overflow: hidden;
  }

  .bar-fill {
    height: 100%;
    border-radius: 4px;
    transition: width 0.5s ease;
  }

  /* Log */
  .log-wrap {
    grid-column: 1 / -1;
    height: 280px;
    overflow-y: auto;
    display: flex;
    flex-direction: column-reverse;
  }

  .log-inner {
    display: flex;
    flex-direction: column;
    gap: 3px;
  }

  .log-entry {
    display: flex;
    align-items: flex-start;
    gap: 8px;
    padding: 5px 8px;
    border-radius: 4px;
    font-size: 11px;
    animation: fadein 0.3s ease;
  }

  @keyframes fadein {
    from { opacity: 0; transform: translateY(-4px); }
    to   { opacity: 1; transform: translateY(0); }
  }

  .log-entry.accept  { background: rgba(34,197,94,0.07);
                       border-left: 2px solid #22c55e; }
  .log-entry.reject  { background: rgba(239,68,68,0.07);
                       border-left: 2px solid #ef4444; }
  .log-entry.attack  { background: rgba(239,68,68,0.12);
                       border-left: 3px solid #ef4444; }
  .log-entry.tcu     { background: rgba(245,158,11,0.08);
                       border-left: 2px solid #f59e0b; }
  .log-entry.rotation{ background: rgba(167,139,250,0.08);
                       border-left: 2px solid #a78bfa; }

  .log-time  { color: #4a7fa8; min-width: 60px;
               font-size: 10px; padding-top: 1px; }
  .log-badge {
    font-size: 9px; padding: 1px 5px;
    border-radius: 3px; font-weight: 700;
    letter-spacing: 1px; min-width: 52px;
    text-align: center; white-space: nowrap;
  }

  .badge-accept  { background: #14532d; color: #22c55e; }
  .badge-reject  { background: #450a0a; color: #ef4444; }
  .badge-attack  { background: #450a0a; color: #f87171; }
  .badge-tcu     { background: #451a03; color: #f59e0b; }
  .badge-rotation{ background: #2e1065; color: #a78bfa; }

  .log-msg { flex: 1; color: #8aacc8; }
  .log-msg span { color: #c8d8f0; }

  /* Architecture zones */
  .arch {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .zone {
    border-radius: 6px;
    padding: 8px 10px;
    border: 1px solid;
    font-size: 10px;
    letter-spacing: 1px;
  }

  .zone-label {
    font-size: 9px;
    letter-spacing: 1.5px;
    opacity: 0.7;
    margin-bottom: 4px;
    text-transform: uppercase;
  }

  .zone-modules {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
  }

  .module-pill {
    padding: 2px 7px;
    border-radius: 3px;
    font-size: 10px;
    font-weight: 700;
    transition: all 0.2s;
  }

  .module-pill.active {
    box-shadow: 0 0 8px currentColor;
    transform: scale(1.05);
  }

  .zone-red    { border-color: #7f1d1d; background: rgba(127,29,29,0.1); color: #fca5a5; }
  .zone-amber  { border-color: #78350f; background: rgba(120,53,15,0.1); color: #fcd34d; }
  .zone-teal   { border-color: #134e4a; background: rgba(19,78,74,0.1);  color: #5eead4; }
  .zone-purple { border-color: #3b0764; background: rgba(59,7,100,0.1);  color: #c4b5fd; }

  .pill-red    { background: rgba(127,29,29,0.3);  color: #fca5a5; }
  .pill-amber  { background: rgba(120,53,15,0.3);  color: #fcd34d; }
  .pill-teal   { background: rgba(19,78,74,0.3);   color: #5eead4; }
  .pill-purple { background: rgba(59,7,100,0.3);   color: #c4b5fd; }

  /* Gateway pipeline */
  .pipeline {
    display: flex;
    flex-direction: column;
    gap: 5px;
  }

  .pipeline-step {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 5px 8px;
    background: #0a1120;
    border-radius: 4px;
    font-size: 11px;
  }

  .step-num {
    width: 18px; height: 18px;
    border-radius: 50%;
    background: #1e3a5f;
    color: #5bc4f5;
    font-size: 10px;
    font-weight: 700;
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }

  .step-name { color: #8aacc8; flex: 1; }
  .step-count {
    font-size: 10px;
    color: #4a7fa8;
    font-weight: 700;
  }

  .scrollbar-thin::-webkit-scrollbar { width: 4px; }
  .scrollbar-thin::-webkit-scrollbar-track { background: #0a0f1e; }
  .scrollbar-thin::-webkit-scrollbar-thumb { background: #1e3a5f;
                                              border-radius: 2px; }
</style>
</head>
<body>

<div class="header">
  <div>
    <h1>⚡ SECUREEV DASHBOARD</h1>
    <div class="subtitle">
      Multi-Layer Cybersecurity Framework for Autonomous EVs
    </div>
  </div>
  <div style="text-align:right; font-size:11px; color:#4a7fa8;">
    <span class="live-dot"></span>LIVE SIMULATION
    <div id="clock" style="margin-top:2px;"></div>
  </div>
</div>

<!-- Stats row -->
<div class="stats-row" style="margin-bottom:12px;">
  <div class="stat-box">
    <div class="stat-value green" id="s-accepted">0</div>
    <div class="stat-label">Accepted</div>
  </div>
  <div class="stat-box">
    <div class="stat-value red" id="s-rejected">0</div>
    <div class="stat-label">Rejected</div>
  </div>
  <div class="stat-box">
    <div class="stat-value amber" id="s-attacks">0</div>
    <div class="stat-label">Attacks</div>
  </div>
  <div class="stat-box">
    <div class="stat-value amber" id="s-tcu-blocked">0</div>
    <div class="stat-label">TCU Blocked</div>
  </div>
  <div class="stat-box">
    <div class="stat-value blue" id="s-epoch">0</div>
    <div class="stat-label">KMS Epoch</div>
  </div>
  <div class="stat-box">
    <div class="stat-value purple" id="s-rotations">0</div>
    <div class="stat-label">Rotations</div>
  </div>
  <div class="stat-box">
    <div class="stat-value blue" id="s-block-rate">0%</div>
    <div class="stat-label">Block Rate</div>
  </div>
</div>

<div class="grid">

  <!-- ECU Status -->
  <div class="card">
    <div class="card-title">ECU Status</div>
    <div class="ecu-panel">

      <div style="font-size:10px; color:#22c55e; letter-spacing:1px;
                  margin-bottom:4px;">BMS ECU — 0x100</div>
      <div class="ecu-row">
        <span class="ecu-label">Voltage</span>
        <span class="ecu-value green" id="bms-v">400.0 V</span>
      </div>
      <div class="ecu-row">
        <span class="ecu-label">Temperature</span>
        <span class="ecu-value green" id="bms-t">35.0 °C</span>
      </div>
      <div class="ecu-row">
        <span class="ecu-label">State of Charge</span>
        <span class="ecu-value green" id="bms-s">85%</span>
      </div>
      <div class="bar-wrap">
        <div class="bar-fill" id="soc-bar"
             style="width:85%; background:#22c55e;"></div>
      </div>

      <div style="font-size:10px; color:#5bc4f5; letter-spacing:1px;
                  margin:8px 0 4px;">Motor ECU — 0x200</div>
      <div class="ecu-row">
        <span class="ecu-label">Torque</span>
        <span class="ecu-value blue" id="motor-t">150.0 Nm</span>
      </div>
      <div class="ecu-row">
        <span class="ecu-label">Speed</span>
        <span class="ecu-value blue">1200 RPM</span>
      </div>

      <div style="font-size:10px; color:#f59e0b; letter-spacing:1px;
                  margin:8px 0 4px;">OBC ECU — 0x300</div>
      <div class="ecu-row">
        <span class="ecu-label">Charge Current</span>
        <span class="ecu-value amber">16000 mA</span>
      </div>
      <div class="ecu-row">
        <span class="ecu-label">Charger ID</span>
        <span class="ecu-value amber">0x01 (trusted)</span>
      </div>
    </div>
  </div>

  <!-- Architecture -->
  <div class="card">
    <div class="card-title">Trust Architecture</div>
    <div class="arch">
      <div class="zone zone-red">
        <div class="zone-label">External Wireless — Untrusted</div>
        <div class="zone-modules">
          <span class="module-pill pill-red">4G/5G</span>
          <span class="module-pill pill-red">Wi-Fi</span>
          <span class="module-pill pill-red">Bluetooth</span>
          <span class="module-pill pill-red" id="pill-attacker">
            Attacker
          </span>
        </div>
      </div>
      <div style="text-align:center; font-size:10px; color:#4a7fa8;">
        ↓ all wireless traffic
      </div>
      <div class="zone zone-amber">
        <div class="zone-label">TCU Trust Boundary — M6</div>
        <div class="zone-modules">
          <span class="module-pill pill-amber"
                id="pill-tcu">TCU</span>
          <span class="module-pill pill-amber">OTA Validate</span>
          <span class="module-pill pill-amber">Allowlist</span>
        </div>
      </div>
      <div style="text-align:center; font-size:10px; color:#4a7fa8;">
        ↓ validated frames only
      </div>
      <div class="zone zone-teal">
        <div class="zone-label">Authenticated CAN — HMAC-SHA256</div>
        <div class="zone-modules">
          <span class="module-pill pill-teal"
                id="pill-gw">Gateway M4</span>
          <span class="module-pill pill-teal">KMS M5</span>
          <span class="module-pill pill-teal"
                id="pill-bms">BMS M1</span>
          <span class="module-pill pill-teal"
                id="pill-motor">Motor M2</span>
          <span class="module-pill pill-teal"
                id="pill-obc">OBC M3</span>
        </div>
      </div>
      <div style="text-align:center; font-size:10px; color:#4a7fa8;">
        ↓ authenticated frames only
      </div>
      <div class="zone zone-purple">
        <div class="zone-label">Autonomous Planning Stack</div>
        <div class="zone-modules">
          <span class="module-pill pill-purple">Perception</span>
          <span class="module-pill pill-purple">Path Planning</span>
          <span class="module-pill pill-purple">Control</span>
        </div>
      </div>
    </div>
  </div>

  <!-- Gateway Pipeline -->
  <div class="card">
    <div class="card-title">Gateway Pipeline</div>
    <div class="pipeline">
      <div class="pipeline-step">
        <div class="step-num">1</div>
        <div class="step-name">Whitelist Check</div>
        <div class="step-count" id="gp-whitelist">—</div>
      </div>
      <div class="pipeline-step">
        <div class="step-num">2</div>
        <div class="step-name">Replay Detection</div>
        <div class="step-count" id="gp-replay">—</div>
      </div>
      <div class="pipeline-step">
        <div class="step-num">3</div>
        <div class="step-name">MAC Verification</div>
        <div class="step-count" id="gp-mac">—</div>
      </div>
      <div class="pipeline-step">
        <div class="step-num">4</div>
        <div class="step-name">Rate Limiting</div>
        <div class="step-count" id="gp-rate">—</div>
      </div>
      <div class="pipeline-step">
        <div class="step-num">5</div>
        <div class="step-name">Domain Isolation</div>
        <div class="step-count" id="gp-domain">—</div>
      </div>
    </div>

    <div style="margin-top:12px; padding-top:10px;
                border-top:1px solid #1e3a5f;">
      <div class="card-title" style="margin-bottom:8px;">
        CAN Frame Format
      </div>
      <div style="display:flex; gap:4px; font-size:10px;">
        <div style="flex:1; background:#1e3a5f; padding:6px;
                    border-radius:4px; text-align:center;">
          <div style="color:#5bc4f5; font-weight:700;">COUNTER</div>
          <div style="color:#4a7fa8; font-size:9px;">2 bytes</div>
        </div>
        <div style="flex:2; background:#134e4a; padding:6px;
                    border-radius:4px; text-align:center;">
          <div style="color:#5eead4; font-weight:700;">PAYLOAD</div>
          <div style="color:#4a7fa8; font-size:9px;">4 bytes</div>
        </div>
        <div style="flex:1; background:#3b0764; padding:6px;
                    border-radius:4px; text-align:center;">
          <div style="color:#c4b5fd; font-weight:700;">MAC</div>
          <div style="color:#4a7fa8; font-size:9px;">2 bytes</div>
        </div>
      </div>
      <div style="font-size:9px; color:#4a7fa8; margin-top:5px;
                  text-align:center;">
        HMAC-SHA256 truncated · Monotonic counter window=5
      </div>
    </div>
  </div>

  <!-- Live log -->
  <div class="card" style="grid-column: 1 / -1;">
    <div class="card-title">Live CAN Bus Feed</div>
    <div class="log-wrap scrollbar-thin" id="log-wrap">
      <div class="log-inner" id="log"></div>
    </div>
  </div>

</div>

<script>
const log     = document.getElementById('log');
const logWrap = document.getElementById('log-wrap');
const MAX_LOG = 80;

let rejectReasons = {
  unknown_can_id: 0, replay_attack: 0,
  mac_failure: 0, rate_limit: 0, domain: 0
};

function addLog(cls, badge, badgeCls, msg, time) {
  const el = document.createElement('div');
  el.className = `log-entry ${cls}`;
  el.innerHTML = `
    <span class="log-time">${time}</span>
    <span class="log-badge ${badgeCls}">${badge}</span>
    <span class="log-msg">${msg}</span>`;
  log.appendChild(el);
  if (log.children.length > MAX_LOG)
    log.removeChild(log.firstChild);
  logWrap.scrollTop = logWrap.scrollHeight;
}

function flash(id) {
  const el = document.getElementById(id);
  if (!el) return;
  el.classList.add('active');
  setTimeout(() => el.classList.remove('active'), 400);
}

function set(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

// Clock
setInterval(() => {
  document.getElementById('clock').textContent =
    new Date().toLocaleTimeString();
}, 1000);

// SSE
const es = new EventSource('/stream');
es.onmessage = e => {
  const ev = JSON.parse(e.data);
  const t  = ev.time;
  const d  = ev.data;

  if (ev.type === 'accept') {
    addLog('accept', 'ACCEPT', 'badge-accept',
      `<span>[${d.module}]</span> can_id=${d.can_id} ` +
      `counter=${d.counter} mac=${d.mac} — ${d.detail}`, t);
    flash('pill-' + d.module.toLowerCase());
    flash('pill-gw');
  }

  else if (ev.type === 'attack') {
    addLog('attack', 'ATTACK', 'badge-attack',
      `<span style="color:#f87171">[${d.type}]</span> ` +
      `${d.detail} → <span style="color:#ef4444">` +
      `BLOCKED (${d.reason})</span>`, t);
    flash('pill-attacker');
    // update reason counts
    if (d.reason in rejectReasons) rejectReasons[d.reason]++;
    updatePipeline();
  }

  else if (ev.type === 'tcu_block') {
    addLog('tcu',
      'TCU BLOCK', 'badge-tcu',
      `<span style="color:#f59e0b">[${d.type}]</span> ` +
      `source=${d.source} → blocked (${d.reason})`, t);
    flash('pill-tcu');
  }

  else if (ev.type === 'rotation') {
    addLog('rotation', 'KEY ROT', 'badge-rotation',
      `KMS epoch <span>${d.old_epoch}</span> → ` +
      `<span>${d.new_epoch}</span> — zero frame loss`, t);
  }

  else if (ev.type === 'stats') {
    set('s-accepted',   d.accepted);
    set('s-rejected',   d.rejected);
    set('s-attacks',    d.attacks);
    set('s-tcu-blocked', d.tcu_blocked);
    set('s-epoch',      d.epoch);
    set('s-rotations',  d.rotations);

    const total = d.accepted + d.rejected;
    const rate  = total > 0
      ? Math.round(d.rejected / total * 100) + '%'
      : '0%';
    set('s-block-rate', rate);

    set('bms-v', d.bms_voltage + ' V');
    set('bms-t', d.bms_temp + ' °C');
    set('bms-s', d.bms_soc + '%');
    set('motor-t', d.motor_torque + ' Nm');

    const bar = document.getElementById('soc-bar');
    if (bar) bar.style.width = d.bms_soc + '%';
  }
};

function updatePipeline() {
  set('gp-whitelist',
    rejectReasons.unknown_can_id
      ? rejectReasons.unknown_can_id + ' blocked' : '—');
  set('gp-replay',
    rejectReasons.replay_attack
      ? rejectReasons.replay_attack + ' blocked' : '—');
  set('gp-mac',
    rejectReasons.mac_failure
      ? rejectReasons.mac_failure + ' blocked' : '—');
  set('gp-rate',
    rejectReasons.rate_limit
      ? rejectReasons.rate_limit + ' blocked' : '—');
  set('gp-domain',
    rejectReasons.domain
      ? rejectReasons.domain + ' blocked' : '—');
}
</script>
</body>
</html>'''


@app.route('/')
def index():
    return render_template_string(HTML)


@app.route('/stream')
def stream():
    def generate():
        while True:
            try:
                event = event_queue.get(timeout=30)
                yield f"data: {json.dumps(event)}\n\n"
            except queue.Empty:
                yield "data: {}\n\n"
    return Response(generate(),
                    mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache',
                             'X-Accel-Buffering': 'no'})


if __name__ == '__main__':
    mode = "real modules" if REAL_MODULES else "mock simulation"
    print(f"\n SecureEV Dashboard — {mode}")
    print(f" Open: http://localhost:5000\n")

    t = threading.Thread(target=run_simulation, daemon=True)
    t.start()
    app.run(debug=False, threaded=True, port=5000)
