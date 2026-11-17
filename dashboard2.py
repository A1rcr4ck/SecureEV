"""
SecureEV Animated Network Dashboard
Copy to your secureev project root and run:
    pip install flask
    python3 dashboard2.py
Open: http://localhost:5001
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, Response, render_template_string
import threading, queue, time, json, random

app = Flask(__name__)
eq  = queue.Queue()

try:
    from bus.virtual_bus import VirtualBus
    from modules.kms import KMS
    from modules.bms_ecu import BMSECU
    from modules.motor_ecu import MotorECU
    from modules.obc_ecu import OBCECU
    from modules.gateway_ecu import GatewayECU
    from modules.tcu import TCU
    from attacker.attacker import Attacker
    REAL = True
except ImportError:
    REAL = False

MASTER_KEY = b'secureev_master_key_32bytes!!!!!'

counters = {"bms":0,"motor":0,"obc":0,"atk":0}
gstats   = {"accepted":0,"rejected":0,"tcu_blocked":0,
            "epoch":0,"rotations":0,"attacks":0,
            "mac_fail":0,"replay_fail":0,"whitelist_fail":0}
bms_data = {"voltage":400.0,"temp":35.0,"soc":85}
atk_mode = {"active": False, "type": "bms_spoof"}

def push(t, d):
    eq.put({"type":t,"data":d,"ts":time.time()})

def sim_loop():
    if REAL:
        real_loop()
    else:
        mock_loop()

def real_loop():
    bus   = VirtualBus()
    kms   = KMS(MASTER_KEY, rotation_interval=25)
    gw    = GatewayECU(kms)
    bms   = BMSECU(kms, bus)
    motor = MotorECU(kms, bus)
    obc   = OBCECU(kms, bus, charger_allowlist=[0x01,0x02])
    tcu   = TCU(kms, gw)
    atk   = Attacker(bus)
    step  = 0

    while True:
        time.sleep(0.9)
        step += 1

        v = round(400 + random.uniform(-3,3), 1)
        t = round(35  + random.uniform(-1,1), 1)
        s = max(72, min(95, bms_data["soc"] + random.randint(-1,0)))
        bms_data.update({"voltage":v,"temp":t,"soc":s})

        f = bms.transmit(v, t, s)
        counters["bms"] += 1
        if gw.receive(f):
            gstats["accepted"] += 1
            push("frame",{"from":"BMS","to":"PLANNING",
                "via":"GW","status":"accept",
                "can_id":"0x100","counter":f.counter,
                "mac":f.mac.hex(),
                "detail":f"V={v} T={t}°C SOC={s}%",
                "color":"#22c55e"})
        else:
            gstats["rejected"] += 1
            push("frame",{"from":"BMS","to":"GW",
                "status":"reject","can_id":"0x100",
                "reason":"mac_failure","color":"#ef4444"})

        f2 = motor.transmit(150+random.uniform(-5,5), 1200, 3)
        counters["motor"] += 1
        if gw.receive(f2):
            gstats["accepted"] += 1
            push("frame",{"from":"MOTOR","to":"PLANNING",
                "via":"GW","status":"accept",
                "can_id":"0x200","counter":f2.counter,
                "mac":f2.mac.hex(),
                "detail":f"torque={round(f2.counter*0+150,1)}Nm",
                "color":"#38bdf8"})

        f3 = obc.transmit(16000, 0x01, 0x01)
        counters["obc"] += 1
        if f3 and gw.receive(f3):
            gstats["accepted"] += 1
            push("frame",{"from":"OBC","to":"PLANNING",
                "via":"GW","status":"accept",
                "can_id":"0x300","counter":f3.counter,
                "mac":f3.mac.hex(),
                "detail":"16000mA charger=0x01",
                "color":"#f59e0b"})

        if step % 7 == 0:
            _run_attack(atk, gw, f)

        if step % 11 == 0:
            tcu.receive_wireless("ota",b'malware',"rogue")
            gstats["tcu_blocked"] = tcu.blocked
            push("tcu",{"type":"Rogue OTA","source":"rogue_server",
                "reason":"unsigned payload"})

        gstats["epoch"]     = kms.get_epoch()
        gstats["rotations"] = len(kms.get_rotation_log())
        push("stats", {**gstats, **bms_data,
             "bms_frames":counters["bms"],
             "motor_frames":counters["motor"],
             "obc_frames":counters["obc"]})

def _run_attack(atk, gw, last_frame):
    gstats["attacks"] += 1
    counters["atk"]   += 1
    choice = random.choice(["bms_spoof","dw","replay",
                             "rogue_charge","flood"])

    if choice == "bms_spoof":
        af = atk.bms_spoof(999.9, 200.0, 0)
        gw.receive(af)
        gstats["mac_fail"] += 1
        gstats["rejected"] += 1
        push("attack",{"type":"BMS Spoof",
            "from":"ATTACKER","target":"BMS",
            "detail":"V=999.9 T=200°C SOC=0%",
            "reason":"mac_failure","color":"#ef4444"})

    elif choice == "dw":
        af = atk.drive_by_wire_inject(500.0,3000,3)
        gw.receive(af)
        gstats["mac_fail"] += 1
        gstats["rejected"] += 1
        push("attack",{"type":"Drive-by-Wire Inject",
            "from":"ATTACKER","target":"MOTOR",
            "detail":"torque=500Nm speed=3000RPM",
            "reason":"mac_failure","color":"#ef4444"})

    elif choice == "replay":
        af = atk.replay(last_frame)
        gw.receive(af)
        gstats["replay_fail"] += 1
        gstats["rejected"]    += 1
        push("attack",{"type":"Replay Attack",
            "from":"ATTACKER","target":"GW",
            "detail":f"counter={last_frame.counter} replayed",
            "reason":"replay_attack","color":"#f97316"})

    elif choice == "rogue_charge":
        af = atk.rogue_charging(0xAA, 32000)
        gw.receive(af)
        gstats["mac_fail"] += 1
        gstats["rejected"] += 1
        push("attack",{"type":"Rogue Charging",
            "from":"ATTACKER","target":"OBC",
            "detail":"charger_id=0xAA unknown",
            "reason":"mac_failure","color":"#ef4444"})

    elif choice == "flood":
        atk.can_flood(0x100, 5)
        for _ in range(5):
            gstats["rejected"]  += 1
            gstats["mac_fail"]  += 1
        push("attack",{"type":"CAN Flood",
            "from":"ATTACKER","target":"GW",
            "detail":"5 frames injected",
            "reason":"mac_failure","color":"#ef4444"})

def mock_loop():
    step = 0
    macs = ["a0ed","d81c","b707","fe97","41ab","ceda",
            "7760","1b4a","0afe","d348","fe43","b61d"]
    while True:
        time.sleep(0.9)
        step += 1

        v = round(400 + random.uniform(-3,3),1)
        t = round(35  + random.uniform(-1,1),1)
        s = max(72, min(95, bms_data["soc"] + random.randint(-1,0)))
        bms_data.update({"voltage":v,"temp":t,"soc":s})
        counters["bms"] += 1
        gstats["accepted"] += 1
        push("frame",{"from":"BMS","to":"PLANNING","via":"GW",
            "status":"accept","can_id":"0x100",
            "counter":counters["bms"],
            "mac":random.choice(macs),
            "detail":f"V={v} T={t}°C SOC={s}%",
            "color":"#22c55e"})

        counters["motor"] += 1
        gstats["accepted"] += 1
        torque = round(150+random.uniform(-5,5),1)
        push("frame",{"from":"MOTOR","to":"PLANNING","via":"GW",
            "status":"accept","can_id":"0x200",
            "counter":counters["motor"],
            "mac":random.choice(macs),
            "detail":f"torque={torque}Nm",
            "color":"#38bdf8"})

        counters["obc"] += 1
        gstats["accepted"] += 1
        push("frame",{"from":"OBC","to":"PLANNING","via":"GW",
            "status":"accept","can_id":"0x300",
            "counter":counters["obc"],
            "mac":random.choice(macs),
            "detail":"16000mA charger=0x01",
            "color":"#f59e0b"})

        if step % 7 == 0:
            gstats["attacks"] += 1
            counters["atk"]   += 1
            atk_choices = [
                ("BMS Spoof","BMS","V=999.9 T=200°C",
                 "mac_failure","#ef4444"),
                ("Drive-by-Wire","MOTOR","torque=500Nm",
                 "mac_failure","#ef4444"),
                ("Replay Attack","GW",
                 f"counter={random.randint(0,5)} replayed",
                 "replay_attack","#f97316"),
                ("Rogue Charging","OBC",
                 "charger=0xAA unknown",
                 "mac_failure","#ef4444"),
            ]
            ac = random.choice(atk_choices)
            gstats["rejected"] += 1
            if ac[3]=="mac_failure": gstats["mac_fail"]+=1
            else: gstats["replay_fail"]+=1
            push("attack",{"type":ac[0],"from":"ATTACKER",
                "target":ac[1],"detail":ac[2],
                "reason":ac[3],"color":ac[4]})

        if step % 11 == 0:
            gstats["tcu_blocked"] += 1
            push("tcu",{"type":"Rogue OTA",
                "source":"rogue_server",
                "reason":"unsigned payload"})

        if step % 18 == 0:
            gstats["epoch"]     += 1
            gstats["rotations"] += 1
            push("rotation",{"old":gstats["epoch"]-1,
                              "new":gstats["epoch"]})

        push("stats",{**gstats,**bms_data,
             "bms_frames":counters["bms"],
             "motor_frames":counters["motor"],
             "obc_frames":counters["obc"]})

# ── HTML ──────────────────────────────────────────────────────────────────────
HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SecureEV Network Dashboard</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#080c18;color:#c8d8f0;
     font-family:'Courier New',monospace;
     height:100vh;overflow:hidden;display:flex;
     flex-direction:column;}

/* ── header ── */
.hdr{display:flex;align-items:center;justify-content:space-between;
     padding:10px 18px;background:#0b1020;
     border-bottom:1px solid #1a2f50;flex-shrink:0;}
.hdr-title{font-size:15px;font-weight:700;
           color:#5bc4f5;letter-spacing:3px;}
.hdr-sub{font-size:10px;color:#3a6080;margin-top:1px;}
.live-ind{display:flex;align-items:center;gap:6px;
          font-size:10px;color:#3a6080;}
.dot{width:7px;height:7px;border-radius:50%;
     background:#22c55e;box-shadow:0 0 6px #22c55e;
     animation:blink 1.4s infinite;}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.25}}

/* ── main layout ── */
.main{display:flex;flex:1;overflow:hidden;gap:0;}
.sidebar{width:220px;flex-shrink:0;background:#0b1020;
         border-right:1px solid #1a2f50;
         display:flex;flex-direction:column;overflow:hidden;}
.canvas-wrap{flex:1;position:relative;overflow:hidden;}
.log-panel{width:260px;flex-shrink:0;background:#0b1020;
           border-left:1px solid #1a2f50;
           display:flex;flex-direction:column;overflow:hidden;}

/* ── sidebar stats ── */
.sb-section{padding:10px 12px;
            border-bottom:1px solid #1a2f50;}
.sb-label{font-size:9px;color:#3a6080;
          letter-spacing:1px;margin-bottom:6px;}
.stat-row{display:flex;justify-content:space-between;
          align-items:center;margin-bottom:4px;font-size:11px;}
.stat-key{color:#4a7fa8;}
.stat-val{font-weight:700;}
.green{color:#22c55e} .red{color:#ef4444}
.blue{color:#38bdf8}  .amber{color:#f59e0b}
.purple{color:#a78bfa}.orange{color:#f97316}

.bar-bg{background:#111827;border-radius:3px;
        height:5px;margin-top:3px;overflow:hidden;}
.bar-fg{height:100%;border-radius:3px;
        transition:width .6s ease;}

/* sensor card */
.sensor{padding:8px 10px;background:#0d1526;
        border:1px solid #1a2f50;border-radius:6px;
        margin:0 10px 6px;font-size:11px;}
.sensor-title{color:#3a6080;font-size:9px;
              letter-spacing:1px;margin-bottom:5px;}
.sensor-row{display:flex;justify-content:space-between;
            margin-bottom:3px;}

/* attack buttons */
.atk-btn{margin:4px 10px;padding:6px 8px;
         background:#1a0a0a;border:1px solid #3a1515;
         border-radius:5px;color:#ef4444;
         font-family:'Courier New',monospace;
         font-size:10px;cursor:pointer;
         width:calc(100% - 20px);text-align:left;
         transition:background .2s;}
.atk-btn:hover{background:#2a1010;}
.atk-btn.tcu{color:#f59e0b;background:#1a1000;
             border-color:#3a2a00;}
.atk-btn.tcu:hover{background:#2a1a00;}

/* ── canvas (SVG topology) ── */
#canvas{width:100%;height:100%;}

/* nodes */
.node-box{transition:filter .2s;}
.node-box.flash-green{filter:drop-shadow(0 0 12px #22c55e);}
.node-box.flash-red{filter:drop-shadow(0 0 12px #ef4444);}
.node-box.flash-amber{filter:drop-shadow(0 0 12px #f59e0b);}

/* ── log panel ── */
.log-hdr{padding:8px 12px;
         border-bottom:1px solid #1a2f50;
         font-size:9px;color:#3a6080;letter-spacing:1px;}
.log-list{flex:1;overflow-y:auto;padding:6px;}
.log-list::-webkit-scrollbar{width:3px;}
.log-list::-webkit-scrollbar-thumb{background:#1a2f50;
                                    border-radius:2px;}
.log-item{padding:5px 7px;border-radius:4px;
          margin-bottom:3px;font-size:10px;
          animation:fadeup .25s ease;border-left:2px solid;}
@keyframes fadeup{from{opacity:0;transform:translateY(-3px)}
                  to{opacity:1;transform:translateY(0)}}
.log-item.accept{background:rgba(34,197,94,.06);
                 border-color:#22c55e;}
.log-item.reject{background:rgba(239,68,68,.06);
                 border-color:#ef4444;}
.log-item.attack{background:rgba(239,68,68,.1);
                 border-color:#ef4444;}
.log-item.tcu{background:rgba(245,158,11,.07);
              border-color:#f59e0b;}
.log-item.rotation{background:rgba(167,139,250,.07);
                   border-color:#a78bfa;}
.log-time{color:#3a6080;font-size:9px;}
.log-badge{display:inline-block;font-size:8px;
           padding:1px 4px;border-radius:2px;
           font-weight:700;margin:0 4px 2px 0;
           letter-spacing:.5px;}
.badge-ok{background:#14532d;color:#22c55e;}
.badge-no{background:#450a0a;color:#ef4444;}
.badge-atk{background:#7c2d12;color:#fb923c;}
.badge-tcu{background:#451a03;color:#f59e0b;}
.badge-rot{background:#2e1065;color:#a78bfa;}
.log-detail{color:#6a8aaa;margin-top:2px;}
</style>
</head>
<body>

<!-- header -->
<div class="hdr">
  <div>
    <div class="hdr-title">⚡ SECUREEV — NETWORK SIMULATION</div>
    <div class="hdr-sub">
      Authenticated CAN Bus · TCU Trust Boundary · Gateway Enforcement
    </div>
  </div>
  <div class="live-ind">
    <div class="dot"></div>
    <span id="clock">—</span>
  </div>
</div>

<div class="main">

  <!-- ── left sidebar ── -->
  <div class="sidebar">
    <div class="sb-section">
      <div class="sb-label">Gateway Stats</div>
      <div class="stat-row">
        <span class="stat-key">Accepted</span>
        <span class="stat-val green" id="s-acc">0</span>
      </div>
      <div class="stat-row">
        <span class="stat-key">Rejected</span>
        <span class="stat-val red" id="s-rej">0</span>
      </div>
      <div class="stat-row">
        <span class="stat-key">Attacks</span>
        <span class="stat-val orange" id="s-atk">0</span>
      </div>
      <div class="stat-row">
        <span class="stat-key">TCU Blocked</span>
        <span class="stat-val amber" id="s-tcu">0</span>
      </div>
      <div class="stat-row">
        <span class="stat-key">MAC Failures</span>
        <span class="stat-val red" id="s-mac">0</span>
      </div>
      <div class="stat-row">
        <span class="stat-key">Replay Blocks</span>
        <span class="stat-val orange" id="s-rep">0</span>
      </div>
    </div>

    <div class="sb-section">
      <div class="sb-label">KMS</div>
      <div class="stat-row">
        <span class="stat-key">Epoch</span>
        <span class="stat-val purple" id="s-epoch">0</span>
      </div>
      <div class="stat-row">
        <span class="stat-key">Rotations</span>
        <span class="stat-val purple" id="s-rot">0</span>
      </div>
    </div>

    <div class="sb-section">
      <div class="sb-label">Frame Counters</div>
      <div class="stat-row">
        <span class="stat-key">BMS frames</span>
        <span class="stat-val green" id="s-bf">0</span>
      </div>
      <div class="stat-row">
        <span class="stat-key">Motor frames</span>
        <span class="stat-val blue" id="s-mf">0</span>
      </div>
      <div class="stat-row">
        <span class="stat-key">OBC frames</span>
        <span class="stat-val amber" id="s-of">0</span>
      </div>
    </div>

    <!-- BMS live sensor -->
    <div class="sb-section" style="flex:1;">
      <div class="sb-label">BMS Live Sensor</div>
      <div class="sensor">
        <div class="sensor-title">BATTERY MANAGEMENT SYSTEM</div>
        <div class="sensor-row">
          <span style="color:#4a7fa8">Voltage</span>
          <span class="green" id="bms-v">400.0 V</span>
        </div>
        <div class="sensor-row">
          <span style="color:#4a7fa8">Temperature</span>
          <span class="green" id="bms-t">35.0 °C</span>
        </div>
        <div class="sensor-row">
          <span style="color:#4a7fa8">SOC</span>
          <span class="green" id="bms-s">85%</span>
        </div>
        <div class="bar-bg" style="margin-top:6px;">
          <div class="bar-fg" id="soc-bar"
               style="width:85%;background:#22c55e;"></div>
        </div>
      </div>

      <!-- Attack buttons -->
      <div style="padding:6px 0 4px;font-size:9px;
                  color:#3a6080;padding-left:10px;
                  letter-spacing:1px;">
        Simulate Attack
      </div>
      <button class="atk-btn" onclick="triggerAtk('bms_spoof')">
        ⚡ BMS Spoof
      </button>
      <button class="atk-btn" onclick="triggerAtk('drive_by_wire')">
        🚗 Drive-by-Wire
      </button>
      <button class="atk-btn" onclick="triggerAtk('replay')">
        🔁 Replay Attack
      </button>
      <button class="atk-btn" onclick="triggerAtk('flood')">
        💥 CAN Flood
      </button>
      <button class="atk-btn tcu" onclick="triggerAtk('rogue_ota')">
        📡 Rogue OTA (TCU)
      </button>
    </div>
  </div>

  <!-- ── SVG canvas ── -->
  <div class="canvas-wrap">
    <svg id="canvas" viewBox="0 0 900 520"
         preserveAspectRatio="xMidYMid meet">

      <!-- Bus line (horizontal backbone) -->
      <line x1="150" y1="260" x2="750" y2="260"
            stroke="#1a3a5a" stroke-width="2"
            stroke-dasharray="6 4"/>
      <text x="420" y="275" fill="#1a3a5a"
            font-size="9" text-anchor="middle"
            font-family="Courier New">
        CAN Bus — HMAC-SHA256 authenticated
      </text>

      <!-- ── External wireless zone (top) ── -->
      <rect x="280" y="10" width="340" height="70"
            rx="8" fill="none" stroke="#7f1d1d"
            stroke-width="1" stroke-dasharray="5 3"/>
      <text x="450" y="27" fill="#fca5a5" font-size="9"
            text-anchor="middle" font-family="Courier New">
        External Wireless (Untrusted)
      </text>

      <!-- 4G node -->
      <g id="node-4g" class="node-box"
         transform="translate(300,35)">
        <rect width="60" height="32" rx="5"
              fill="#1a0808" stroke="#7f1d1d" stroke-width="1"/>
        <text x="30" y="14" fill="#fca5a5" font-size="9"
              text-anchor="middle" font-family="Courier New"
              font-weight="700">4G/5G</text>
        <text x="30" y="26" fill="#7f1d1d" font-size="8"
              text-anchor="middle" font-family="Courier New">
          Cellular
        </text>
      </g>

      <!-- Wi-Fi node -->
      <g id="node-wifi" class="node-box"
         transform="translate(390,35)">
        <rect width="60" height="32" rx="5"
              fill="#1a0808" stroke="#7f1d1d" stroke-width="1"/>
        <text x="30" y="14" fill="#fca5a5" font-size="9"
              text-anchor="middle" font-family="Courier New"
              font-weight="700">Wi-Fi</text>
        <text x="30" y="26" fill="#7f1d1d" font-size="8"
              text-anchor="middle" font-family="Courier New">
          OTA
        </text>
      </g>

      <!-- Attacker node -->
      <g id="node-atk" class="node-box"
         transform="translate(480,35)">
        <rect width="70" height="32" rx="5"
              fill="#2a0808" stroke="#ef4444" stroke-width="1.5"/>
        <text x="35" y="14" fill="#ef4444" font-size="9"
              text-anchor="middle" font-family="Courier New"
              font-weight="700">Attacker</text>
        <text x="35" y="26" fill="#7f1d1d" font-size="8"
              text-anchor="middle" font-family="Courier New">
          rogue
        </text>
      </g>

      <!-- Arrows wireless to TCU -->
      <line x1="330" y1="67" x2="400" y2="115"
            stroke="#7f1d1d" stroke-width="1"
            marker-end="url(#arr-red)"/>
      <line x1="420" y1="67" x2="420" y2="115"
            stroke="#7f1d1d" stroke-width="1"
            marker-end="url(#arr-red)"/>
      <line x1="515" y1="67" x2="450" y2="115"
            stroke="#ef4444" stroke-width="1.5"
            stroke-dasharray="4 2"
            marker-end="url(#arr-red)"/>

      <!-- ── TCU boundary ── -->
      <rect x="260" y="110" width="380" height="60"
            rx="8" fill="none" stroke="#78350f"
            stroke-width="1" stroke-dasharray="5 3"/>
      <text x="340" y="126" fill="#fcd34d" font-size="9"
            text-anchor="middle" font-family="Courier New">
        TCU Trust Boundary — M6
      </text>

      <!-- TCU node -->
      <g id="node-tcu" class="node-box"
         transform="translate(330,130)">
        <rect width="180" height="32" rx="6"
              fill="#1a1000" stroke="#78350f" stroke-width="1.5"/>
        <text x="90" y="14" fill="#fcd34d" font-size="10"
              text-anchor="middle" font-family="Courier New"
              font-weight="700">Telematics Control Unit</text>
        <text x="90" y="26" fill="#78350f" font-size="8"
              text-anchor="middle" font-family="Courier New">
          Allowlist · OTA validate · Classify
        </text>
      </g>

      <!-- Arrow TCU to Gateway -->
      <line x1="420" y1="162" x2="420" y2="205"
            stroke="#78350f" stroke-width="1.5"
            marker-end="url(#arr-amber)"/>
      <text x="440" y="187" fill="#78350f" font-size="8"
            font-family="Courier New">validated only</text>

      <!-- ── Authenticated CAN zone ── -->
      <rect x="60" y="195" width="780" height="180"
            rx="10" fill="none" stroke="#134e4a"
            stroke-width="1" stroke-dasharray="5 3"/>
      <text x="130" y="212" fill="#5eead4" font-size="9"
            font-family="Courier New">
        Authenticated CAN Bus (HMAC-SHA256)
      </text>

      <!-- Gateway node -->
      <g id="node-gw" class="node-box"
         transform="translate(340,218)">
        <rect width="160" height="50" rx="7"
              fill="#0d201e" stroke="#134e4a" stroke-width="2"/>
        <text x="80" y="18" fill="#5eead4" font-size="11"
              text-anchor="middle" font-family="Courier New"
              font-weight="700">Gateway ECU</text>
        <text x="80" y="30" fill="#134e4a" font-size="8"
              text-anchor="middle" font-family="Courier New">
          Whitelist · Replay · MAC
        </text>
        <text x="80" y="42" fill="#134e4a" font-size="8"
              text-anchor="middle" font-family="Courier New">
          Rate Limit · Domain Isolation
        </text>
      </g>

      <!-- KMS node -->
      <g id="node-kms" class="node-box"
         transform="translate(660,220)">
        <rect width="120" height="46" rx="6"
              fill="#0d1020" stroke="#3b0764" stroke-width="1.5"/>
        <text x="60" y="17" fill="#c4b5fd" font-size="10"
              text-anchor="middle" font-family="Courier New"
              font-weight="700">KMS — M5</text>
        <text x="60" y="29" fill="#3b0764" font-size="8"
              text-anchor="middle" font-family="Courier New">
          HKDF derivation
        </text>
        <text x="60" y="40" fill="#3b0764" font-size="8"
              text-anchor="middle" font-family="Courier New">
          Atomic rotation
        </text>
      </g>
      <!-- KMS to Gateway arrow -->
      <line x1="660" y1="243" x2="500" y2="243"
            stroke="#3b0764" stroke-width="1.5"
            marker-end="url(#arr-purple)"/>

      <!-- ECU nodes -->
      <!-- BMS -->
      <g id="node-bms" class="node-box"
         transform="translate(75,310)">
        <rect width="110" height="50" rx="6"
              fill="#0d1a0d" stroke="#166534" stroke-width="1.5"/>
        <text x="55" y="17" fill="#22c55e" font-size="10"
              text-anchor="middle" font-family="Courier New"
              font-weight="700">BMS — M1</text>
        <text x="55" y="29" fill="#166534" font-size="8"
              text-anchor="middle" font-family="Courier New">
          0x100 · 10ms
        </text>
        <text x="55" y="41" fill="#166534" font-size="8"
              text-anchor="middle" font-family="Courier New">
          V · T · SOC
        </text>
      </g>

      <!-- Motor -->
      <g id="node-motor" class="node-box"
         transform="translate(220,310)">
        <rect width="110" height="50" rx="6"
              fill="#0a1520" stroke="#1e40af" stroke-width="1.5"/>
        <text x="55" y="17" fill="#38bdf8" font-size="10"
              text-anchor="middle" font-family="Courier New"
              font-weight="700">Motor — M2</text>
        <text x="55" y="29" fill="#1e40af" font-size="8"
              text-anchor="middle" font-family="Courier New">
          0x200 · 5ms
        </text>
        <text x="55" y="41" fill="#1e40af" font-size="8"
              text-anchor="middle" font-family="Courier New">
          Torque · Speed
        </text>
      </g>

      <!-- OBC -->
      <g id="node-obc" class="node-box"
         transform="translate(365,310)">
        <rect width="110" height="50" rx="6"
              fill="#1a1200" stroke="#78350f" stroke-width="1.5"/>
        <text x="55" y="17" fill="#f59e0b" font-size="10"
              text-anchor="middle" font-family="Courier New"
              font-weight="700">OBC — M3</text>
        <text x="55" y="29" fill="#78350f" font-size="8"
              text-anchor="middle" font-family="Courier New">
          0x300 · 100ms
        </text>
        <text x="55" y="41" fill="#78350f" font-size="8"
              text-anchor="middle" font-family="Courier New">
          Charging
        </text>
      </g>

      <!-- Attacker on bus -->
      <g id="node-atk-bus" class="node-box"
         transform="translate(510,310)">
        <rect width="110" height="50" rx="6"
              fill="#1a0505" stroke="#7f1d1d" stroke-width="1.5"
              stroke-dasharray="4 2"/>
        <text x="55" y="17" fill="#ef4444" font-size="10"
              text-anchor="middle" font-family="Courier New"
              font-weight="700">Attacker</text>
        <text x="55" y="29" fill="#7f1d1d" font-size="8"
              text-anchor="middle" font-family="Courier New">
          0x7FF · no key
        </text>
        <text x="55" y="41" fill="#7f1d1d" font-size="8"
              text-anchor="middle" font-family="Courier New">
          Spoof · Replay
        </text>
      </g>

      <!-- ECU to bus vertical lines -->
      <line x1="130" y1="310" x2="130" y2="260"
            stroke="#134e4a" stroke-width="1.5"
            marker-end="url(#arr-teal)"/>
      <line x1="275" y1="310" x2="275" y2="260"
            stroke="#134e4a" stroke-width="1.5"
            marker-end="url(#arr-teal)"/>
      <line x1="420" y1="310" x2="420" y2="268"
            stroke="#134e4a" stroke-width="1.5"
            marker-end="url(#arr-teal)"/>
      <line x1="565" y1="310" x2="565" y2="260"
            stroke="#7f1d1d" stroke-width="1.5"
            stroke-dasharray="4 2"
            marker-end="url(#arr-red)"/>

      <!-- Gateway to bus -->
      <line x1="420" y1="268" x2="420" y2="258"
            stroke="#134e4a" stroke-width="2"/>

      <!-- ── Autonomous planning zone ── -->
      <rect x="60" y="390" width="780" height="55"
            rx="8" fill="none" stroke="#2e1065"
            stroke-width="1" stroke-dasharray="5 3"/>
      <text x="450" y="407" fill="#a78bfa" font-size="9"
            text-anchor="middle" font-family="Courier New">
        Autonomous Planning Stack — authenticated frames only
      </text>

      <g id="node-plan" class="node-box"
         transform="translate(245,412)">
        <rect width="410" height="26" rx="5"
              fill="#12082a" stroke="#2e1065" stroke-width="1.5"/>
        <text x="205" y="17" fill="#c4b5fd" font-size="10"
              text-anchor="middle" font-family="Courier New"
              font-weight="700">
          Perception · Path Planning · Vehicle Control
        </text>
      </g>

      <!-- Arrow bus to planning -->
      <line x1="420" y1="375" x2="420" y2="390"
            stroke="#2e1065" stroke-width="1.5"
            marker-end="url(#arr-purple)"/>
      <text x="460" y="386" fill="#2e1065" font-size="8"
            font-family="Courier New">auth + cleared</text>

      <!-- Arrowhead markers -->
      <defs>
        <marker id="arr-teal" viewBox="0 0 10 10"
                refX="8" refY="5"
                markerWidth="6" markerHeight="6"
                orient="auto-start-reverse">
          <path d="M2 1L8 5L2 9" fill="none"
                stroke="#134e4a" stroke-width="1.5"
                stroke-linecap="round"/>
        </marker>
        <marker id="arr-red" viewBox="0 0 10 10"
                refX="8" refY="5"
                markerWidth="6" markerHeight="6"
                orient="auto-start-reverse">
          <path d="M2 1L8 5L2 9" fill="none"
                stroke="#7f1d1d" stroke-width="1.5"
                stroke-linecap="round"/>
        </marker>
        <marker id="arr-amber" viewBox="0 0 10 10"
                refX="8" refY="5"
                markerWidth="6" markerHeight="6"
                orient="auto-start-reverse">
          <path d="M2 1L8 5L2 9" fill="none"
                stroke="#78350f" stroke-width="1.5"
                stroke-linecap="round"/>
        </marker>
        <marker id="arr-purple" viewBox="0 0 10 10"
                refX="8" refY="5"
                markerWidth="6" markerHeight="6"
                orient="auto-start-reverse">
          <path d="M2 1L8 5L2 9" fill="none"
                stroke="#2e1065" stroke-width="1.5"
                stroke-linecap="round"/>
        </marker>
      </defs>

      <!-- Animated packet container -->
      <g id="packets"></g>

      <!-- Frame info tooltip -->
      <g id="tooltip" opacity="0">
        <rect id="tt-bg" x="0" y="0" width="200" height="70"
              rx="5" fill="#0d1526" stroke="#1e3a5f"
              stroke-width="1"/>
        <text id="tt-line1" x="8" y="16"
              fill="#5bc4f5" font-size="9"
              font-family="Courier New" font-weight="700"/>
        <text id="tt-line2" x="8" y="28"
              fill="#8aacc8" font-size="8"
              font-family="Courier New"/>
        <text id="tt-line3" x="8" y="40"
              fill="#8aacc8" font-size="8"
              font-family="Courier New"/>
        <text id="tt-line4" x="8" y="52"
              fill="#8aacc8" font-size="8"
              font-family="Courier New"/>
        <text id="tt-status" x="8" y="64"
              font-size="9" font-family="Courier New"
              font-weight="700"/>
      </g>

    </svg>
  </div>

  <!-- ── log panel ── -->
  <div class="log-panel">
    <div class="log-hdr">Event Log</div>
    <div class="log-list" id="log-list"></div>
  </div>

</div>

<script>
// ── node center coords (SVG viewBox space) ────────────────
const NODE = {
  BMS:      {x:130, y:335},
  MOTOR:    {x:275, y:335},
  OBC:      {x:420, y:335},
  ATTACKER: {x:565, y:335},
  GW:       {x:420, y:243},
  TCU:      {x:420, y:146},
  WIFI:     {x:420, y:51},
  PLANNING: {x:420, y:425},
  KMS:      {x:720, y:243},
};

const BUS_Y = 260;

let pktId = 0;
const MAX_LOG = 60;

// clock
setInterval(()=>{
  const d = new Date();
  document.getElementById('clock').textContent =
    d.toLocaleTimeString();
}, 1000);

// ── animate a packet along a path ────────────────────────
function animPacket(x1,y1,x2,y2,color,label,onDone,via){
  const g = document.createElementNS(
    'http://www.w3.org/2000/svg','g');
  const r = document.createElementNS(
    'http://www.w3.org/2000/svg','rect');
  const t = document.createElementNS(
    'http://www.w3.org/2000/svg','text');

  const w = Math.max(label.length * 5.5 + 10, 36);
  r.setAttribute('width', w);
  r.setAttribute('height', 16);
  r.setAttribute('rx', 3);
  r.setAttribute('fill', color);
  r.setAttribute('opacity', '0.9');
  t.setAttribute('x', w/2);
  t.setAttribute('y', 11);
  t.setAttribute('fill', '#000');
  t.setAttribute('font-size', '8');
  t.setAttribute('font-family','Courier New');
  t.setAttribute('font-weight','700');
  t.setAttribute('text-anchor','middle');
  t.textContent = label;
  g.appendChild(r); g.appendChild(t);
  g.setAttribute('transform',`translate(${x1-w/2},${y1-8})`);
  document.getElementById('packets').appendChild(g);

  // simple two-segment animation via waypoint
  const steps = via ? 30 : 22;
  let step = 0;
  const mid = via || {x:(x1+x2)/2, y:(y1+y2)/2};

  const tick = () => {
    step++;
    const prog = step / steps;
    let cx, cy;
    if(via && prog < .5){
      const p = prog * 2;
      cx = x1 + (mid.x - x1)*p;
      cy = y1 + (mid.y - y1)*p;
    } else {
      const p = via ? (prog - .5)*2 : prog;
      const sx = via ? mid.x : x1;
      const sy = via ? mid.y : y1;
      cx = sx + (x2-sx)*p;
      cy = sy + (y2-sy)*p;
    }
    g.setAttribute('transform',
      `translate(${cx-w/2},${cy-8})`);
    if(step < steps) requestAnimationFrame(tick);
    else {
      g.remove();
      if(onDone) onDone();
    }
  };
  requestAnimationFrame(tick);
}

// ── flash a node ─────────────────────────────────────────
function flash(nodeId, cls){
  const el = document.getElementById('node-'+nodeId);
  if(!el) return;
  el.classList.add(cls);
  setTimeout(()=>el.classList.remove(cls), 500);
}

// ── add log entry ────────────────────────────────────────
const logList = document.getElementById('log-list');
function addLog(cls, badge, badgeCls, main, detail){
  const el = document.createElement('div');
  el.className = `log-item ${cls}`;
  const ts = new Date().toLocaleTimeString();
  el.innerHTML =
    `<div><span class="log-time">${ts}</span> ` +
    `<span class="log-badge ${badgeCls}">${badge}</span>` +
    `<span style="font-size:10px;">${main}</span></div>` +
    (detail ? `<div class="log-detail">${detail}</div>` : '');
  logList.prepend(el);
  while(logList.children.length > MAX_LOG)
    logList.removeChild(logList.lastChild);
}

// ── set stat helper ───────────────────────────────────────
function ss(id,v){
  const el=document.getElementById(id);
  if(el) el.textContent=v;
}

// ── SSE handler ───────────────────────────────────────────
const es = new EventSource('/stream2');
es.onmessage = e => {
  const ev = JSON.parse(e.data);
  const d  = ev.data;
  if(!d || !ev.type) return;

  if(ev.type === 'frame'){
    // determine source node
    const src = d.from; // BMS, MOTOR, OBC
    const sn  = NODE[src];
    const gw  = NODE.GW;
    const pl  = NODE.PLANNING;

    flash(src.toLowerCase(), 'flash-green');

    if(d.status === 'accept'){
      // ECU -> bus -> GW -> planning
      animPacket(sn.x, sn.y, gw.x, BUS_Y,
        d.color, d.can_id, ()=>{
          flash('gw','flash-green');
          animPacket(gw.x, gw.y, pl.x, pl.y,
            d.color, 'PASS', ()=>{
              flash('plan','flash-green');
            });
        }, {x: sn.x, y: BUS_Y});

      addLog('accept','ACCEPT','badge-ok',
        ` [${d.from}] ${d.can_id} mac=${d.mac}`,
        d.detail);
    } else {
      // rejected at gateway
      animPacket(sn.x, sn.y, gw.x, BUS_Y,
        '#ef4444', d.can_id, ()=>{
          flash('gw','flash-red');
        }, {x: sn.x, y: BUS_Y});
      addLog('reject','REJECT','badge-no',
        ` [${d.from}] ${d.can_id}`,
        d.reason);
    }
  }

  else if(ev.type === 'attack'){
    const atk = NODE.ATTACKER;
    const gw  = NODE.GW;
    flash('atk','flash-red');
    flash('atk-bus','flash-red');

    // animate attack packet to GW, stops there
    let targetNode;
    if(d.target==='BMS') targetNode = NODE.BMS;
    else if(d.target==='MOTOR') targetNode = NODE.MOTOR;
    else if(d.target==='OBC') targetNode = NODE.OBC;
    else targetNode = gw;

    animPacket(atk.x, atk.y,
      targetNode.x, BUS_Y,
      d.color, 'ATK', ()=>{
        flash('gw','flash-red');
        // show X marker briefly
        showBlock(gw.x, gw.y);
      }, {x: atk.x, y: BUS_Y});

    addLog('attack','ATTACK','badge-atk',
      ` ${d.type} → ${d.target}`,
      `${d.detail} | blocked: ${d.reason}`);
  }

  else if(ev.type === 'tcu'){
    flash('tcu','flash-amber');
    flash('wifi','flash-red');
    const w = NODE.WIFI;
    const t = NODE.TCU;
    animPacket(w.x, w.y, t.x, t.y,
      '#f59e0b', 'OTA', ()=>{
        showBlock(t.x, t.y);
      });
    addLog('tcu','TCU BLK','badge-tcu',
      ` Rogue OTA from ${d.source}`, d.reason);
  }

  else if(ev.type === 'rotation'){
    flash('kms','flash-amber');
    addLog('rotation','KEY ROT','badge-rot',
      ` epoch ${d.old} → ${d.new}`,
      'zero frame loss confirmed');
  }

  else if(ev.type === 'stats'){
    ss('s-acc',  d.accepted);
    ss('s-rej',  d.rejected);
    ss('s-atk',  d.attacks);
    ss('s-tcu',  d.tcu_blocked);
    ss('s-mac',  d.mac_fail);
    ss('s-rep',  d.replay_fail);
    ss('s-epoch',d.epoch);
    ss('s-rot',  d.rotations);
    ss('s-bf',   d.bms_frames);
    ss('s-mf',   d.motor_frames);
    ss('s-of',   d.obc_frames);
    ss('bms-v',  d.voltage + ' V');
    ss('bms-t',  d.temp + ' °C');
    ss('bms-s',  d.soc + '%');
    const bar = document.getElementById('soc-bar');
    if(bar) bar.style.width = d.soc + '%';
  }
};

// ── show blocked X marker ─────────────────────────────────
function showBlock(cx, cy){
  const svg = document.getElementById('canvas');
  const g   = document.createElementNS(
    'http://www.w3.org/2000/svg','g');
  g.innerHTML = `
    <circle cx="${cx}" cy="${cy}" r="14"
            fill="rgba(239,68,68,.2)"
            stroke="#ef4444" stroke-width="1.5"/>
    <text x="${cx}" y="${cy+5}"
          fill="#ef4444" font-size="16"
          text-anchor="middle" font-weight="700">✕</text>`;
  svg.appendChild(g);
  setTimeout(()=>g.remove(), 700);
}

// ── manual attack trigger ─────────────────────────────────
function triggerAtk(type){
  fetch('/trigger?type='+type);
}
</script>
</body>
</html>"""

triggered_attack = {"type": None}

@app.route('/trigger')
def trigger():
    from flask import request
    t = request.args.get('type','bms_spoof')
    triggered_attack["type"] = t
    return "ok"

@app.route('/')
def index():
    return render_template_string(HTML)

@app.route('/stream2')
def stream2():
    def gen():
        while True:
            try:
                ev = eq.get(timeout=30)
                yield f"data: {json.dumps(ev)}\n\n"
            except queue.Empty:
                yield "data: {}\n\n"
    return Response(gen(), mimetype='text/event-stream',
                    headers={'Cache-Control':'no-cache',
                             'X-Accel-Buffering':'no'})

if __name__ == '__main__':
    mode = "real modules" if REAL else "mock simulation"
    print(f"\n SecureEV Network Dashboard — {mode}")
    print(f" Open: http://localhost:5001\n")
    t = threading.Thread(target=sim_loop, daemon=True)
    t.start()
    app.run(debug=False, threaded=True, port=5001)
