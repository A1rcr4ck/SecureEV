"""
SecureEV Animated Network Dashboard v3
Copy to your secureev project root and run:
    pip install flask
    python3 dashboard3.py
Open: http://localhost:5002
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

counters = {"bms":0,"motor":0,"obc":0}
gstats   = {"accepted":0,"rejected":0,"tcu_blocked":0,
            "epoch":0,"rotations":0,"attacks":0,
            "mac_fail":0,"replay_fail":0}
bms_data = {"voltage":400.0,"temp":35.0,"soc":85}
pending_atk = {"type": None}
sim_speed = {"delay": 0.9}

def push(t, d):
    eq.put({"type":t,"data":d})

def sim_loop():
    if REAL:
        real_loop()
    else:
        mock_loop()

def real_loop():
    bus   = VirtualBus()
    kms   = KMS(MASTER_KEY, rotation_interval=20)
    gw    = GatewayECU(kms)
    bms   = BMSECU(kms, bus)
    motor = MotorECU(kms, bus)
    obc   = OBCECU(kms, bus, charger_allowlist=[0x01,0x02])
    tcu   = TCU(kms, gw)
    atk   = Attacker(bus)
    step  = 0
    last_frame = [None]

    while True:
        time.sleep(sim_speed["delay"])
        step += 1
        pt = pending_atk["type"]
        if pt:
            pending_atk["type"] = None

        v = round(400 + (random.random()-0.5)*4, 1)
        t = round(35  + (random.random()-0.5)*2, 1)
        s = max(72, min(95, bms_data["soc"] + (-1 if random.random()<0.3 else 0)))
        bms_data.update({"voltage":v,"temp":t,"soc":s})

        f = bms.transmit(v, t, s)
        last_frame[0] = f
        counters["bms"] += 1
        if gw.receive(f):
            gstats["accepted"] += 1
            push("frame",{"from":"BMS","status":"accept",
                "can_id":"0x100","counter":f.counter,
                "mac":f.mac.hex(),
                "detail":f"V={v} T={t}°C SOC={s}%",
                "color":"#22c55e"})

        if step % 2 == 0:
            f2 = motor.transmit(150+random.uniform(-5,5), 1200, 3)
            counters["motor"] += 1
            if gw.receive(f2):
                gstats["accepted"] += 1
                push("frame",{"from":"MOTOR","status":"accept",
                    "can_id":"0x200","counter":f2.counter,
                    "mac":f2.mac.hex(),
                    "detail":"torque=150Nm speed=1200RPM",
                    "color":"#38bdf8"})

        if step % 5 == 0:
            f3 = obc.transmit(16000, 0x01, 0x01)
            counters["obc"] += 1
            if f3 and gw.receive(f3):
                gstats["accepted"] += 1
                push("frame",{"from":"OBC","status":"accept",
                    "can_id":"0x300","counter":f3.counter,
                    "mac":f3.mac.hex(),
                    "detail":"16000mA charger=0x01",
                    "color":"#f59e0b"})

        if step % 12 == 0:
            old_ep = kms.get_epoch()
            kms.rotate()
            gstats["epoch"]     = kms.get_epoch()
            gstats["rotations"] = len(kms.get_rotation_log())
            push("rotation",{"old":old_ep,"new":kms.get_epoch()})

        atk_type = pt if pt else ("auto" if step % 7 == 0 else None)
        if atk_type:
            _do_attack(atk, gw, last_frame[0], atk_type)

        if step % 11 == 0:
            tcu.receive_wireless("ota",b'malware',"rogue")
            gstats["tcu_blocked"] = tcu.blocked
            push("tcu",{"source":"rogue_server","reason":"unsigned payload"})

        push("stats",{**gstats,**bms_data,
             "bms_frames":counters["bms"],
             "motor_frames":counters["motor"],
             "obc_frames":counters["obc"]})

def _do_attack(atk, gw, last_frame, atk_type):
    gstats["attacks"] += 1
    choices = ["bms","dbw","replay","flood"]
    t = atk_type if atk_type != "auto" else random.choice(choices)

    if t == "bms":
        af = atk.bms_spoof(999.9, 200.0, 0)
        gw.receive(af)
        gstats["rejected"] += 1
        gstats["mac_fail"] += 1
        push("attack",{"type":"BMS Spoof","from":"BMS",
            "detail":"V=999.9 T=200°C","reason":"mac_failure","color":"#ef4444"})

    elif t == "dbw":
        af = atk.drive_by_wire_inject(500.0,3000,3)
        gw.receive(af)
        gstats["rejected"] += 1
        gstats["mac_fail"] += 1
        push("attack",{"type":"Drive-by-Wire","from":"MOTOR",
            "detail":"torque=500Nm","reason":"mac_failure","color":"#ef4444"})

    elif t == "replay" and last_frame:
        af = atk.replay(last_frame)
        gw.receive(af)
        gstats["rejected"] += 1
        gstats["replay_fail"] += 1
        push("attack",{"type":"Replay","from":"BMS",
            "detail":f"counter={last_frame.counter}",
            "reason":"replay_attack","color":"#f97316"})

    elif t == "flood":
        for _ in range(3):
            af = atk.bms_spoof(0, 0, 0)
            gw.receive(af)
            gstats["rejected"] += 1
            gstats["mac_fail"] += 1
        push("attack",{"type":"CAN Flood","from":"BMS",
            "detail":"3 frames injected","reason":"mac_failure","color":"#ef4444"})

    elif t == "ota":
        gstats["tcu_blocked"] += 1
        gstats["attacks"] -= 1
        push("tcu",{"source":"rogue_server","reason":"unsigned payload"})

def mock_loop():
    step = 0
    soc  = [85]
    MACS = ["a0ed","d81c","b707","fe97","41ab","ceda"]
    rMac = lambda: random.choice(MACS)

    while True:
        time.sleep(sim_speed["delay"])
        step += 1
        pt = pending_atk["type"]
        if pt: pending_atk["type"] = None

        v = round(400 + (random.random()-0.5)*4, 1)
        t = round(35  + (random.random()-0.5)*2, 1)
        soc[0] = max(72, min(95, soc[0]+(-1 if random.random()<0.3 else 0)))
        bms_data.update({"voltage":v,"temp":t,"soc":soc[0]})
        counters["bms"] += 1
        gstats["accepted"] += 1
        push("frame",{"from":"BMS","status":"accept",
            "can_id":"0x100","counter":counters["bms"],
            "mac":rMac(),"detail":f"V={v} T={t}°C SOC={soc[0]}%",
            "color":"#22c55e"})

        if step%2==0:
            counters["motor"] += 1
            gstats["accepted"] += 1
            push("frame",{"from":"MOTOR","status":"accept",
                "can_id":"0x200","counter":counters["motor"],
                "mac":rMac(),"detail":"torque=150Nm speed=1200RPM",
                "color":"#38bdf8"})

        if step%5==0:
            counters["obc"] += 1
            gstats["accepted"] += 1
            push("frame",{"from":"OBC","status":"accept",
                "can_id":"0x300","counter":counters["obc"],
                "mac":rMac(),"detail":"16000mA charger=0x01",
                "color":"#f59e0b"})

        if step%12==0:
            gstats["epoch"]     += 1
            gstats["rotations"] += 1
            push("rotation",{"old":gstats["epoch"]-1,"new":gstats["epoch"]})

        atk_t = pt if pt else ("auto" if step%7==0 else None)
        if atk_t:
            gstats["attacks"] += 1
            if atk_t == "ota":
                gstats["tcu_blocked"] += 1
                gstats["attacks"]     -= 1
                push("tcu",{"source":"rogue_server","reason":"unsigned payload"})
            else:
                choices = [
                    ("BMS Spoof","BMS","V=999.9 T=200°C","mac_failure","#ef4444"),
                    ("Drive-by-Wire","MOTOR","torque=500Nm","mac_failure","#ef4444"),
                    ("Replay","BMS",f"counter={counters['bms']-1}","replay_attack","#f97316"),
                    ("CAN Flood","BMS","3 frames","mac_failure","#ef4444"),
                ]
                c = random.choice(choices) if atk_t=="auto" else choices[{"bms":0,"dbw":1,"replay":2,"flood":3}.get(atk_t,0)]
                gstats["rejected"] += 1
                if c[3]=="mac_failure": gstats["mac_fail"]+=1
                else: gstats["replay_fail"]+=1
                push("attack",{"type":c[0],"from":c[1],"detail":c[2],"reason":c[3],"color":c[4]})

        push("stats",{**gstats,**bms_data,
             "bms_frames":counters["bms"],
             "motor_frames":counters["motor"],
             "obc_frames":counters["obc"]})

source = open(__file__).read()
HTML = source.split('HTML_TEMPLATE = """', 1)[1].split('"""', 1)[0]

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/stream3')
def stream3():
    def gen():
        while True:
            try:
                ev = eq.get(timeout=30)
                yield f"data: {json.dumps(ev)}\n\n"
            except queue.Empty:
                yield "data: {}\n\n"
    return Response(gen(), mimetype='text/event-stream',
                    headers={'Cache-Control':'no-cache','X-Accel-Buffering':'no'})

@app.route('/atk')
def trigger_atk():
    from flask import request
    pending_atk["type"] = request.args.get('t','bms')
    return "ok"

@app.route('/speed')
def set_speed():
    from flask import request
    try:
        v = float(request.args.get('v', 900)) / 1000.0
        sim_speed["delay"] = max(0.2, min(2.0, v))
    except ValueError:
        pass
    return "ok"

# HTML_START
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SecureEV Network Dashboard</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#080c18;color:#c8d8f0;font-family:'Courier New',monospace;display:flex;flex-direction:column;height:100vh;overflow:hidden}
.hdr{display:flex;align-items:center;justify-content:space-between;padding:10px 18px;background:#0b1020;border-bottom:1px solid #1a2f50;flex-shrink:0}
.hdr-title{font-size:14px;font-weight:700;color:#5bc4f5;letter-spacing:3px}
.hdr-sub{font-size:10px;color:#3a6080;margin-top:1px}
.dot{width:7px;height:7px;border-radius:50%;background:#22c55e;box-shadow:0 0 6px #22c55e;animation:blink 1.4s infinite;display:inline-block;margin-right:5px}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.2}}
.main{display:flex;flex:1;overflow:hidden}
.sb{width:200px;flex-shrink:0;background:#0b1020;border-right:1px solid #1a2f50;display:flex;flex-direction:column;padding:10px;gap:6px;overflow:hidden}
.canvas{flex:1;position:relative;overflow:hidden;background:#080c18}
svg#topo{width:100%;height:100%}
.log-panel{width:240px;flex-shrink:0;background:#0b1020;border-left:1px solid #1a2f50;display:flex;flex-direction:column;overflow:hidden}
.sb-title{font-size:9px;color:#3a6080;letter-spacing:1px;padding-bottom:5px;border-bottom:1px solid #1a2f50}
.stat{display:flex;justify-content:space-between;font-size:11px;align-items:center}
.stat-key{color:#4a7fa8}.stat-val{font-weight:700;font-size:12px}
.green{color:#22c55e}.red{color:#ef4444}.amber{color:#f59e0b}.purple{color:#a78bfa}.blue{color:#38bdf8}
.sensor{background:#0d1526;border:1px solid #1a2f50;border-radius:5px;padding:8px}
.sl{font-size:9px;color:#3a6080;margin-bottom:4px}
.sv{font-size:11px;font-weight:700}
.bar{height:4px;background:#111827;border-radius:2px;margin-top:3px;overflow:hidden}
.bar-fill{height:100%;border-radius:2px;background:#22c55e;transition:width .5s}
.atk-btn{width:100%;padding:5px 8px;font-size:10px;font-family:'Courier New',monospace;background:#1a0808;border:1px solid #3a1515;border-radius:4px;color:#ef4444;cursor:pointer;text-align:left}
.atk-btn:hover{background:#2a1010}
.atk-btn.tcu{color:#f59e0b;background:#1a1000;border-color:#3a2a00}
.atk-btn.tcu:hover{background:#2a1a00}
.log-hdr{padding:8px 10px;font-size:9px;color:#3a6080;border-bottom:1px solid #1a2f50;letter-spacing:1px;flex-shrink:0}
.log-list{flex:1;overflow-y:auto;padding:5px;display:flex;flex-direction:column;gap:3px}
.log-list::-webkit-scrollbar{width:3px}
.log-list::-webkit-scrollbar-thumb{background:#1a2f50;border-radius:2px}
.le{font-size:10px;padding:4px 6px;border-radius:3px;border-left:2px solid;animation:fin .2s ease}
@keyframes fin{from{opacity:0;transform:translateY(-2px)}to{opacity:1;transform:none}}
.le-ok{background:rgba(34,197,94,.07);border-color:#22c55e;color:#22c55e}
.le-atk{background:rgba(239,68,68,.1);border-color:#ef4444;color:#ef4444}
.le-tcu{background:rgba(245,158,11,.08);border-color:#f59e0b;color:#f59e0b}
.le-rot{background:rgba(167,139,250,.08);border-color:#a78bfa;color:#a78bfa}
.le-det{color:#6a8aaa;font-size:9px;margin-top:2px}
.speed-row{display:flex;align-items:center;gap:6px;padding:6px 10px;border-top:1px solid #1a2f50;font-size:10px;color:#3a6080;flex-shrink:0}
.speed-row input{flex:1;accent-color:#5bc4f5}
</style>
</head>
<body>
<div class="hdr">
  <div>
    <div class="hdr-title">SECUREEV — NETWORK SIMULATION</div>
    <div class="hdr-sub">Authenticated CAN · TCU Trust Boundary · Gateway Enforcement</div>
  </div>
  <div style="font-size:11px;color:#3a6080"><span class="dot"></span><span id="clk">—</span></div>
</div>
<div class="main">
<div class="sb">
  <div class="sb-title">Gateway stats</div>
  <div class="stat"><span class="stat-key">Accepted</span><span class="stat-val green" id="s-acc">0</span></div>
  <div class="stat"><span class="stat-key">Rejected</span><span class="stat-val red" id="s-rej">0</span></div>
  <div class="stat"><span class="stat-key">Attacks</span><span class="stat-val amber" id="s-atk">0</span></div>
  <div class="stat"><span class="stat-key">TCU blocked</span><span class="stat-val amber" id="s-tcu">0</span></div>
  <div class="stat"><span class="stat-key">MAC failures</span><span class="stat-val red" id="s-mac">0</span></div>
  <div class="stat"><span class="stat-key">Replay blocks</span><span class="stat-val red" id="s-rep">0</span></div>
  <div class="sb-title" style="margin-top:4px">KMS</div>
  <div class="stat"><span class="stat-key">Epoch</span><span class="stat-val purple" id="s-ep">0</span></div>
  <div class="stat"><span class="stat-key">Rotations</span><span class="stat-val purple" id="s-rot">0</span></div>
  <div class="sb-title" style="margin-top:4px">BMS live</div>
  <div class="sensor">
    <div class="sl">Voltage</div><div class="sv green" id="bv">400.0 V</div>
    <div class="sl" style="margin-top:5px">Temperature</div><div class="sv green" id="bt">35.0 °C</div>
    <div class="sl" style="margin-top:5px">State of charge</div><div class="sv green" id="bs">85%</div>
    <div class="bar"><div class="bar-fill" id="soc-bar" style="width:85%"></div></div>
  </div>
  <div class="sb-title" style="margin-top:4px">Simulate attack</div>
  <button class="atk-btn" onclick="fetch('/atk?t=bms')">⚡ BMS spoof</button>
  <button class="atk-btn" onclick="fetch('/atk?t=dbw')">🚗 Drive-by-wire</button>
  <button class="atk-btn" onclick="fetch('/atk?t=replay')">🔁 Replay</button>
  <button class="atk-btn" onclick="fetch('/atk?t=flood')">💥 CAN flood</button>
  <button class="atk-btn tcu" onclick="fetch('/atk?t=ota')">📡 Rogue OTA</button>
</div>

<div class="canvas">
<svg id="topo" viewBox="0 0 500 580" preserveAspectRatio="xMidYMid meet">
<defs>
  <marker id="ah" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse">
    <path d="M2 1L8 5L2 9" fill="none" stroke="context-stroke" stroke-width="1.5" stroke-linecap="round"/>
  </marker>
</defs>

<!-- Zone 1: External wireless -->
<rect x="80" y="12" width="340" height="65" rx="8" fill="none" stroke="#7f1d1d" stroke-width="0.5" stroke-dasharray="5 3"/>
<text x="250" y="26" fill="#fca5a5" font-size="9" text-anchor="middle" font-family="Courier New">External wireless — untrusted</text>
<!-- 4G -->
<rect x="90" y="33" width="60" height="34" rx="5" fill="#1a0808" stroke="#7f1d1d" stroke-width="0.5"/>
<text x="120" y="48" fill="#fca5a5" font-size="9" text-anchor="middle" font-family="Courier New" font-weight="700">4G/5G</text>
<text x="120" y="60" fill="#7f1d1d" font-size="8" text-anchor="middle" font-family="Courier New">Cellular</text>
<!-- WiFi -->
<rect x="168" y="33" width="60" height="34" rx="5" fill="#1a0808" stroke="#7f1d1d" stroke-width="0.5"/>
<text x="198" y="48" fill="#fca5a5" font-size="9" text-anchor="middle" font-family="Courier New" font-weight="700">Wi-Fi</text>
<text x="198" y="60" fill="#7f1d1d" font-size="8" text-anchor="middle" font-family="Courier New">OTA</text>
<!-- Attacker -->
<rect x="248" y="33" width="70" height="34" rx="5" fill="#2a0808" stroke="#ef4444" stroke-width="1"/>
<text x="283" y="48" fill="#ef4444" font-size="9" text-anchor="middle" font-family="Courier New" font-weight="700">Attacker</text>
<text x="283" y="60" fill="#7f1d1d" font-size="8" text-anchor="middle" font-family="Courier New">rogue</text>
<!-- Bluetooth -->
<rect x="330" y="33" width="82" height="34" rx="5" fill="#1a0808" stroke="#7f1d1d" stroke-width="0.5"/>
<text x="371" y="48" fill="#fca5a5" font-size="9" text-anchor="middle" font-family="Courier New" font-weight="700">Bluetooth</text>
<text x="371" y="60" fill="#7f1d1d" font-size="8" text-anchor="middle" font-family="Courier New">charging ctrl</text>

<!-- Lines wireless -> TCU -->
<line x1="120" y1="67" x2="228" y2="122" stroke="#7f1d1d" stroke-width="0.5" marker-end="url(#ah)"/>
<line x1="198" y1="67" x2="238" y2="122" stroke="#7f1d1d" stroke-width="0.5" marker-end="url(#ah)"/>
<line x1="283" y1="67" x2="262" y2="122" stroke="#ef4444" stroke-width="0.8" stroke-dasharray="4 2" marker-end="url(#ah)"/>
<line x1="371" y1="67" x2="272" y2="122" stroke="#7f1d1d" stroke-width="0.5" marker-end="url(#ah)"/>

<!-- Zone 2: TCU -->
<rect x="80" y="114" width="340" height="58" rx="8" fill="none" stroke="#78350f" stroke-width="0.8" stroke-dasharray="5 3"/>
<text x="185" y="128" fill="#fcd34d" font-size="9" text-anchor="middle" font-family="Courier New">TCU trust boundary — M6</text>
<rect id="node-tcu" x="140" y="132" width="220" height="32" rx="6" fill="#1a1000" stroke="#78350f" stroke-width="1"/>
<text x="250" y="146" fill="#fcd34d" font-size="10" text-anchor="middle" font-family="Courier New" font-weight="700">Telematics Control Unit</text>
<text x="250" y="157" fill="#78350f" font-size="8" text-anchor="middle" font-family="Courier New">Allowlist · OTA validate · Classify</text>
<line x1="250" y1="164" x2="250" y2="206" stroke="#78350f" stroke-width="1" marker-end="url(#ah)"/>
<text x="270" y="190" fill="#78350f" font-size="8" font-family="Courier New">validated only</text>

<!-- Zone 3: Authenticated CAN -->
<rect x="50" y="200" width="400" height="248" rx="10" fill="none" stroke="#0F6E56" stroke-width="0.8" stroke-dasharray="5 3"/>
<text x="150" y="215" fill="#5eead4" font-size="9" font-family="Courier New">Authenticated CAN bus — HMAC-SHA256</text>

<!-- Gateway -->
<rect id="node-gw" x="170" y="222" width="160" height="46" rx="7" fill="#0d201e" stroke="#134e4a" stroke-width="1.5"/>
<text x="250" y="238" fill="#5eead4" font-size="10" text-anchor="middle" font-family="Courier New" font-weight="700">Gateway ECU — M4</text>
<text x="250" y="250" fill="#134e4a" font-size="8" text-anchor="middle" font-family="Courier New">Whitelist · Replay · MAC verify</text>
<text x="250" y="261" fill="#134e4a" font-size="8" text-anchor="middle" font-family="Courier New">Rate limit · Domain isolation</text>

<!-- KMS -->
<rect id="node-kms" x="358" y="226" width="82" height="38" rx="5" fill="#0d1020" stroke="#3b0764" stroke-width="1"/>
<text x="399" y="241" fill="#c4b5fd" font-size="9" text-anchor="middle" font-family="Courier New" font-weight="700">KMS — M5</text>
<text x="399" y="252" fill="#3b0764" font-size="8" text-anchor="middle" font-family="Courier New">HKDF derive</text>
<text x="399" y="261" fill="#3b0764" font-size="8" text-anchor="middle" font-family="Courier New">epoch rotate</text>
<line x1="358" y1="245" x2="330" y2="245" stroke="#3b0764" stroke-width="0.8" stroke-dasharray="3 2" marker-end="url(#ah)"/>
<text x="344" y="255" fill="#3b0764" font-size="7" text-anchor="middle" font-family="Courier New">keys</text>

<!-- CAN bus backbone -->
<line x1="70" y1="315" x2="430" y2="315" stroke="#1a3a5a" stroke-width="1.5" stroke-dasharray="6 4"/>
<text x="250" y="327" fill="#1a3a5a" font-size="8" text-anchor="middle" font-family="Courier New">CAN bus backbone</text>
<line x1="250" y1="268" x2="250" y2="314" stroke="#134e4a" stroke-width="1"/>

<!-- ECU nodes -->
<rect id="node-bms" x="68" y="338" width="100" height="50" rx="6" fill="#0d1a0d" stroke="#166534" stroke-width="1.2"/>
<text x="118" y="356" fill="#22c55e" font-size="10" text-anchor="middle" font-family="Courier New" font-weight="700">BMS — M1</text>
<text x="118" y="368" fill="#166534" font-size="8" text-anchor="middle" font-family="Courier New">0x100 · 10ms</text>
<text x="118" y="380" fill="#166534" font-size="8" text-anchor="middle" font-family="Courier New">V · T · SOC</text>
<line x1="118" y1="338" x2="118" y2="315" stroke="#134e4a" stroke-width="1" marker-end="url(#ah)"/>

<rect id="node-motor" x="188" y="338" width="100" height="50" rx="6" fill="#0a1520" stroke="#1e40af" stroke-width="1.2"/>
<text x="238" y="356" fill="#38bdf8" font-size="10" text-anchor="middle" font-family="Courier New" font-weight="700">Motor — M2</text>
<text x="238" y="368" fill="#1e40af" font-size="8" text-anchor="middle" font-family="Courier New">0x200 · 5ms</text>
<text x="238" y="380" fill="#1e40af" font-size="8" text-anchor="middle" font-family="Courier New">Torque · Speed</text>
<line x1="238" y1="338" x2="238" y2="315" stroke="#134e4a" stroke-width="1" marker-end="url(#ah)"/>

<rect id="node-obc" x="308" y="338" width="100" height="50" rx="6" fill="#1a1200" stroke="#78350f" stroke-width="1.2"/>
<text x="358" y="356" fill="#f59e0b" font-size="10" text-anchor="middle" font-family="Courier New" font-weight="700">OBC — M3</text>
<text x="358" y="368" fill="#78350f" font-size="8" text-anchor="middle" font-family="Courier New">0x300 · 100ms</text>
<text x="358" y="380" fill="#78350f" font-size="8" text-anchor="middle" font-family="Courier New">Charging</text>
<line x1="358" y1="338" x2="358" y2="315" stroke="#134e4a" stroke-width="1" marker-end="url(#ah)"/>

<!-- Frame format legend -->
<rect x="58" y="400" width="270" height="34" rx="5" fill="#0a0f1e" stroke="#1a3a5a" stroke-width="0.5"/>
<text x="70" y="413" fill="#3a6080" font-size="8" font-family="Courier New">CAN frame (8 bytes)</text>
<rect x="66" y="418" width="58" height="11" rx="2" fill="#1e3a5f"/>
<text x="95" y="426" fill="#5bc4f5" font-size="7" text-anchor="middle" font-family="Courier New" font-weight="700">COUNTER 2B</text>
<rect x="128" y="418" width="88" height="11" rx="2" fill="#134e4a"/>
<text x="172" y="426" fill="#5eead4" font-size="7" text-anchor="middle" font-family="Courier New" font-weight="700">PAYLOAD 4B</text>
<rect x="220" y="418" width="48" height="11" rx="2" fill="#2e1065"/>
<text x="244" y="426" fill="#c4b5fd" font-size="7" text-anchor="middle" font-family="Courier New" font-weight="700">MAC 2B</text>

<!-- Arrow to planning -->
<line x1="250" y1="448" x2="250" y2="470" stroke="#2e1065" stroke-width="1" marker-end="url(#ah)"/>
<text x="272" y="463" fill="#2e1065" font-size="8" font-family="Courier New">auth only</text>

<!-- Zone 4: Planning -->
<rect x="50" y="470" width="400" height="50" rx="8" fill="none" stroke="#2e1065" stroke-width="0.8" stroke-dasharray="5 3"/>
<text x="250" y="485" fill="#a78bfa" font-size="9" text-anchor="middle" font-family="Courier New">Autonomous planning stack</text>
<rect id="node-plan" x="100" y="490" width="300" height="24" rx="5" fill="#12082a" stroke="#2e1065" stroke-width="1"/>
<text x="250" y="506" fill="#c4b5fd" font-size="10" text-anchor="middle" font-family="Courier New" font-weight="700">Perception · Path planning · Control</text>

<!-- Moving packets -->
<g id="pkts"></g>

<!-- Block marker (hidden) -->
<g id="blk" opacity="0">
  <circle id="blk-c" cx="250" cy="245" r="16" fill="none" stroke="#ef4444" stroke-width="1.5"/>
  <text id="blk-x" x="250" y="251" fill="#ef4444" font-size="18" text-anchor="middle" font-family="Courier New" font-weight="700">✕</text>
</g>
</svg>
</div>

<div class="log-panel">
  <div class="log-hdr">Event log</div>
  <div class="log-list" id="log"></div>
  <div class="speed-row">
    Speed
    <input type="range" min="400" max="2000" value="900" id="spd" oninput="setSp(this.value)">
    <span id="spd-lbl" style="min-width:28px;text-align:right">1×</span>
  </div>
</div>
</div>

<script>
const $ = id=>document.getElementById(id);
const ss = (id,v)=>{const e=$(id);if(e)e.textContent=v};
const N={TCU:{x:250,y:148},GW:{x:250,y:245},BMS:{x:118,y:363},MOTOR:{x:238,y:363},
         OBC:{x:358,y:363},KMS:{x:399,y:245},PLAN:{x:250,y:502},BUS:{x:250,y:315},
         WIFI:{x:198,y:50},ATK:{x:283,y:50}};
let spd=900;

setInterval(()=>ss('clk',new Date().toLocaleTimeString()),1000);
function setSp(v){
  spd=+v;
  ss('spd-lbl', v<550?'2×':v<900?'1.5×':v<1400?'1×':'0.5×');
  clearTimeout(window._spdTimer);
  window._spdTimer = setTimeout(()=>fetch('/speed?v='+v), 120);
}

function animPkt(x1,y1,x2,y2,color,lbl,cb,wp){
  const svg=$('pkts');
  const g=document.createElementNS('http://www.w3.org/2000/svg','g');
  const lw=Math.max(lbl.length*5.5+10,32);
  const r=document.createElementNS('http://www.w3.org/2000/svg','rect');
  r.setAttribute('width',lw);r.setAttribute('height',15);r.setAttribute('rx',3);
  r.setAttribute('fill',color);r.setAttribute('opacity','0.95');
  const t=document.createElementNS('http://www.w3.org/2000/svg','text');
  t.setAttribute('x',lw/2);t.setAttribute('y',11);t.setAttribute('fill','#000');
  t.setAttribute('font-size','7.5');t.setAttribute('font-family','Courier New');
  t.setAttribute('font-weight','700');t.setAttribute('text-anchor','middle');
  t.textContent=lbl;g.appendChild(r);g.appendChild(t);
  g.setAttribute('transform',`translate(${x1-lw/2},${y1-7})`);
  svg.appendChild(g);
  const steps=28;let st=0;
  function tick(){
    st++;const p=st/steps;let cx,cy;
    if(wp&&p<.5){const q=p*2;cx=x1+(wp.x-x1)*q;cy=y1+(wp.y-y1)*q;}
    else{const q=wp?(p-.5)*2:p,sx=wp?wp.x:x1,sy=wp?wp.y:y1;cx=sx+(x2-sx)*q;cy=sy+(y2-sy)*q;}
    g.setAttribute('transform',`translate(${cx-lw/2},${cy-7})`);
    if(st<steps)requestAnimationFrame(tick);else{g.remove();if(cb)cb();}
  }
  requestAnimationFrame(tick);
}

function flashNode(id,color){
  const el=$(id);if(!el)return;
  const os=el.getAttribute('stroke'),ow=el.getAttribute('stroke-width');
  el.setAttribute('stroke',color);el.setAttribute('stroke-width','2.5');
  setTimeout(()=>{el.setAttribute('stroke',os);el.setAttribute('stroke-width',ow);},400);
}

function showBlock(cx,cy){
  const b=$('blk'),bc=$('blk-c'),bx=$('blk-x');
  bc.setAttribute('cx',cx);bc.setAttribute('cy',cy);
  bx.setAttribute('x',cx);bx.setAttribute('y',cy+6);
  b.setAttribute('opacity','1');setTimeout(()=>b.setAttribute('opacity','0'),600);
}

const log=$('log');
function addLog(cls,badge,main,detail){
  const d=document.createElement('div');d.className='le '+cls;
  d.innerHTML=`<div><b>${badge}</b> ${main}</div>`+(detail?`<div class="le-det">${detail}</div>`:'');
  log.prepend(d);while(log.children.length>50)log.removeChild(log.lastChild);
}

const es=new EventSource('/stream3');
es.onmessage=e=>{
  const ev=JSON.parse(e.data);const d=ev.data;if(!d||!ev.type)return;
  if(ev.type==='frame'){
    const src=d.from,sn=N[src],wp={x:sn.x,y:N.BUS.y};
    flashNode('node-'+src.toLowerCase(),'#22c55e');
    if(d.status==='accept'){
      animPkt(sn.x,sn.y,N.GW.x,N.BUS.y,d.color,d.can_id,()=>{
        flashNode('node-gw',d.color);
        animPkt(N.GW.x,N.GW.y,N.PLAN.x,N.PLAN.y,d.color,'PASS',()=>{
          flashNode('node-plan',d.color);});
        addLog('le-ok','ACCEPT',`[${d.from}] ${d.can_id} mac=${d.mac}`,d.detail);
      },wp);
    }
  }
  else if(ev.type==='attack'){
    const sn=N[d.from]||N.BMS;
    animPkt(sn.x,sn.y,N.BUS.x,N.BUS.y,d.color,'ATK',()=>{
      showBlock(N.GW.x,N.GW.y+10);flashNode('node-gw','#ef4444');
      addLog('le-atk','BLOCKED',`${d.type} — ${d.can_id||'0x???'}`,`${d.detail} | ${d.reason}`);
    },{x:sn.x,y:N.BUS.y});
  }
  else if(ev.type==='tcu'){
    flashNode('node-tcu','#f59e0b');
    animPkt(N.WIFI.x,N.WIFI.y,N.TCU.x,N.TCU.y,'#ef4444','OTA',()=>{
      showBlock(N.TCU.x,N.TCU.y);
      addLog('le-tcu','TCU BLOCK',`Rogue OTA from ${d.source}`,d.reason);
    });
  }
  else if(ev.type==='rotation'){
    flashNode('node-kms','#a78bfa');
    animPkt(N.KMS.x,N.KMS.y,N.GW.x,N.GW.y,'#a78bfa','KEY',()=>{
      flashNode('node-gw','#a78bfa');
      addLog('le-rot','KEY ROT',`epoch ${d.old} → ${d.new}`,'zero frame loss — previous-epoch fallback active');
    });
  }
  else if(ev.type==='stats'){
    ss('s-acc',d.accepted);ss('s-rej',d.rejected);ss('s-atk',d.attacks);
    ss('s-tcu',d.tcu_blocked);ss('s-mac',d.mac_fail);ss('s-rep',d.replay_fail);
    ss('s-ep',d.epoch);ss('s-rot',d.rotations);
    ss('bv',d.voltage.toFixed(1)+' V');ss('bt',d.temp.toFixed(1)+' °C');ss('bs',d.soc+'%');
    $('soc-bar').style.width=d.soc+'%';
  }
};
</script>
</body>
</html>"""
# HTML_END

if __name__ == '__main__':
    mode = "real modules" if REAL else "mock simulation"
    print(f"\n SecureEV Network Dashboard v3 — {mode}")
    print(f" Open: http://localhost:5002\n")
    t = threading.Thread(target=sim_loop, daemon=True)
    t.start()
    app.run(debug=False, threaded=True, port=5002)

# """
# SecureEV Animated Network Dashboard v3
# Copy to your secureev project root and run:
#     pip install flask
#     python3 dashboard3.py
# Open: http://localhost:5002
# """

# import sys, os
# sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# from flask import Flask, Response, render_template_string
# import threading, queue, time, json, random

# app = Flask(__name__)
# eq  = queue.Queue()

# try:
#     from bus.virtual_bus import VirtualBus
#     from modules.kms import KMS
#     from modules.bms_ecu import BMSECU
#     from modules.motor_ecu import MotorECU
#     from modules.obc_ecu import OBCECU
#     from modules.gateway_ecu import GatewayECU
#     from modules.tcu import TCU
#     from attacker.attacker import Attacker
#     REAL = True
# except ImportError:
#     REAL = False

# MASTER_KEY = b'secureev_master_key_32bytes!!!!!'

# counters = {"bms":0,"motor":0,"obc":0}
# gstats   = {"accepted":0,"rejected":0,"tcu_blocked":0,
#             "epoch":0,"rotations":0,"attacks":0,
#             "mac_fail":0,"replay_fail":0}
# bms_data = {"voltage":400.0,"temp":35.0,"soc":85}
# pending_atk = {"type": None}
# sim_speed = {"delay": 0.9}

# def push(t, d):
#     eq.put({"type":t,"data":d})

# def sim_loop():
#     if REAL:
#         real_loop()
#     else:
#         mock_loop()

# def real_loop():
#     bus   = VirtualBus()
#     kms   = KMS(MASTER_KEY, rotation_interval=20)
#     gw    = GatewayECU(kms)
#     bms   = BMSECU(kms, bus)
#     motor = MotorECU(kms, bus)
#     obc   = OBCECU(kms, bus, charger_allowlist=[0x01,0x02])
#     tcu   = TCU(kms, gw)
#     atk   = Attacker(bus)
#     step  = 0
#     last_frame = [None]

#     while True:
#         time.sleep(sim_speed["delay"])
#         step += 1
#         pt = pending_atk["type"]
#         if pt:
#             pending_atk["type"] = None

#         v = round(400 + (random.random()-0.5)*4, 1)
#         t = round(35  + (random.random()-0.5)*2, 1)
#         s = max(72, min(95, bms_data["soc"] + (-1 if random.random()<0.3 else 0)))
#         bms_data.update({"voltage":v,"temp":t,"soc":s})

#         f = bms.transmit(v, t, s)
#         last_frame[0] = f
#         counters["bms"] += 1
#         if gw.receive(f):
#             gstats["accepted"] += 1
#             push("frame",{"from":"BMS","status":"accept",
#                 "can_id":"0x100","counter":f.counter,
#                 "mac":f.mac.hex(),
#                 "detail":f"V={v} T={t}°C SOC={s}%",
#                 "color":"#3dcc83"})

#         if step % 2 == 0:
#             f2 = motor.transmit(150+random.uniform(-5,5), 1200, 3)
#             counters["motor"] += 1
#             if gw.receive(f2):
#                 gstats["accepted"] += 1
#                 push("frame",{"from":"MOTOR","status":"accept",
#                     "can_id":"0x200","counter":f2.counter,
#                     "mac":f2.mac.hex(),
#                     "detail":"torque=150Nm speed=1200RPM",
#                     "color":"#54b4df"})

#         if step % 5 == 0:
#             f3 = obc.transmit(16000, 0x01, 0x01)
#             counters["obc"] += 1
#             if f3 and gw.receive(f3):
#                 gstats["accepted"] += 1
#                 push("frame",{"from":"OBC","status":"accept",
#                     "can_id":"0x300","counter":f3.counter,
#                     "mac":f3.mac.hex(),
#                     "detail":"16000mA charger=0x01",
#                     "color":"#e5a33e"})

#         if step % 12 == 0:
#             old_ep = kms.get_epoch()
#             kms.rotate()
#             gstats["epoch"]     = kms.get_epoch()
#             gstats["rotations"] = len(kms.get_rotation_log())
#             push("rotation",{"old":old_ep,"new":kms.get_epoch()})

#         atk_type = pt if pt else ("auto" if step % 7 == 0 else None)
#         if atk_type:
#             _do_attack(atk, gw, last_frame[0], atk_type)

#         if step % 11 == 0:
#             tcu.receive_wireless("ota",b'malware',"rogue")
#             gstats["tcu_blocked"] = tcu.blocked
#             push("tcu",{"source":"rogue_server","reason":"unsigned payload"})

#         push("stats",{**gstats,**bms_data,
#              "bms_frames":counters["bms"],
#              "motor_frames":counters["motor"],
#              "obc_frames":counters["obc"]})

# def _do_attack(atk, gw, last_frame, atk_type):
#     gstats["attacks"] += 1
#     choices = ["bms","dbw","replay","flood"]
#     t = atk_type if atk_type != "auto" else random.choice(choices)

#     if t == "bms":
#         af = atk.bms_spoof(999.9, 200.0, 0)
#         gw.receive(af)
#         gstats["rejected"] += 1
#         gstats["mac_fail"] += 1
#         push("attack",{"type":"BMS Spoof","from":"BMS",
#             "detail":"V=999.9 T=200°C","reason":"mac_failure","color":"#ef6268"})

#     elif t == "dbw":
#         af = atk.drive_by_wire_inject(500.0,3000,3)
#         gw.receive(af)
#         gstats["rejected"] += 1
#         gstats["mac_fail"] += 1
#         push("attack",{"type":"Drive-by-Wire","from":"MOTOR",
#             "detail":"torque=500Nm","reason":"mac_failure","color":"#ef6268"})

#     elif t == "replay" and last_frame:
#         af = atk.replay(last_frame)
#         gw.receive(af)
#         gstats["rejected"] += 1
#         gstats["replay_fail"] += 1
#         push("attack",{"type":"Replay","from":"BMS",
#             "detail":f"counter={last_frame.counter}",
#             "reason":"replay_attack","color":"#f97316"})

#     elif t == "flood":
#         for _ in range(3):
#             af = atk.bms_spoof(0, 0, 0)
#             gw.receive(af)
#             gstats["rejected"] += 1
#             gstats["mac_fail"] += 1
#         push("attack",{"type":"CAN Flood","from":"BMS",
#             "detail":"3 frames injected","reason":"mac_failure","color":"#ef6268"})

#     elif t == "ota":
#         gstats["tcu_blocked"] += 1
#         gstats["attacks"] -= 1
#         push("tcu",{"source":"rogue_server","reason":"unsigned payload"})

# def mock_loop():
#     step = 0
#     soc  = [85]
#     MACS = ["a0ed","d81c","b707","fe97","41ab","ceda"]
#     rMac = lambda: random.choice(MACS)

#     while True:
#         time.sleep(sim_speed["delay"])
#         step += 1
#         pt = pending_atk["type"]
#         if pt: pending_atk["type"] = None

#         v = round(400 + (random.random()-0.5)*4, 1)
#         t = round(35  + (random.random()-0.5)*2, 1)
#         soc[0] = max(72, min(95, soc[0]+(-1 if random.random()<0.3 else 0)))
#         bms_data.update({"voltage":v,"temp":t,"soc":soc[0]})
#         counters["bms"] += 1
#         gstats["accepted"] += 1
#         push("frame",{"from":"BMS","status":"accept",
#             "can_id":"0x100","counter":counters["bms"],
#             "mac":rMac(),"detail":f"V={v} T={t}°C SOC={soc[0]}%",
#             "color":"#3dcc83"})

#         if step%2==0:
#             counters["motor"] += 1
#             gstats["accepted"] += 1
#             push("frame",{"from":"MOTOR","status":"accept",
#                 "can_id":"0x200","counter":counters["motor"],
#                 "mac":rMac(),"detail":"torque=150Nm speed=1200RPM",
#                 "color":"#54b4df"})

#         if step%5==0:
#             counters["obc"] += 1
#             gstats["accepted"] += 1
#             push("frame",{"from":"OBC","status":"accept",
#                 "can_id":"0x300","counter":counters["obc"],
#                 "mac":rMac(),"detail":"16000mA charger=0x01",
#                 "color":"#e5a33e"})

#         if step%12==0:
#             gstats["epoch"]     += 1
#             gstats["rotations"] += 1
#             push("rotation",{"old":gstats["epoch"]-1,"new":gstats["epoch"]})

#         atk_t = pt if pt else ("auto" if step%7==0 else None)
#         if atk_t:
#             gstats["attacks"] += 1
#             if atk_t == "ota":
#                 gstats["tcu_blocked"] += 1
#                 gstats["attacks"]     -= 1
#                 push("tcu",{"source":"rogue_server","reason":"unsigned payload"})
#             else:
#                 choices = [
#                     ("BMS Spoof","BMS","V=999.9 T=200°C","mac_failure","#ef6268"),
#                     ("Drive-by-Wire","MOTOR","torque=500Nm","mac_failure","#ef6268"),
#                     ("Replay","BMS",f"counter={counters['bms']-1}","replay_attack","#f97316"),
#                     ("CAN Flood","BMS","3 frames","mac_failure","#ef6268"),
#                 ]
#                 c = random.choice(choices) if atk_t=="auto" else choices[{"bms":0,"dbw":1,"replay":2,"flood":3}.get(atk_t,0)]
#                 gstats["rejected"] += 1
#                 if c[3]=="mac_failure": gstats["mac_fail"]+=1
#                 else: gstats["replay_fail"]+=1
#                 push("attack",{"type":c[0],"from":c[1],"detail":c[2],"reason":c[3],"color":c[4]})

#         push("stats",{**gstats,**bms_data,
#              "bms_frames":counters["bms"],
#              "motor_frames":counters["motor"],
#              "obc_frames":counters["obc"]})

# source = open(__file__).read()
# HTML = source.split('HTML_TEMPLATE = """', 1)[1].split('"""', 1)[0]

# @app.route('/')
# def index():
#     return render_template_string(HTML_TEMPLATE)

# @app.route('/stream3')
# def stream3():
#     def gen():
#         while True:
#             try:
#                 ev = eq.get(timeout=30)
#                 yield f"data: {json.dumps(ev)}\n\n"
#             except queue.Empty:
#                 yield "data: {}\n\n"
#     return Response(gen(), mimetype='text/event-stream',
#                     headers={'Cache-Control':'no-cache','X-Accel-Buffering':'no'})

# @app.route('/atk')
# def trigger_atk():
#     from flask import request
#     pending_atk["type"] = request.args.get('t','bms')
#     return "ok"

# @app.route('/speed')
# def set_speed():
#     from flask import request
#     try:
#         v = float(request.args.get('v', 900)) / 1000.0
#         sim_speed["delay"] = max(0.2, min(2.0, v))
#     except ValueError:
#         pass
#     return "ok"

# # HTML_START
# HTML_TEMPLATE = """<!DOCTYPE html>
# <html lang="en">
# <head>
# <meta charset="UTF-8">
# <title>SecureEV Network Dashboard</title>
# <style>
# *{box-sizing:border-box;margin:0;padding:0}
# body{
#   background:#111b28;color:#d7e2ec;font-family:'Segoe UI',Arial,sans-serif;
#   display:flex;flex-direction:column;height:100vh;overflow:hidden
# }
# .hdr{
#   display:flex;align-items:center;justify-content:space-between;padding:13px 22px;
#   background:#172b40;border-bottom:2px solid #2e668d;flex-shrink:0
# }
# .hdr-title{font-size:19px;font-weight:700;color:#f4f8fb;letter-spacing:2px}
# .hdr-sub{font-size:11px;color:#9fb7c9;margin-top:3px}
# .dot{
#   width:8px;height:8px;border-radius:50%;background:#36b879;
#   box-shadow:0 0 5px rgba(54,184,121,.35);animation:blink 1.4s infinite;
#   display:inline-block;margin-right:7px
# }
# @keyframes blink{0%,100%{opacity:1}50%{opacity:.4}}
# .main{display:flex;flex:1;overflow:hidden}
# .sb{
#   width:225px;flex-shrink:0;background:#162333;border-right:1px solid #294054;
#   display:flex;flex-direction:column;padding:12px;gap:7px;overflow:hidden
# }
# .canvas{flex:1;position:relative;overflow:hidden;background:#101a27}
# svg#topo{width:100%;height:100%}
# .log-panel{
#   width:285px;flex-shrink:0;background:#162333;border-left:1px solid #294054;
#   display:flex;flex-direction:column;overflow:hidden
# }
# .sb-title{
#   font-size:11px;color:#8ea9bd;letter-spacing:1px;padding-bottom:6px;
#   border-bottom:1px solid #294054
# }
# .stat{display:flex;justify-content:space-between;font-size:13px;align-items:center}
# .stat-key{color:#a9bdcd}.stat-val{font-weight:700;font-size:14px}
# .green{color:#3dcc83}.red{color:#ff6464}.amber{color:#e9ad45}.purple{color:#b497e7}.blue{color:#54b4df}
# .sensor{background:#1b2b3c;border:1px solid #344b60;border-radius:6px;padding:9px}
# .sl{font-size:10px;color:#8da5b8;margin-bottom:4px}.sv{font-size:13px;font-weight:700}
# .bar{height:5px;background:#304456;border-radius:3px;margin-top:4px;overflow:hidden}.bar-fill{height:100%;border-radius:3px;background:#35b978;transition:width .5s}
# .atk-btn{
#   width:100%;padding:7px 9px;font-size:11px;font-family:'Segoe UI',Arial,sans-serif;
#   background:#2a2026;border:1px solid #70434d;border-radius:5px;color:#ff8c8c;
#   cursor:pointer;text-align:left
# }
# .atk-btn:hover{background:#35242b}
# .atk-btn.tcu{color:#f0bd61;background:#302a20;border-color:#735c35}
# .atk-btn.tcu:hover{background:#3b3020}
# .log-hdr{
#   padding:9px 11px;font-size:11px;color:#8ea9bd;border-bottom:1px solid #294054;
#   letter-spacing:1px;flex-shrink:0
# }
# .log-list{flex:1;overflow-y:auto;padding:6px;display:flex;flex-direction:column;gap:4px}
# .log-list::-webkit-scrollbar{width:5px}.log-list::-webkit-scrollbar-thumb{background:#40576b;border-radius:3px}
# .le{font-size:11px;padding:6px 7px;border-radius:4px;border-left:3px solid;animation:fin .2s ease}
# @keyframes fin{from{opacity:0;transform:translateY(-2px)}to{opacity:1;transform:none}}
# .le-ok{background:#182d29;border-color:#35b978;color:#62d59c}
# .le-atk{background:#332125;border-color:#e45757;color:#ff8c8c}
# .le-tcu{background:#332c20;border-color:#d89a37;color:#f0bd61}
# .le-rot{background:#29253a;border-color:#8063b8;color:#bba1e8}
# .le-det{color:#9db1c1;font-size:10px;margin-top:2px}
# .speed-row{
#   display:flex;align-items:center;gap:6px;padding:7px 11px;border-top:1px solid #294054;
#   font-size:11px;color:#8ea9bd;flex-shrink:0
# }
# .speed-row input{flex:1;accent-color:#4d9ac2}
# </style>
# </head>
# <body>
# <div class="hdr">
#   <div>
#     <div class="hdr-title">SECUREEV — NETWORK SIMULATION</div>
#     <div class="hdr-sub">Authenticated CAN · TCU Trust Boundary · Gateway Enforcement</div>
#   </div>
#   <div style="font-size:11px;color:#9aafc0"><span class="dot"></span><span id="clk">—</span></div>
# </div>
# <div class="main">
# <div class="sb">
#   <div class="sb-title">Gateway stats</div>
#   <div class="stat"><span class="stat-key">Accepted</span><span class="stat-val green" id="s-acc">0</span></div>
#   <div class="stat"><span class="stat-key">Rejected</span><span class="stat-val red" id="s-rej">0</span></div>
#   <div class="stat"><span class="stat-key">Attacks</span><span class="stat-val amber" id="s-atk">0</span></div>
#   <div class="stat"><span class="stat-key">TCU blocked</span><span class="stat-val amber" id="s-tcu">0</span></div>
#   <div class="stat"><span class="stat-key">MAC failures</span><span class="stat-val red" id="s-mac">0</span></div>
#   <div class="stat"><span class="stat-key">Replay blocks</span><span class="stat-val red" id="s-rep">0</span></div>
#   <div class="sb-title" style="margin-top:4px">KMS</div>
#   <div class="stat"><span class="stat-key">Epoch</span><span class="stat-val purple" id="s-ep">0</span></div>
#   <div class="stat"><span class="stat-key">Rotations</span><span class="stat-val purple" id="s-rot">0</span></div>
#   <div class="sb-title" style="margin-top:4px">BMS live</div>
#   <div class="sensor">
#     <div class="sl">Voltage</div><div class="sv green" id="bv">400.0 V</div>
#     <div class="sl" style="margin-top:5px">Temperature</div><div class="sv green" id="bt">35.0 °C</div>
#     <div class="sl" style="margin-top:5px">State of charge</div><div class="sv green" id="bs">85%</div>
#     <div class="bar"><div class="bar-fill" id="soc-bar" style="width:85%"></div></div>
#   </div>
#   <div class="sb-title" style="margin-top:4px">Simulate attack</div>
#   <button class="atk-btn" onclick="fetch('/atk?t=bms')">⚡ BMS spoof</button>
#   <button class="atk-btn" onclick="fetch('/atk?t=dbw')">🚗 Drive-by-wire</button>
#   <button class="atk-btn" onclick="fetch('/atk?t=replay')">🔁 Replay</button>
#   <button class="atk-btn" onclick="fetch('/atk?t=flood')">💥 CAN flood</button>
#   <button class="atk-btn tcu" onclick="fetch('/atk?t=ota')">📡 Rogue OTA</button>
# </div>

# <div class="canvas">
# <svg id="topo" viewBox="0 0 500 580" preserveAspectRatio="xMidYMid meet">
# <defs>
#   <marker id="ah" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse">
#     <path d="M2 1L8 5L2 9" fill="none" stroke="context-stroke" stroke-width="1.5" stroke-linecap="round"/>
#   </marker>
# </defs>

# <!-- Zone 1: External wireless -->
# <rect x="80" y="12" width="340" height="65" rx="8" fill="none" stroke="#b85b64" stroke-width="0.5" stroke-dasharray="5 3"/>
# <text x="250" y="26" fill="#ff9999" font-size="10" text-anchor="middle" font-family="Courier New">External wireless — untrusted</text>
# <!-- 4G -->
# <rect x="90" y="33" width="66" height="38" rx="5" fill="#f2f6fa2f2" stroke="#b85b64" stroke-width="0.5"/>
# <text x="120" y="48" fill="#ff9999" font-size="10" text-anchor="middle" font-family="Courier New" font-weight="700">4G/5G</text>
# <text x="120" y="60" fill="#b85b64" font-size="10" text-anchor="middle" font-family="Courier New">Cellular</text>
# <!-- WiFi -->
# <rect x="168" y="33" width="66" height="38" rx="5" fill="#f2f6fa2f2" stroke="#b85b64" stroke-width="0.5"/>
# <text x="198" y="48" fill="#ff9999" font-size="10" text-anchor="middle" font-family="Courier New" font-weight="700">Wi-Fi</text>
# <text x="198" y="60" fill="#b85b64" font-size="10" text-anchor="middle" font-family="Courier New">OTA</text>
# <!-- Attacker -->
# <rect x="248" y="33" width="76" height="38" rx="5" fill="#332125" stroke="#ef6268" stroke-width="1"/>
# <text x="283" y="48" fill="#ef6268" font-size="10" text-anchor="middle" font-family="Courier New" font-weight="700">Attacker</text>
# <text x="283" y="60" fill="#b85b64" font-size="10" text-anchor="middle" font-family="Courier New">rogue</text>
# <!-- Bluetooth -->
# <rect x="330" y="33" width="88" height="38" rx="5" fill="#f2f6fa2f2" stroke="#b85b64" stroke-width="0.5"/>
# <text x="371" y="48" fill="#ff9999" font-size="10" text-anchor="middle" font-family="Courier New" font-weight="700">Bluetooth</text>
# <text x="371" y="60" fill="#b85b64" font-size="10" text-anchor="middle" font-family="Courier New">charging ctrl</text>

# <!-- Lines wireless -> TCU -->
# <line x1="120" y1="67" x2="228" y2="122" stroke="#b85b64" stroke-width="0.5" marker-end="url(#ah)"/>
# <line x1="198" y1="67" x2="238" y2="122" stroke="#b85b64" stroke-width="0.5" marker-end="url(#ah)"/>
# <line x1="283" y1="67" x2="262" y2="122" stroke="#ef6268" stroke-width="0.8" stroke-dasharray="4 2" marker-end="url(#ah)"/>
# <line x1="371" y1="67" x2="272" y2="122" stroke="#b85b64" stroke-width="0.5" marker-end="url(#ah)"/>

# <!-- Zone 2: TCU -->
# <rect x="80" y="114" width="340" height="58" rx="8" fill="none" stroke="#b77a25" stroke-width="0.8" stroke-dasharray="5 3"/>
# <text x="185" y="128" fill="#e6ad4e" font-size="10" text-anchor="middle" font-family="Courier New">TCU trust boundary — M6</text>
# <rect id="node-tcu" x="140" y="132" width="240" height="36" rx="6" fill="#f2f6fa7e6" stroke="#b77a25" stroke-width="1"/>
# <text x="250" y="146" fill="#e6ad4e" font-size="11.5" text-anchor="middle" font-family="Courier New" font-weight="700">Telematics Control Unit</text>
# <text x="250" y="157" fill="#b77a25" font-size="10" text-anchor="middle" font-family="Courier New">Allowlist · OTA validate · Classify</text>
# <line x1="250" y1="164" x2="250" y2="206" stroke="#b77a25" stroke-width="1" marker-end="url(#ah)"/>
# <text x="270" y="190" fill="#b77a25" font-size="10" font-family="Courier New">validated only</text>

# <!-- Zone 3: Authenticated CAN -->
# <rect x="50" y="200" width="400" height="248" rx="10" fill="none" stroke="#3b9b82" stroke-width="0.8" stroke-dasharray="5 3"/>
# <text x="150" y="215" fill="#5bc3a3" font-size="10" font-family="Courier New">Authenticated CAN bus — HMAC-SHA256</text>

# <!-- Gateway -->
# <rect id="node-gw" x="160" y="219" width="185" height="62" rx="7" fill="#1d302e" stroke="#3b9b82" stroke-width="1.5"/>
# <text x="252.5" y="235" fill="#5bc3a3" font-size="11.5" text-anchor="middle" font-family="Courier New" font-weight="700">Gateway ECU — M4</text>
# <text x="252.5" y="248" fill="#3b9b82" font-size="9" text-anchor="middle" font-family="Courier New">Whitelist · Replay</text>
# <text x="252.5" y="259" fill="#3b9b82" font-size="9" text-anchor="middle" font-family="Courier New">MAC verification</text>
# <text x="252.5" y="270" fill="#3b9b82" font-size="9" text-anchor="middle" font-family="Courier New">Rate limit · Domain isolation</text>

# <!-- KMS -->
# <rect id="node-kms" x="365" y="223" width="78" height="42" rx="5" fill="#2b2639" stroke="#ad8ee1" stroke-width="1"/>
# <text x="404" y="237" fill="#ad8ee1" font-size="10" text-anchor="middle" font-family="Courier New" font-weight="700">KMS — M5</text>
# <text x="404" y="249" fill="#ad8ee1" font-size="10" text-anchor="middle" font-family="Courier New">HKDF derive</text>
# <text x="404" y="260" fill="#ad8ee1" font-size="10" text-anchor="middle" font-family="Courier New">epoch rotate</text>
# <line x1="365" y1="244" x2="345" y2="244" stroke="#ad8ee1" stroke-width="0.8" stroke-dasharray="3 2" marker-end="url(#ah)"/>
# <text x="355" y="254" fill="#ad8ee1" font-size="9.5" text-anchor="middle" font-family="Courier New">keys</text>

# <!-- CAN bus backbone -->
# <line x1="70" y1="315" x2="430" y2="315" stroke="#8ea7bb" stroke-width="1.5" stroke-dasharray="6 4"/>
# <text x="250" y="327" fill="#8ea7bb" font-size="10" text-anchor="middle" font-family="Courier New">CAN bus backbone</text>
# <line x1="250" y1="268" x2="250" y2="314" stroke="#3b9b82" stroke-width="1"/>

# <!-- ECU nodes -->
# <rect id="node-bms" x="68" y="338" width="108" height="56" rx="6" fill="#1c3027" stroke="#45b77b" stroke-width="1.2"/>
# <text x="118" y="356" fill="#3dcc83" font-size="11.5" text-anchor="middle" font-family="Courier New" font-weight="700">BMS — M1</text>
# <text x="118" y="368" fill="#45b77b" font-size="10" text-anchor="middle" font-family="Courier New">0x100 · 10ms</text>
# <text x="118" y="380" fill="#45b77b" font-size="10" text-anchor="middle" font-family="Courier New">V · T · SOC</text>
# <line x1="118" y1="338" x2="118" y2="315" stroke="#3b9b82" stroke-width="1" marker-end="url(#ah)"/>

# <rect id="node-motor" x="188" y="338" width="108" height="56" rx="6" fill="#1e3344" stroke="#5b9bc3" stroke-width="1.2"/>
# <text x="238" y="356" fill="#54b4df" font-size="11.5" text-anchor="middle" font-family="Courier New" font-weight="700">Motor — M2</text>
# <text x="238" y="368" fill="#5b9bc3" font-size="10" text-anchor="middle" font-family="Courier New">0x200 · 5ms</text>
# <text x="238" y="380" fill="#5b9bc3" font-size="10" text-anchor="middle" font-family="Courier New">Torque · Speed</text>
# <line x1="238" y1="338" x2="238" y2="315" stroke="#3b9b82" stroke-width="1" marker-end="url(#ah)"/>

# <rect id="node-obc" x="308" y="338" width="108" height="56" rx="6" fill="#f2f6fa4df" stroke="#b77a25" stroke-width="1.2"/>
# <text x="358" y="356" fill="#e5a33e" font-size="11.5" text-anchor="middle" font-family="Courier New" font-weight="700">OBC — M3</text>
# <text x="358" y="368" fill="#b77a25" font-size="10" text-anchor="middle" font-family="Courier New">0x300 · 100ms</text>
# <text x="358" y="380" fill="#b77a25" font-size="10" text-anchor="middle" font-family="Courier New">Charging</text>
# <line x1="358" y1="338" x2="358" y2="315" stroke="#3b9b82" stroke-width="1" marker-end="url(#ah)"/>

# <!-- Frame format legend -->
# <rect x="58" y="400" width="270" height="34" rx="5" fill="#182737" stroke="#8ea7bb" stroke-width="0.5"/>
# <text x="70" y="413" fill="#9aafc0" font-size="10" font-family="Courier New">CAN frame (8 bytes)</text>
# <rect x="66" y="418" width="58" height="11" rx="2" fill="#203649"/>
# <text x="95" y="426" fill="#54b4df" font-size="9.5" text-anchor="middle" font-family="Courier New" font-weight="700">COUNTER 2B</text>
# <rect x="128" y="418" width="88" height="11" rx="2" fill="#3b9b82"/>
# <text x="172" y="426" fill="#5bc3a3" font-size="9.5" text-anchor="middle" font-family="Courier New" font-weight="700">PAYLOAD 4B</text>
# <rect x="220" y="418" width="48" height="11" rx="2" fill="#9d7bce"/>
# <text x="244" y="426" fill="#ad8ee1" font-size="9.5" text-anchor="middle" font-family="Courier New" font-weight="700">MAC 2B</text>

# <!-- Arrow to planning -->
# <line x1="250" y1="448" x2="250" y2="470" stroke="#9d7bce" stroke-width="1" marker-end="url(#ah)"/>
# <text x="272" y="463" fill="#9d7bce" font-size="10" font-family="Courier New">auth only</text>

# <!-- Zone 4: Planning -->
# <rect x="50" y="470" width="400" height="50" rx="8" fill="none" stroke="#9d7bce" stroke-width="0.8" stroke-dasharray="5 3"/>
# <text x="250" y="485" fill="#ad8ee1" font-size="10" text-anchor="middle" font-family="Courier New">Autonomous planning stack</text>
# <rect id="node-plan" x="100" y="490" width="300" height="24" rx="5" fill="#29253a" stroke="#9d7bce" stroke-width="1"/>
# <text x="250" y="506" fill="#ad8ee1" font-size="11.5" text-anchor="middle" font-family="Courier New" font-weight="700">Perception · Path planning · Control</text>

# <!-- Moving packets -->
# <g id="pkts"></g>

# <!-- Block marker (hidden) -->
# <g id="blk" opacity="0">
#   <circle id="blk-c" cx="250" cy="245" r="16" fill="none" stroke="#ef6268" stroke-width="1.5"/>
#   <text id="blk-x" x="250" y="251" fill="#ef6268" font-size="18" text-anchor="middle" font-family="Courier New" font-weight="700">✕</text>
# </g>
# </svg>
# </div>

# <div class="log-panel">
#   <div class="log-hdr">Event log</div>
#   <div class="log-list" id="log"></div>
#   <div class="speed-row">
#     Speed
#     <input type="range" min="400" max="2000" value="900" id="spd" oninput="setSp(this.value)">
#     <span id="spd-lbl" style="min-width:28px;text-align:right">1×</span>
#   </div>
# </div>
# </div>

# <script>
# const $ = id=>document.getElementById(id);
# const ss = (id,v)=>{const e=$(id);if(e)e.textContent=v};
# const N={TCU:{x:250,y:148},GW:{x:250,y:245},BMS:{x:118,y:363},MOTOR:{x:238,y:363},
#          OBC:{x:358,y:363},KMS:{x:399,y:245},PLAN:{x:250,y:502},BUS:{x:250,y:315},
#          WIFI:{x:198,y:50},ATK:{x:283,y:50}};
# let spd=900;

# setInterval(()=>ss('clk',new Date().toLocaleTimeString()),1000);
# function setSp(v){
#   spd=+v;
#   ss('spd-lbl', v<550?'2×':v<900?'1.5×':v<1400?'1×':'0.5×');
#   clearTimeout(window._spdTimer);
#   window._spdTimer = setTimeout(()=>fetch('/speed?v='+v), 120);
# }

# function animPkt(x1,y1,x2,y2,color,lbl,cb,wp){
#   const svg=$('pkts');
#   const g=document.createElementNS('http://www.w3.org/2000/svg','g');
#   const lw=Math.max(lbl.length*5.5+10,32);
#   const r=document.createElementNS('http://www.w3.org/2000/svg','rect');
#   r.setAttribute('width',lw);r.setAttribute('height',15);r.setAttribute('rx',3);
#   r.setAttribute('fill',color);r.setAttribute('opacity','0.95');
#   const t=document.createElementNS('http://www.w3.org/2000/svg','text');
#   t.setAttribute('x',lw/2);t.setAttribute('y',11);t.setAttribute('fill','#000');
#   t.setAttribute('font-size','7.5');t.setAttribute('font-family','Courier New');
#   t.setAttribute('font-weight','700');t.setAttribute('text-anchor','middle');
#   t.textContent=lbl;g.appendChild(r);g.appendChild(t);
#   g.setAttribute('transform',`translate(${x1-lw/2},${y1-7})`);
#   svg.appendChild(g);
#   const steps=28;let st=0;
#   function tick(){
#     st++;const p=st/steps;let cx,cy;
#     if(wp&&p<.5){const q=p*2;cx=x1+(wp.x-x1)*q;cy=y1+(wp.y-y1)*q;}
#     else{const q=wp?(p-.5)*2:p,sx=wp?wp.x:x1,sy=wp?wp.y:y1;cx=sx+(x2-sx)*q;cy=sy+(y2-sy)*q;}
#     g.setAttribute('transform',`translate(${cx-lw/2},${cy-7})`);
#     if(st<steps)requestAnimationFrame(tick);else{g.remove();if(cb)cb();}
#   }
#   requestAnimationFrame(tick);
# }

# function flashNode(id,color){
#   const el=$(id);if(!el)return;
#   const os=el.getAttribute('stroke'),ow=el.getAttribute('stroke-width');
#   el.setAttribute('stroke',color);el.setAttribute('stroke-width','2.5');
#   setTimeout(()=>{el.setAttribute('stroke',os);el.setAttribute('stroke-width',ow);},400);
# }

# function showBlock(cx,cy){
#   const b=$('blk'),bc=$('blk-c'),bx=$('blk-x');
#   bc.setAttribute('cx',cx);bc.setAttribute('cy',cy);
#   bx.setAttribute('x',cx);bx.setAttribute('y',cy+6);
#   b.setAttribute('opacity','1');setTimeout(()=>b.setAttribute('opacity','0'),600);
# }

# const log=$('log');
# function addLog(cls,badge,main,detail){
#   const d=document.createElement('div');d.className='le '+cls;
#   d.innerHTML=`<div><b>${badge}</b> ${main}</div>`+(detail?`<div class="le-det">${detail}</div>`:'');
#   log.prepend(d);while(log.children.length>50)log.removeChild(log.lastChild);
# }

# const es=new EventSource('/stream3');
# es.onmessage=e=>{
#   const ev=JSON.parse(e.data);const d=ev.data;if(!d||!ev.type)return;
#   if(ev.type==='frame'){
#     const src=d.from,sn=N[src],wp={x:sn.x,y:N.BUS.y};
#     flashNode('node-'+src.toLowerCase(),'#3dcc83');
#     if(d.status==='accept'){
#       animPkt(sn.x,sn.y,N.GW.x,N.BUS.y,d.color,d.can_id,()=>{
#         flashNode('node-gw',d.color);
#         animPkt(N.GW.x,N.GW.y,N.PLAN.x,N.PLAN.y,d.color,'PASS',()=>{
#           flashNode('node-plan',d.color);});
#         addLog('le-ok','ACCEPT',`[${d.from}] ${d.can_id} mac=${d.mac}`,d.detail);
#       },wp);
#     }
#   }
#   else if(ev.type==='attack'){
#     const sn=N[d.from]||N.BMS;
#     animPkt(sn.x,sn.y,N.BUS.x,N.BUS.y,d.color,'ATK',()=>{
#       showBlock(N.GW.x,N.GW.y+10);flashNode('node-gw','#ef6268');
#       addLog('le-atk','BLOCKED',`${d.type} — ${d.can_id||'0x???'}`,`${d.detail} | ${d.reason}`);
#     },{x:sn.x,y:N.BUS.y});
#   }
#   else if(ev.type==='tcu'){
#     flashNode('node-tcu','#e5a33e');
#     animPkt(N.WIFI.x,N.WIFI.y,N.TCU.x,N.TCU.y,'#ef6268','OTA',()=>{
#       showBlock(N.TCU.x,N.TCU.y);
#       addLog('le-tcu','TCU BLOCK',`Rogue OTA from ${d.source}`,d.reason);
#     });
#   }
#   else if(ev.type==='rotation'){
#     flashNode('node-kms','#ad8ee1');
#     animPkt(N.KMS.x,N.KMS.y,N.GW.x,N.GW.y,'#ad8ee1','KEY',()=>{
#       flashNode('node-gw','#ad8ee1');
#       addLog('le-rot','KEY ROT',`epoch ${d.old} → ${d.new}`,'zero frame loss — previous-epoch fallback active');
#     });
#   }
#   else if(ev.type==='stats'){
#     ss('s-acc',d.accepted);ss('s-rej',d.rejected);ss('s-atk',d.attacks);
#     ss('s-tcu',d.tcu_blocked);ss('s-mac',d.mac_fail);ss('s-rep',d.replay_fail);
#     ss('s-ep',d.epoch);ss('s-rot',d.rotations);
#     ss('bv',d.voltage.toFixed(1)+' V');ss('bt',d.temp.toFixed(1)+' °C');ss('bs',d.soc+'%');
#     $('soc-bar').style.width=d.soc+'%';
#   }
# };
# </script>
# </body>
# </html>"""
# # HTML_END

# if __name__ == '__main__':
#     mode = "real modules" if REAL else "mock simulation"
#     print(f"\n SecureEV Network Dashboard v3 — {mode}")
#     print(f" Open: http://localhost:5002\n")
#     t = threading.Thread(target=sim_loop, daemon=True)
#     t.start()
#     app.run(debug=False, threaded=True, port=5002)