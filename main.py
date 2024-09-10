import webview
import json
import threading
import time
import random
import frida
import sys
from capstone import *

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Watchpoint at {address}</title>
    <style>
        :root {{
            --background: #1F1F1F;
            --surface: #252526;
            --primary: #007ACC;
            --on-primary: #FFFFFF;
            --on-surface: #CCCCCC;
            --divider: #3F3F3F;
        }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: var(--background);
            color: var(--on-surface);
            margin: 0;
            padding: 10px;
            font-size: 14px;
        }}
        .container {{
            display: flex;
            flex-direction: column;
            height: 100vh;
        }}
        .header {{
            background-color: var(--surface);
            padding: 10px;
            border-bottom: 1px solid var(--divider);
        }}
        .content {{
            flex: 1;
            overflow-y: auto;
            padding: 10px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        th, td {{
            text-align: left;
            padding: 8px;
            border-bottom: 1px solid var(--divider);
        }}
        th {{
            background-color: var(--surface);
            color: var(--primary);
        }}
        .footer {{
            background-color: var(--surface);
            padding: 10px;
            border-top: 1px solid var(--divider);
            display: flex;
            justify-content: flex-end;
        }}
        button {{
            background-color: var(--primary);
            color: var(--on-primary);
            border: none;
            padding: 5px 10px;
            margin-left: 5px;
            cursor: pointer;
        }}
        button:hover {{
            opacity: 0.8;
        }}
        #notification {{
            position: fixed;
            bottom: 20px;
            right: 20px;
            background-color: var(--primary);
            color: var(--on-primary);
            padding: 10px;
            border-radius: 4px;
            display: none;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2>Watchpoint at {address}</h2>
            <p>Type: {type}, Size: {size} bytes</p>
        </div>
        <div class="content">
            <table id="hits-table">
                <thead>
                    <tr>
                        <th>Count</th>
                        <th>Address</th>
                        <th>Symbol</th>
                        <th>Opcode</th>
                    </tr>
                </thead>
                <tbody id="hits-body"></tbody>
            </table>
        </div>
        <div class="footer">
            <button onclick="toggleWatchpoint()" id="toggle-btn">Disable</button>
            <button onclick="removeWatchpoint()">Remove</button>
        </div>
    </div>
    <div id="notification"></div>

    <script>
        function updateHits(hits) {{
            const tbody = document.getElementById('hits-body');
            tbody.innerHTML = '';
            hits.forEach(hit => {{
                const row = tbody.insertRow();
                row.insertCell(0).textContent = hit.count;
                row.insertCell(1).textContent = hit.address;
                row.insertCell(2).textContent = hit.symbol;
                row.insertCell(3).textContent = hit.opcode;
            }});
        }}

        function toggleWatchpoint() {{
            pywebview.api.toggle_watchpoint();
        }}

        function removeWatchpoint() {{
            pywebview.api.remove_watchpoint();
        }}

        function updateStatus(active) {{
            const toggleBtn = document.getElementById('toggle-btn');
            toggleBtn.textContent = active ? 'Disable' : 'Enable';
        }}

        function showNotification(message) {{
            const notification = document.getElementById('notification');
            notification.textContent = message;
            notification.style.display = 'block';
            setTimeout(() => {{
                notification.style.display = 'none';
            }}, 3000);
        }}
    </script>
</body>
</html>
"""

MAIN_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Watchpoint Analyzer</title>
    <style>
        :root {
            --background: #1F1F1F;
            --surface: #252526;
            --primary: #007ACC;
            --on-primary: #FFFFFF;
            --on-surface: #CCCCCC;
            --divider: #3F3F3F;
        }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: var(--background);
            color: var(--on-surface);
            margin: 0;
            padding: 10px;
            font-size: 14px;
        }
        .container {
            max-width: 400px;
            margin: 0 auto;
        }
        h1 {
            color: var(--primary);
        }
        .form-group {
            margin-bottom: 10px;
        }
        label {
            display: block;
            margin-bottom: 5px;
        }
        input, select {
            width: 100%;
            padding: 5px;
            background-color: var(--surface);
            border: 1px solid var(--divider);
            color: var(--on-surface);
        }
        button {
            background-color: var(--primary);
            color: var(--on-primary);
            border: none;
            padding: 5px 10px;
            cursor: pointer;
            width: 100%;
        }
        button:hover {
            opacity: 0.8;
        }
        #notification {
            position: fixed;
            bottom: 20px;
            right: 20px;
            background-color: var(--primary);
            color: var(--on-primary);
            padding: 10px;
            border-radius: 4px;
            display: none;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Set Watchpoint</h1>
        <div class="form-group">
            <label for="address">Address (hex)</label>
            <input type="text" id="address" placeholder="e.g., 0x1000">
        </div>
        <div class="form-group">
            <label for="type">Type</label>
            <select id="type">
                <option value="r">Read</option>
                <option value="w">Write</option>
                <option value="a">Access</option>
            </select>
        </div>
        <div class="form-group">
            <label for="size">Size</label>
            <select id="size">
                <option value="1">1 byte</option>
                <option value="2">2 bytes</option>
                <option value="4">4 bytes</option>
                <option value="8">8 bytes</option>
            </select>
        </div>
        <button onclick="setWatchpoint()">Set Watchpoint</button>
    </div>
    <div id="notification"></div>
    <script>
        function setWatchpoint() {
            const address = document.getElementById('address').value;
            const type = document.getElementById('type').value;
            const size = document.getElementById('size').value;
            pywebview.api.set_watchpoint(address, type, size);
        }
        function showNotification(message) {
            const notification = document.getElementById('notification');
            notification.textContent = message;
            notification.style.display = 'block';
            setTimeout(() => {
                notification.style.display = 'none';
            }, 3000);
        }
    </script>
</body>
</html>
"""


def get_device():
    mgr = frida.get_device_manager()
    changed = threading.Event()

    def on_changed():
        changed.set()

    mgr.on("changed", on_changed)

    device = None
    while device is None:
        devices = [dev for dev in mgr.enumerate_devices() if dev.type == "usb"]
        if len(devices) == 0:
            print("Waiting for usb device...")
            changed.wait()
        else:
            device = devices[0]

    mgr.off("changed", on_changed)
    return device


def disassemble_arm64_instruction(address, _bytes):
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

    instruction = ""
    for i in md.disasm(_bytes, address):
        instruction = f"0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}"
        break
    return instruction


class WatchpointWindow:
    def __init__(self, address, wp_type, size, manager, slot):
        self.address = address
        self.type = wp_type
        self.size = size
        self.active = True
        self.hits = []
        self.window = None
        self.manager = manager
        self.slot = slot
        self.window_active = threading.Event()
        self.window_active.set()

    def create_window(self):
        html_content = HTML_TEMPLATE.format(
            address=hex(self.address), type=self.type, size=self.size
        )
        self.window = webview.create_window(
            f"Watchpoint at {hex(self.address)}", html=html_content, js_api=self
        )
        self.window.events.closed += self.on_window_close

    def on_window_close(self):
        self.window_active.clear()
        self.manager.remove_watchpoint(self.address, self.slot)

    def toggle_watchpoint(self):
        if not self.window_active.is_set():
            return
        self.active = not self.active
        status = "enabled" if self.active else "disabled"
        self.safe_evaluate_js(f"updateStatus({json.dumps(self.active)})")
        self.safe_evaluate_js(f"showNotification('Watchpoint {status}')")

    def remove_watchpoint(self):
        if not self.window_active.is_set():
            return
        self.safe_evaluate_js("showNotification('Watchpoint removed')")
        self.manager.remove_watchpoint(self.address, self.slot)
        try:
            self.window.destroy()
        except Exception as _e:
            pass

    def add_hit(self, hit):
        if not self.window_active.is_set():
            return
        existing_hit = next(
            (h for h in self.hits if h["address"] == hit["address"]), None
        )
        if existing_hit:
            existing_hit["count"] += 1
        else:
            self.hits.append(hit)
        self.safe_evaluate_js(f"updateHits({json.dumps(self.hits)})")
        self.safe_evaluate_js(f"log('{hit['address']}: {hit['opcode']}')")

    def safe_evaluate_js(self, code):
        if self.window_active.is_set():
            try:
                self.window.evaluate_js(code)
            except Exception as e:
                print(f"Error evaluating JS: {e}")


class WatchpointManager:
    def __init__(self, frida_api):
        self.watchpoints = {}
        self.frida_api = frida_api
        self.next_slot = 0
        self.lock = threading.Lock()

    def create_watchpoint(self, address, wp_type, size):
        with self.lock:
            if address in self.watchpoints:
                return False
            slot = self.next_slot
            self.next_slot += 1
            wp_window = WatchpointWindow(address, wp_type, size, self, slot)
            self.watchpoints[address] = wp_window
            wp_window.create_window()

            self.frida_api.setwatchpoint(address, int(size), wp_type)

            threading.Thread(
                target=self.update_watchpoint, args=(address,), daemon=True
            ).start()
            return True

    def remove_watchpoint(self, address, slot):
        with self.lock:
            if address in self.watchpoints:
                self.next_slot -= 1
                self.frida_api.removewatchpoint(slot)
                del self.watchpoints[address]

    def update_watchpoint(self, address):
        while True:
            with self.lock:
                if (
                    address not in self.watchpoints
                    or not self.watchpoints[address].window_active.is_set()
                ):
                    break
                wp = self.watchpoints[address]
                if not wp.active:
                    time.sleep(0.1)
                    continue

            informations = self.frida_api.getbreakinfo()
            for info in informations:
                slot = info["watchSlot"]
                if slot == wp.slot:
                    context = info["context"]
                    _bytes = bytes.fromhex(info["hexData"])
                    code = disassemble_arm64_instruction(
                        int(context["pc"], 16), _bytes
                    ).split(":")[1]
                    symbol = info["symbol"]
                    hit = {
                        "count": 1,
                        "address": hex(int(context["pc"], 16)),
                        "symbol": symbol,
                        "opcode": code,
                    }
                    wp.add_hit(hit)
            time.sleep(0.1)


class MainWindow:
    def __init__(self, frida_api):
        self.manager = WatchpointManager(frida_api)

    def set_watchpoint(self, address, wp_type, size):
        try:
            address = int(address, 16)
            success = self.manager.create_watchpoint(address, wp_type, size)
            if success:
                self.window.evaluate_js(
                    f"showNotification('Watchpoint set at {hex(address)}')"
                )
            else:
                self.window.evaluate_js(
                    f"showNotification('Watchpoint already exists at {hex(address)}')"
                )
        except ValueError:
            self.window.evaluate_js("showNotification('Invalid address format')")

    def create_window(self):
        self.window = webview.create_window(
            "Watchpoint Analyzer", html=MAIN_HTML, js_api=self
        )
        return self.window


def on_message(message, data):
    print(message)


def main():
    with open("hook.js") as f:
        jscode = f.read()

    device = get_device()
    # device = frida.get_device_manager().add_remote_device("")
    apps = device.enumerate_applications()

    target = sys.argv[1]
    app_name = ""
    app_identifier = ""
    for app in apps:
        if target == app.name:
            app_name = app.name
            break
        elif target == app.identifier:
            app_identifier = app.identifier
            break
    if app_identifier != "":
        pid = device.spawn([app_identifier])
        process = device.attach(pid)
        device.resume(pid)
    else:
        process = device.attach(app_name)

    script = process.create_script(jscode)
    script.on("message", on_message)
    script.load()
    api = script.exports_sync
    api.initialize()

    main_window = MainWindow(api)
    window = main_window.create_window()
    webview.start(window)


if __name__ == "__main__":
    main()
