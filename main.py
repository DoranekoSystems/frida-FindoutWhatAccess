import sys
import frida
import threading
from capstone import *


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

    for i in md.disasm(_bytes, address):
        instruction = f"0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}"
        break
    return instruction


def on_message(message, data):
    if "payload" in message:
        pc = int(message["payload"]["pc"], 16)
        print(disassemble_arm64_instruction(pc, data))


def main():
    with open("hook.js") as f:
        jscode = f.read()

    device = get_device()
    apps = device.enumerate_applications()
    target = sys.argv[1]
    for app in apps:
        if target == app.identifier or target == app.name:
            app_identifier = app.identifier
            app_name = app.name
            break
    process = device.attach(app_name)

    script = process.create_script(jscode)
    script.on("message", on_message)
    script.load()
    api = script.exports_sync
    api.initialize()

    api.setwatchpoint(0xB9CD26B10, 4, "w")
    api.setwatchpoint(0xB9CD26B18, 4, "r")

    sys.stdin.read()


main()
