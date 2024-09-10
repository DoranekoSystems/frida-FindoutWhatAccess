const MAX_WATCHPOINTS = 4;

let watchpoints = new Array(MAX_WATCHPOINTS).fill(null);
let thread = null;
let breakCounter = 0;
let breakFlag = false;
let hookedAddressList = [];
let informationQueue = [];

function bytesToHex(bytes) {
  var hexArray = [];
  for (var i = 0; i < bytes.length; ++i) {
    var hex = (bytes[i] & 0xff).toString(16);
    hex = hex.length === 1 ? "0" + hex : hex;
    hexArray.push(hex);
  }
  return hexArray.join("");
}

function initializeWatchpoints() {
  thread = Process.enumerateThreads()[0];
  Process.setExceptionHandler(exceptionHandler);
  console.log("Watchpoint system initialized");
}

function exceptionHandler(e) {
  if (["breakpoint", "single-step"].includes(e.type)) {
    if (breakCounter == 0) {
      const bytes = new Uint8Array(e.context.pc.readByteArray(4));

      // Since send is very slow, push to a queue and retrieve it at regular intervals
      let data = {
        context: e.context,
        hexData: bytesToHex(bytes),
        symbol: DebugSymbol.fromAddress(e.context.pc).moduleName,
        watchSlot: 0,
      };
      let breakFlag = true;
      let hookAddress = parseInt(e.context.pc.add(0x04));
      if (hookedAddressList.length > 0) {
        Interceptor.detachAll();
        gc();
        let x = 1 + 1;
        hookedAddressList = [];
      }
      Interceptor.attach(ptr(hookAddress), {
        onEnter: function (args) {
          // Exclude it except during break
          if (breakFlag) {
            data.watchSlot = breakCounter - 1;
            informationQueue.push(data);
            for (let i = 0; i < breakCounter; i++) {
              if (watchpoints[i] !== null) {
                const { address, size, conditions } = watchpoints[i];
                thread.setHardwareWatchpoint(i, address, size, conditions);
              }
            }
            breakCounter = 0;
            breakFlag = false;
          }
        },
      });
      hookedAddressList.push(hookAddress);
    }
    // Disable each watchpoint one by one to identify which watchpoint was triggered
    if (watchpoints[breakCounter] !== null) {
      thread.unsetHardwareWatchpoint(breakCounter);
    }
    breakCounter++;
    return true;
  }
  return false;
}

function setWatchpoint(address, size, conditions) {
  const availableSlot = watchpoints.findIndex((wp) => wp === null);
  if (availableSlot === -1) {
    throw new Error("No available watchpoint slots");
  }

  watchpoints[availableSlot] = { address, size, conditions };
  thread.setHardwareWatchpoint(availableSlot, address, size, conditions);
  console.log(`Watchpoint set at slot ${availableSlot}`);
}

function removeWatchpoint(slot) {
  if (slot < 0 || slot >= MAX_WATCHPOINTS) {
    throw new Error("Invalid watchpoint slot");
  }

  if (watchpoints[slot] === null) {
    console.log(`No watchpoint at slot ${slot}`);
    return;
  }

  thread.unsetHardwareWatchpoint(slot);
  watchpoints[slot] = null;
  console.log(`Watchpoint removed from slot ${slot}`);
}

function removeAllWatchpoints() {
  for (let i = 0; i < MAX_WATCHPOINTS; i++) {
    if (watchpoints[i] !== null) {
      thread.unsetHardwareWatchpoint(i);
      watchpoints[i] = null;
    }
  }
  console.log("All watchpoints removed");
}

rpc.exports = {
  initialize: initializeWatchpoints,
  setwatchpoint: function (address, size, conditions) {
    setWatchpoint(ptr(address), size, conditions);
  },
  removewatchpoint: removeWatchpoint,
  removeallwatchpoints: removeAllWatchpoints,
  getbreakinfo: function () {
    let result = informationQueue;
    informationQueue = [];
    return result;
  },
};
