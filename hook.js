const MAX_WATCHPOINTS = 4;

let watchpoints = new Array(MAX_WATCHPOINTS).fill(null);
let thread = null;

function initializeWatchpoints() {
  thread = Process.enumerateThreads()[0];
  Process.setExceptionHandler(exceptionHandler);
  console.log("Watchpoint system initialized");
}

function exceptionHandler(e) {
  if (["breakpoint", "single-step"].includes(e.type)) {
    const bytes = e.context.pc.readByteArray(4);
    send({ pc: e.context.pc }, bytes);
    for (let i = 0; i < MAX_WATCHPOINTS; i++) {
      if (watchpoints[i] !== null) {
        thread.unsetHardwareWatchpoint(i);
      }
    }
    Interceptor.attach(e.context.pc.add(0x04), {
      onEnter: function (args) {
        for (let i = 0; i < MAX_WATCHPOINTS; i++) {
          if (watchpoints[i] !== null) {
            const { address, size, conditions } = watchpoints[i];
            thread.setHardwareWatchpoint(i, address, size, conditions);
          }
        }
      },
    });
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
};
