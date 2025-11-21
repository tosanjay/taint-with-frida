'use strict';

/**
 * High-level taint tracker with dangerous function detection
 */

var core = require("./core.js");
var arch = require("./amd64.js");
var DangerousFunctionTracker = require("./dangerous-functions.js").DangerousFunctionTracker;

// Taint engine components
var memory = new core.Memory();
var regs = new core.Registers(arch);

// Global taint engine export
var taintEngine = {
    memory: memory,
    regs: regs,
    arch: arch
};

// Dangerous function tracker (initialized later)
var dangerousTracker = null;

// Logging
function log(module, str) {
    console.log("<" + module + ": " + str + ">");
}

// Instruction handlers (same as in index.js)
function scaleSHL(addr, scale) {
    switch(scale) {
        case 1: return addr;
        case 2: return addr.shl(1);
        case 4: return addr.shl(2);
        case 8: return addr.shl(3);
    }
}

function doMovRegMem(ctx) {
    var instr = Instruction.parse(ctx.pc);
    var operands = instr.operands;
    var op0 = operands[0].value;
    var op1 = operands[1].value;
    var size0 = operands[0].size;

    if(op1.base === undefined)
        return;

    var addr = ctx[op1.base].add(op1.disp);
    if(op1.index !== undefined)
        addr = addr.add(scaleSHL(ctx[op1.index], op1.scale));

    regs.fromBitMap(op0, memory.toBitMap(addr, size0));
}

function doMovMemReg(ctx) {
    var instr = Instruction.parse(ctx.pc);
    var operands = instr.operands;
    var op0 = operands[0].value;
    var op1 = operands[1].value;

    if(op0.base === undefined)
        return;

    var addr = ctx[op0.base].add(op0.disp);
    if(op0.index !== undefined)
        addr = addr.add(scaleSHL(ctx[op0.index], op0.scale));

    memory.fromRanges(regs.toRanges(op1, addr));
}

function doMovRegReg(ctx) {
    var instr = Instruction.parse(ctx.pc);
    var operands = instr.operands;
    var op0 = operands[0].value;
    var op1 = operands[1].value;

    regs.spread(op0, op1);
}

function doMovRegImm(ctx) {
    var instr = Instruction.parse(ctx.pc);
    var op0 = instr.operands[0].value

    regs.untaint(op0);
}

function doMovMemImm(ctx) {
    var instr = Instruction.parse(ctx.pc);
    var operands = instr.operands;
    var op0 = operands[0].value;
    var size1 = operands[1].size;

    if(op0.base === undefined)
        return;

    var addr = ctx[op0.base].add(op0.disp);
    if(op0.index !== undefined)
        addr = addr.add(scaleSHL(ctx[op0.index], op0.scale));

    memory.untaint(addr, size1);
}

function doXorSameReg(ctx) {
    var instr = Instruction.parse(ctx.pc);
    var op0 = instr.operands[0].value

    regs.untaint(op0);
}

function doPushReg(ctx) {
    var instr = Instruction.parse(ctx.pc);
    var operands = instr.operands;
    var op0 = operands[0].value;

    var addr = ctx.rsp;

    memory.fromRanges(regs.toRanges(op0, addr));
}

function doPopReg(ctx) {
    var instr = Instruction.parse(ctx.pc);
    var operands = instr.operands;
    var op0 = operands[0].value;
    var size0 = operands[0].size;

    var addr = ctx[arch.sp];

    regs.fromBitMap(op0, memory.toBitMap(addr, size0));
}

function doRet(ctx) {
    var addr = ctx[arch.sp];

    regs.fromBitMap("pc", memory.toBitMap(addr, arch.ptrSize));
}

function doCall(ctx) {
    var addr = ctx[arch.sp];
    memory.untaint(addr);
}

function startTracing(hookSyscalls) {
    hookSyscalls = hookSyscalls || false;

    Stalker.follow(Process.getCurrentThreadId(), {
        transform: function (iterator) {
          var instr = iterator.next();

          try {
              do {
                var operands = instr.operands;
                var mnemonic = instr.mnemonic;

                if(operands.length == 2 && !mnemonic.startsWith("cmp") && !mnemonic.startsWith("test")) {
                    if(operands[0].type == "reg" && operands[1].type == "mem")
                        iterator.putCallout(doMovRegMem);
                    else if(operands[0].type == "mem" && operands[1].type == "reg")
                        iterator.putCallout(doMovMemReg);
                    else if(mnemonic.startsWith("doMov") && operands[0].type == "reg" && operands[1].type == "imm")
                        iterator.putCallout(doMovRegImm);
                    else if(mnemonic.startsWith("doMov") && operands[0].type == "mem" && operands[1].type == "imm")
                        iterator.putCallout(doMovMemImm);
                    else if(operands[0].type == "reg" && operands[1].type == "reg") {
                        if(mnemonic.startsWith("xor") && operands[0].value == operands[1].value)
                            iterator.putCallout(doXorSameReg);
                        else
                            iterator.putCallout(doMovRegReg);
                    }
                }
                else if(mnemonic.startsWith("push"))
                    iterator.putCallout(doPushReg);
                else if(mnemonic.startsWith("pop"))
                    iterator.putCallout(doPopReg);
                else if(mnemonic.startsWith("ret"))
                    iterator.putCallout(doRet);
                else if(mnemonic.startsWith("call"))
                    iterator.putCallout(doCall);
                else if(hookSyscalls && mnemonic == "syscall") {
                    iterator.putCallout(exports.syscallPreHook);
                    iterator.keep();
                    iterator.putCallout(exports.syscallPostHook);
                    continue;
                }

                iterator.keep();
              } while ((instr = iterator.next()) !== null);
          }
          catch(err) { console.log(err); }
        }
    });

    log("taint", "started tracing");
}

function stopTracing() {
    Stalker.unfollow(Process.getCurrentThreadId());

    log("taint", "stopped tracing");
}

function report() {
    log("taint", "report:" +
      "\n  tainted registers = " + JSON.stringify(regs.toArray()) +
      "\n  tainted memory    = " + JSON.stringify(memory.toArray()));

    // Also report dangerous function tracker stats
    if (dangerousTracker !== null) {
        dangerousTracker.report();
    }
}

/**
 * Initialize dangerous function tracking
 */
function initDangerousFunctions(configPath) {
    configPath = configPath || '/home/user/taint-with-frida/dangerous-functions.json';

    try {
        // Read config file
        var configData = File.readAllText(configPath);
        var config = JSON.parse(configData);

        // Create tracker
        dangerousTracker = new DangerousFunctionTracker(taintEngine, config);

        // Initialize hooks
        dangerousTracker.initialize();

        log("tracker", "dangerous function tracking initialized");

        return dangerousTracker;
    } catch (e) {
        console.log("Error initializing dangerous function tracker: " + e.message);
        console.log("Make sure to run: python3 config-converter.py");
        return null;
    }
}

// Exports
exports.memory = memory;
exports.regs = regs;
exports.arch = arch;
exports.taintEngine = taintEngine;
exports.dangerousTracker = function() { return dangerousTracker; };
exports.syscallPreHook = function(ctx) {};
exports.syscallPostHook = function(ctx) {};
exports.startTracing = startTracing;
exports.stopTracing = stopTracing;
exports.report = report;
exports.log = log;
exports.initDangerousFunctions = initDangerousFunctions;
