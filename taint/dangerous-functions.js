'use strict';

/**
 * Dangerous Function Tracker
 *
 * Automatically hooks dangerous functions and checks for tainted data flow
 */

// Risk level colors for output
var RISK_COLORS = {
    'critical': '\x1b[91m',  // bright red
    'high': '\x1b[31m',      // red
    'medium': '\x1b[33m',    // yellow
    'low': '\x1b[36m',       // cyan
    'reset': '\x1b[0m'
};

var RISK_SYMBOLS = {
    'critical': '🔴',
    'high': '🟠',
    'medium': '🟡',
    'low': '🔵'
};

/**
 * DangerousFunctionTracker class
 */
var DangerousFunctionTracker = function(taintEngine, config) {
    this.taintEngine = taintEngine;
    this.config = config;
    this.hooks = [];
    this.detections = [];
    this.stats = {
        total_calls: 0,
        tainted_calls: 0,
        by_risk: {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0
        }
    };
};

/**
 * Check if a memory region contains tainted data
 */
DangerousFunctionTracker.prototype.checkTaintedMemory = function(addr, size, description) {
    if (addr.isNull()) {
        return { tainted: false, reason: 'null pointer' };
    }

    size = size || 0;

    // If size is 0, try to read as null-terminated string
    if (size === 0) {
        try {
            var str = Memory.readCString(addr);
            if (str === null) {
                return { tainted: false, reason: 'unable to read string' };
            }
            size = str.length;
        } catch (e) {
            return { tainted: false, reason: 'memory read error: ' + e.message };
        }
    }

    var isTainted = this.taintEngine.memory.isTainted(addr, size);

    return {
        tainted: isTainted,
        addr: addr,
        size: size,
        description: description
    };
};

/**
 * Check if a register contains tainted data
 */
DangerousFunctionTracker.prototype.checkTaintedRegister = function(reg, description) {
    var isTainted = this.taintEngine.regs.isTainted(reg);

    return {
        tainted: isTainted,
        register: reg,
        description: description
    };
};

/**
 * Get argument value based on calling convention (x86_64 System V ABI)
 */
DangerousFunctionTracker.prototype.getArgument = function(ctx, index) {
    var argRegs = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9'];

    if (index < argRegs.length) {
        return ctx[argRegs[index]];
    } else {
        // Arguments beyond 6th are on the stack
        var stackOffset = (index - 6) * 8;
        return Memory.readPointer(ctx.rsp.add(stackOffset + 8)); // +8 for return address
    }
};

/**
 * Check a function argument for taint
 */
DangerousFunctionTracker.prototype.checkArgument = function(ctx, argCheck) {
    var argValue = this.getArgument(ctx, argCheck.index);
    var result = null;

    switch (argCheck.type) {
        case 'source':
        case 'dest':
        case 'exec':
        case 'format':
            // Treat as pointer to data
            var size = 0;
            if (argCheck.index === 2) {
                // For functions like memcpy where 3rd arg is size
                size = argValue.toInt32();
            }
            result = this.checkTaintedMemory(argValue, size, argCheck.description);
            result.argIndex = argCheck.index;
            result.argType = argCheck.type;
            break;
    }

    return result;
};

/**
 * Log a detection
 */
DangerousFunctionTracker.prototype.logDetection = function(funcName, funcConfig, taintedArgs, ctx) {
    var risk = funcConfig.risk || 'medium';
    var color = RISK_COLORS[risk];
    var symbol = RISK_SYMBOLS[risk];
    var reset = RISK_COLORS.reset;

    var detection = {
        timestamp: Date.now(),
        function: funcName,
        risk: risk,
        description: funcConfig.description,
        tainted_args: taintedArgs,
        backtrace: Thread.backtrace(ctx, Backtracer.ACCURATE).map(DebugSymbol.fromAddress)
    };

    this.detections.push(detection);
    this.stats.tainted_calls++;
    this.stats.by_risk[risk]++;

    // Pretty print detection
    console.log(color + '━'.repeat(80) + reset);
    console.log(color + symbol + ' TAINTED DATA IN DANGEROUS FUNCTION' + reset);
    console.log(color + '━'.repeat(80) + reset);
    console.log('Function: ' + color + funcName + '()' + reset);
    console.log('Risk:     ' + color + risk.toUpperCase() + reset);
    console.log('Reason:   ' + funcConfig.description);
    console.log('');
    console.log('Tainted Arguments:');

    for (var i = 0; i < taintedArgs.length; i++) {
        var arg = taintedArgs[i];
        console.log('  [' + arg.argIndex + '] ' + arg.description + ' (' + arg.argType + ')');
        console.log('      Address: ' + arg.addr);
        console.log('      Size:    ' + arg.size + ' bytes');

        // Try to show the data
        try {
            if (arg.size > 0 && arg.size <= 256) {
                var data = Memory.readCString(arg.addr, arg.size);
                if (data) {
                    // Truncate and escape for display
                    var display = data.length > 64 ? data.substring(0, 64) + '...' : data;
                    display = display.replace(/\n/g, '\\n').replace(/\r/g, '\\r').replace(/\t/g, '\\t');
                    console.log('      Data:    "' + display + '"');
                }
            }
        } catch (e) {
            // Memory might not be readable as string
        }
    }

    console.log('');
    console.log('Call Stack:');
    var bt = detection.backtrace;
    for (var i = 0; i < Math.min(bt.length, 10); i++) {
        console.log('  ' + bt[i]);
    }
    console.log(color + '━'.repeat(80) + reset);
    console.log('');
};

/**
 * Hook a single function
 */
DangerousFunctionTracker.prototype.hookFunction = function(funcName, funcConfig) {
    var self = this;

    // Try to resolve the function
    var funcPtr = Module.findExportByName(null, funcName);
    if (funcPtr === null) {
        // Try with underscore prefix (some systems)
        funcPtr = Module.findExportByName(null, '_' + funcName);
    }

    if (funcPtr === null) {
        return false;
    }

    try {
        var hook = Interceptor.attach(funcPtr, {
            onEnter: function(args) {
                self.stats.total_calls++;

                // Check each argument that needs checking
                var taintedArgs = [];

                for (var i = 0; i < funcConfig.arg_checks.length; i++) {
                    var argCheck = funcConfig.arg_checks[i];
                    var result = self.checkArgument(this.context, argCheck);

                    if (result && result.tainted) {
                        taintedArgs.push(result);
                    }
                }

                // If any arguments are tainted, log the detection
                if (taintedArgs.length > 0) {
                    self.logDetection(funcName, funcConfig, taintedArgs, this.context);
                }
            }
        });

        this.hooks.push({
            name: funcName,
            hook: hook,
            config: funcConfig
        });

        return true;
    } catch (e) {
        console.log('Warning: Failed to hook ' + funcName + ': ' + e.message);
        return false;
    }
};

/**
 * Initialize hooks from configuration
 */
DangerousFunctionTracker.prototype.initialize = function() {
    var totalHooked = 0;
    var totalAttempted = 0;

    console.log('[*] Initializing dangerous function tracker...');
    console.log('');

    // Iterate through all categories
    for (var category in this.config) {
        var functions = this.config[category];

        if (typeof functions !== 'object') {
            continue;
        }

        var categoryHooked = 0;
        var categoryTotal = 0;

        for (var funcName in functions) {
            var funcConfig = functions[funcName];

            if (!funcConfig.enabled) {
                continue;
            }

            categoryTotal++;
            totalAttempted++;

            if (this.hookFunction(funcName, funcConfig)) {
                categoryHooked++;
                totalHooked++;
            }
        }

        if (categoryTotal > 0) {
            console.log('[+] ' + category + ': ' + categoryHooked + '/' + categoryTotal + ' functions hooked');
        }
    }

    console.log('');
    console.log('[*] Total: ' + totalHooked + '/' + totalAttempted + ' dangerous functions hooked');
    console.log('');

    return totalHooked;
};

/**
 * Get statistics
 */
DangerousFunctionTracker.prototype.getStats = function() {
    return this.stats;
};

/**
 * Print report
 */
DangerousFunctionTracker.prototype.report = function() {
    console.log('');
    console.log('═'.repeat(80));
    console.log('DANGEROUS FUNCTION TRACKER REPORT');
    console.log('═'.repeat(80));
    console.log('');
    console.log('Statistics:');
    console.log('  Total function calls:    ' + this.stats.total_calls);
    console.log('  Calls with tainted data: ' + this.stats.tainted_calls);
    console.log('');
    console.log('Detections by risk:');
    console.log('  🔴 Critical: ' + this.stats.by_risk.critical);
    console.log('  🟠 High:     ' + this.stats.by_risk.high);
    console.log('  🟡 Medium:   ' + this.stats.by_risk.medium);
    console.log('  🔵 Low:      ' + this.stats.by_risk.low);
    console.log('');
    console.log('Total detections: ' + this.detections.length);
    console.log('═'.repeat(80));
    console.log('');
};

/**
 * Cleanup hooks
 */
DangerousFunctionTracker.prototype.cleanup = function() {
    for (var i = 0; i < this.hooks.length; i++) {
        this.hooks[i].hook.detach();
    }
    this.hooks = [];
};

exports.DangerousFunctionTracker = DangerousFunctionTracker;
