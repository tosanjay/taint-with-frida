/**
 * Example: Dangerous Function Tracking
 *
 * This example demonstrates Phase 1 of the taint tracking system:
 * - Automatic detection of dangerous function calls
 * - Tracking tainted data flow into dangerous functions
 * - Categorization by risk level
 *
 * Usage:
 *   1. Compile a target program (see example-vuln.c)
 *   2. Run: frida -l example-dangerous.js ./target_program
 */

var tracker = require("./taint/tracker.js");

// Initialize dangerous function tracking
// This will automatically hook all enabled functions from the config
tracker.initDangerousFunctions();

// Example: Hook main to start taint tracking
// You'll need to adjust the address based on your target binary
// Use: objdump -d ./target_program | grep "<main>:"
//
// For demonstration, we'll hook common entry points

// Try to hook main (if available)
var mainPtr = Module.findExportByName(null, 'main');
if (mainPtr !== null) {
    Interceptor.attach(mainPtr, {
        onEnter: function(args) {
            tracker.log("example", "=== Entering main() ===");

            // Start taint tracking
            tracker.startTracing(true); // true = hook syscalls

            // Taint command line arguments as they're common sources of user input
            // argc is in rdi, argv is in rsi
            var argc = this.context.rdi.toInt32();
            var argv = this.context.rsi;

            tracker.log("example", "argc = " + argc);

            // Taint all command line arguments
            for (var i = 0; i < argc; i++) {
                var argPtr = Memory.readPointer(argv.add(i * Process.pointerSize));
                var argStr = Memory.readCString(argPtr);
                var argLen = argStr.length;

                tracker.log("example", "Tainting argv[" + i + "]: " + argStr);
                tracker.memory.taint(argPtr, argLen);
            }
        }
    });
}

// Hook read syscall to taint data from stdin
tracker.syscallPreHook = function(ctx) {
    var syscallNum = ctx.rax.toInt32();

    // read(fd, buf, count)
    if (syscallNum === 0) {
        var fd = ctx.rdi.toInt32();
        var buf = ctx.rsi;
        var count = ctx.rdx.toInt32();

        tracker.log("syscall", "read(fd=" + fd + ", buf=" + buf + ", count=" + count + ")");

        // Only taint if reading from stdin (fd=0) or other untrusted sources
        if (fd === 0 || fd >= 3) {
            tracker.memory.taint(buf, count);
            tracker.log("syscall", "Tainted " + count + " bytes from read()");
        }
    }
    // exit syscalls
    else if (syscallNum === 60 || syscallNum === 231) {
        tracker.log("syscall", "exit() called - generating report");
        tracker.stopTracing();
        tracker.report();
    }
};

tracker.syscallPostHook = function(ctx) {
    // Can track return values here if needed
};

// Cleanup on exit
Process.setExceptionHandler(function(details) {
    tracker.log("exception", "Exception occurred: " + details.type);
    tracker.stopTracing();
    tracker.report();
    return false;
});

tracker.log("example", "Dangerous function tracker initialized");
tracker.log("example", "Waiting for program execution...");
