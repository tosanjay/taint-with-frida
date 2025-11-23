/**
 * Example: Dangerous Function Tracking (Bundled)
 *
 * This example demonstrates Phase 1 of the taint tracking system:
 * - Automatic detection of dangerous function calls
 * - Tracking tainted data flow into dangerous functions
 * - Categorization by risk level
 *
 * Usage:
 *   frida -l example-dangerous-bundled.js ./target_program [args]
 */

'use strict';

// ============================================================================
// Module: bitmap.js
// ============================================================================
var BitMap = function(size){
	this._cols  = 8;
	this._shift = 3;
	this._rows  = (size>>this._shift)+1;
	this._buf   = new ArrayBuffer(this._rows);
	this._bin   = new Uint8Array(this._buf);
};

BitMap.prototype.get = function(off){
	var row = off>>this._shift;
	var col = off%this._cols;
	var bit = 1<<col;
	return (this._bin[row]&bit)>0;
};

BitMap.prototype.set = function(off,bool){
	var row = off>>this._shift;
	var col = off%this._cols;
	var bit = 1<<col;
	if (bool) {
		this._bin[row] |= bit;
	} else {
		bit = 255 ^ bit;
		this._bin[row] &= bit;
	}
};

BitMap.prototype.flip = function(off){
	var row = Math.floor(off/this._cols);
	var col = off%this._cols;
	var bit = 1<<col;
	this._bin[row] ^= bit;
};

BitMap.prototype.fill = function() {
	for(var i=0;i<this._rows;i++) {
		this._bin[i] = 255;
	}
};

BitMap.prototype.clear = function() {
	for(var i=0;i<this._rows;i++) {
		this._bin[i] = 0;
	}
};

// ============================================================================
// Module: interval-tree.js
// ============================================================================
var IntervalTreeModule = (function () {
  var exports = {};

  exports.Node = function (start, end, left, right) {
    this.interval = [start, end];
    this.max = ptr("0");
    this.parentNode = null;
    this.left = left;
    this.right = right;
  };

  exports.IntervalTree = function () {
    this.root = null;
  };

  function addNode(node, side, interval) {
    var child = new exports.Node(interval[0], interval[1]);
    child.max = interval[1];
    child.parentNode = node;
    node[side] = child;
    if (node.max.compare(interval[1]) < 0) {
      while (child) {
        if (child.max.compare(interval[1]) < 0) {
          child.max = interval[1];
        }
        child = child.parentNode;
      }
    }
  }

  function addHelper(node, interval) {
    if (node.interval[0].compare(interval[0]) > 0) {
      if (node.left) {
        addHelper(node.left, interval);
      } else {
        addNode(node, 'left', interval);
      }
    } else {
      if (node.right) {
        addHelper(node.right, interval);
      } else {
        addNode(node, 'right', interval);
      }
    }
  }

  exports.IntervalTree.prototype.add = function (interval) {
    if (!this.root) {
      this.root = new exports.Node(interval[0], interval[1]);
      this.root.max = interval[1];
      return;
    }
    addHelper(this.root, interval);
  };

  function contains(point, node) {
    if (!node) {
      return false;
    }
    if (node.interval[0].compare(point) <= 0 && node.interval[1].compare(point) >= 0) {
      return true;
    }
    var result = false;
    var temp;
    ['left', 'right'].forEach(function (key) {
      temp = node[key];
      if (temp) {
        if (temp.max > point) {
          result = result || contains(point, temp);
        }
      }
    });
    return result;
  }

  exports.IntervalTree.prototype.contains = function (point) {
    return contains(point, this.root);
  };

  function intersects(a, b) {
    return (a[0].compare(b[0]) <= 0 && a[1].compare(b[0]) >= 0) || (a[0].compare(b[1]) <= 0 && a[1].compare(b[1]) >= 0) ||
      (b[0].compare(a[0]) <= 0 && b[1].compare(a[0]) >= 0) || (b[0].compare(a[1]) <= 0 && b[1].compare(a[1]) >= 0);
  }

  function intersectsHelper(interval, node) {
    if (!node) {
      return false;
    }
    if (intersects(node.interval, interval)) {
      return true;
    }
    var result = false;
    var temp;
    ['left', 'right'].forEach(function (side) {
      temp = node[side];
      if (temp && temp.max.compare(interval[0]) >= 0) {
        result = result || intersectsHelper(interval, temp);
      }
    });
    return result;
  }

  exports.IntervalTree.prototype.intersects = function (interval) {
    return intersectsHelper(interval, this.root);
  };

  function intersection(a, b) {
    if(a === null || b === null)
        return null;
    if(b[0].compare(a[1]) > 0 || a[0].compare(b[1]) > 0)
        return null;

    var o = new Array(2);
    if(a[0].compare(b[0]) >= 0)
        o[0] = a[0];
    else
        o[0] = b[0];
    if(a[1].compare(b[1]) <= 0)
        o[1] = a[1];
    else
        o[1] = b[1];
    return o;
  }

  function intersectionHelper(interval, node) {
    if (!node) {
      return null;
    }
    var result = [];
    var inter = intersection(node.interval, interval);
    if(inter !== null)
        result.push(inter);
    var temp;
    ['left', 'right'].forEach(function (side) {
      temp = node[side];
      if (temp && temp.max.compare(interval[0]) >= 0) {
        var interArr = intersectionHelper(interval, temp);
        if(inter !== null)
            result = result.concat(interArr);
      }
    });
    return result;
  }

  exports.IntervalTree.prototype.intersection = function (interval) {
    return intersectionHelper(interval, this.root);
  };

  function heightHelper(node) {
    if (!node) {
      return 0;
    }
    return 1 + Math.max(heightHelper(node.left), heightHelper(node.right));
  }

  exports.IntervalTree.prototype.height = function () {
    return heightHelper(this.root);
  };

  exports.IntervalTree.prototype.findMax = function (node) {
    var stack = [node];
    var current;
    var max = -Infinity;
    var maxNode;
    while (stack.length) {
      current = stack.pop();
      if (current.left) {
        stack.push(current.left);
      }
      if (current.right) {
        stack.push(current.right);
      }
      if (current.interval[1].compare(max) > 0) {
        max = current.interval[1];
        maxNode = current;
      }
    }
    return maxNode;
  };

  exports.IntervalTree.prototype._removeHelper = function (interval, node) {
    if (!node) {
      return;
    }
    if (node.interval[0] === interval[0] &&
        node.interval[1] === interval[1]) {
      if (node.left && node.right) {
        var replacement = node.left;
        while (replacement.left) {
          replacement = replacement.left;
        }
        var temp = replacement.interval;
        replacement.interval = node.interval;
        node.interval = temp;
        this._removeHelper(replacement.interval, node);
      } else {
        var side = 'left';
        if (node.right) {
          side = 'right';
        }
        var parentNode = node.parentNode;
        if (parentNode) {
          if (parentNode.left === node) {
            parentNode.left = node[side];
          } else {
            parentNode.right = node[side];
          }
          if (node[side]) {
            node[side].parentNode = parentNode;
          }
        } else {
          this.root = node[side];
          if (this.root) {
            this.root.parentNode = null;
          }
        }
      }
      var p = node.parentNode;
      if (p) {
        var maxNode = this.findMax(p);
        var max = maxNode.interval[1];
        while (maxNode) {
          if (maxNode.max === node.interval[1]) {
            maxNode.max = max;
            maxNode = maxNode.parentNode;
          } else {
            maxNode = false;
          }
        }
      }
    } else {
      this._removeHelper(interval, node.left);
      this._removeHelper(interval, node.right);
    }
  };

  exports.IntervalTree.prototype.remove = function (interval) {
    return this._removeHelper(interval, this.root);
  };

  return exports;
})();

var IntervalTree = IntervalTreeModule.IntervalTree;

// ============================================================================
// Module: amd64.js
// ============================================================================
var arch = {
    space: 920,
    ptrSize: 8,
    sp: "rsp",
    registers: {
        'ac': [192, 8],
        'acflag': [192, 8],
        'ah': [17, 1],
        'al': [16, 1],
        'ax': [16, 2],
        'bh': [41, 1],
        'bl': [40, 1],
        'bp': [56, 8],
        'bx': [40, 2],
        'cc_dep1': [152, 8],
        'cc_dep2': [160, 8],
        'cc_ndep': [168, 8],
        'cc_op': [144, 8],
        'ch': [25, 1],
        'cl': [24, 1],
        'cmlen': [880, 8],
        'cmstart': [872, 8],
        'cx': [24, 2],
        'd': [176, 8],
        'dflag': [176, 8],
        'dh': [33, 1],
        'di': [72, 2],
        'dih': [73, 1],
        'dil': [72, 1],
        'dl': [32, 1],
        'dx': [32, 2],
        'eax': [16, 4],
        'ebp': [56, 4],
        'ebx': [40, 4],
        'ecx': [24, 4],
        'edi': [72, 4],
        'edx': [32, 4],
        'emnote': [864, 4],
        'esi': [64, 4],
        'esp': [48, 4],
        'fc3210': [856, 8],
        'fpreg': [776, 64],
        'fpround': [848, 8],
        'fptag': [840, 8],
        'fpu_regs': [776, 64],
        'fpu_tags': [840, 8],
        'fs': [208, 8],
        'fs_const': [208, 8],
        'ftop': [768, 4],
        'gs': [904, 8],
        'gs_const': [904, 8],
        'id': [200, 8],
        'idflag': [200, 8],
        'ip': [184, 8],
        'ip_at_syscall': [912, 8],
        'mm0': [776, 8],
        'mm1': [784, 8],
        'mm2': [792, 8],
        'mm3': [800, 8],
        'mm4': [808, 8],
        'mm5': [816, 8],
        'mm6': [824, 8],
        'mm7': [832, 8],
        'nraddr': [888, 8],
        'pc': [184, 8],
        'r10': [96, 8],
        'r10d': [96, 4],
        'r10w': [96, 2],
        'r10b': [96, 1],
        'r11': [104, 8],
        'r11d': [104, 4],
        'r11w': [104, 2],
        'r11b': [104, 1],
        'r12': [112, 8],
        'r12d': [112, 4],
        'r12w': [112, 2],
        'r12b': [112, 1],
        'r13': [120, 8],
        'r13d': [120, 4],
        'r13w': [120, 2],
        'r13b': [120, 1],
        'r14': [128, 8],
        'r14d': [128, 4],
        'r14w': [128, 2],
        'r14b': [128, 1],
        'r15': [136, 8],
        'r15d': [136, 4],
        'r15w': [136, 2],
        'r15b': [136, 1],
        'r8': [80, 8],
        'r8d': [80, 4],
        'r8w': [80, 2],
        'r8b': [80, 1],
        'r9': [88, 8],
        'r9d': [88, 4],
        'r9w': [88, 2],
        'r9b': [88, 1],
        'rax': [16, 8],
        'rbp': [56, 8],
        'rbx': [40, 8],
        'rcx': [24, 8],
        'rdi': [72, 8],
        'rdx': [32, 8],
        'rip': [184, 8],
        'rsi': [64, 8],
        'rsp': [48, 8],
        'si': [64, 2],
        'sih': [65, 1],
        'sil': [64, 1],
        'sp': [48, 8],
        'sseround': [216, 8],
        'xmm0': [224, 16],
        'xmm1': [256, 16],
        'xmm10': [544, 16],
        'xmm11': [576, 16],
        'xmm12': [608, 16],
        'xmm13': [640, 16],
        'xmm14': [672, 16],
        'xmm15': [704, 16],
        'xmm16': [736, 16],
        'xmm2': [288, 16],
        'xmm3': [320, 16],
        'xmm4': [352, 16],
        'xmm5': [384, 16],
        'xmm6': [416, 16],
        'xmm7': [448, 16],
        'xmm8': [480, 16],
        'xmm9': [512, 16],
        'ymm0': [224, 32],
        'ymm1': [256, 32],
        'ymm10': [544, 32],
        'ymm11': [576, 32],
        'ymm12': [608, 32],
        'ymm13': [640, 32],
        'ymm14': [672, 32],
        'ymm15': [704, 32],
        'ymm16': [736, 32],
        'ymm2': [288, 32],
        'ymm3': [320, 32],
        'ymm4': [352, 32],
        'ymm5': [384, 32],
        'ymm6': [416, 32],
        'ymm7': [448, 32],
        'ymm8': [480, 32],
        'ymm9': [512, 32]
    }
};

// ============================================================================
// Module: core.js
// ============================================================================
var Registers = function(archDef) {
    this.arch = archDef;
    this.regTaintMap = new BitMap(archDef.space + 32);
}

Registers.prototype.taint = function(reg) {
    var rm = this.arch.registers[reg];
    for(var i = rm[0]; i < (rm[0] + rm[1]); ++i)
        this.regTaintMap.set(i, true);
}

Registers.prototype.untaint = function(reg) {
    var rm = this.arch.registers[reg];
    for(var i = rm[0]; i < (rm[0] + rm[1]); ++i)
        this.regTaintMap.set(i, false);
}

Registers.prototype.isTainted = function(reg) {
    var rm = this.arch.registers[reg];
    for(var i = rm[0]; i < (rm[0] + rm[1]); ++i)
        if(this.regTaintMap.get(i))
            return true;
    return false;
}

Registers.prototype.isFullyTainted = function(reg) {
    var rm = this.arch.registers[reg];
    for(var i = rm[0]; i < (rm[0] + rm[1]); ++i)
        if(this.regTaintMap.get(i))
            return true;
        else
            return false;
    return false;
}

Registers.prototype.toArray = function() {
    var arr = [];
    for(var r in this.arch.registers) {
        if(this.isTainted(r))
            arr.push(r);
    }
    return arr;
}

Registers.prototype.toRanges = function(reg, base) {
    var rm = this.arch.registers[reg];
    var ranges = [];
    for(var i = 0; i < rm[1]; ++i) {
        if(this.regTaintMap.get(rm[0] + i)) {
            var addr = base.add(i);

            if(ranges.length === 0) {
                ranges.push([addr, addr]);
            }
            if(ranges[ranges.length -1][1].equals(addr))
                ranges[ranges.length -1][1] = addr.add(1);
            else {
                ranges.push([addr, addr.add(1)]);
            }
        }
    }
    return ranges;
}

Registers.prototype.spread = function(destReg, srcReg) {
    var rm0 = this.arch.registers[destReg];
    var rm1 = this.arch.registers[srcReg];
    for(var i = 0; i < rm0[1]; ++i)
        this.regTaintMap.set(rm0[0] + i, this.regTaintMap.get(rm1[0] + i));
}

Registers.prototype.fromBitMap = function(reg, bmap) {
    var rm = this.arch.registers[reg];
    for(var i = 0; i < rm[1]; ++i)
        this.regTaintMap.set(i + rm[0], bmap.get(i));
}

var TaintMemory = function() {
    this.memTaintTree = new IntervalTree();
}

TaintMemory.prototype.taint = function(addr, size) {
    this.memTaintTree.add([addr, addr.add(size)]);
}

TaintMemory.prototype.untaint = function(addr, size) {
    this.memTaintTree.remove([addr, addr.add(size)]);
}

TaintMemory.prototype.isTainted = function(addr, size) {
    return this.memTaintTree.intersects([addr, addr.add(size)]);
}

TaintMemory.prototype.isFullyTainted = function(addr, size) {
    var inter = this.memTaintTree.intersection([addr, addr.add(size)]);
    if(inter.length != 1)
        return false;
    return inter[0][0].compare(addr) == 0 && inter[0][1].compare(addr.add(size)) == 0;
}

TaintMemory.prototype.toArray = function() {
    function helper(node, arr) {
        if(node === undefined) return arr;

        helper(node.left, arr);
        if(arr.length > 0 && arr[arr.length -1][1].compare(node.interval[0]) >= 0)
            arr[arr.length -1][1] = node.interval[1];
        else
            arr.push(node.interval);
        helper(node.right, arr);

        return arr;
    }

    return helper(this.memTaintTree.root, []);
}

TaintMemory.prototype.fromRanges = function(ranges) {
    for(var i in ranges) {
        this.memTaintTree.add(ranges[i]);
    }
}

TaintMemory.prototype.toBitMap = function(addr, size) {
    var inter = this.memTaintTree.intersection([addr, addr.add(size)]);
    var bmap = new BitMap(size);

    for(var i in inter) {
        for(var j = inter[i][0].sub(addr).toInt32(); j < inter[i][1].sub(addr).toInt32(); ++j) {
            bmap.set(j, true);
        }
    }

    return bmap;
}

// ============================================================================
// Module: dangerous-functions.js
// ============================================================================
var RISK_COLORS = {
    'critical': '\x1b[91m',
    'high': '\x1b[31m',
    'medium': '\x1b[33m',
    'low': '\x1b[36m',
    'reset': '\x1b[0m'
};

var RISK_SYMBOLS = {
    'critical': '🔴',
    'high': '🟠',
    'medium': '🟡',
    'low': '🔵'
};

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

DangerousFunctionTracker.prototype.checkTaintedMemory = function(addr, size, description) {
    if (addr.isNull()) {
        return { tainted: false, reason: 'null pointer' };
    }

    size = size || 0;

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

DangerousFunctionTracker.prototype.checkTaintedRegister = function(reg, description) {
    var isTainted = this.taintEngine.regs.isTainted(reg);

    return {
        tainted: isTainted,
        register: reg,
        description: description
    };
};

DangerousFunctionTracker.prototype.getArgument = function(ctx, index) {
    var argRegs = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9'];

    if (index < argRegs.length) {
        return ctx[argRegs[index]];
    } else {
        var stackOffset = (index - 6) * 8;
        return Memory.readPointer(ctx.rsp.add(stackOffset + 8));
    }
};

DangerousFunctionTracker.prototype.checkArgument = function(ctx, argCheck) {
    var argValue = this.getArgument(ctx, argCheck.index);
    var result = null;

    switch (argCheck.type) {
        case 'source':
        case 'dest':
        case 'exec':
        case 'format':
            var size = 0;
            if (argCheck.index === 2) {
                size = argValue.toInt32();
            }
            result = this.checkTaintedMemory(argValue, size, argCheck.description);
            result.argIndex = argCheck.index;
            result.argType = argCheck.type;
            break;
    }

    return result;
};

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

        try {
            if (arg.size > 0 && arg.size <= 256) {
                var data = Memory.readCString(arg.addr, arg.size);
                if (data) {
                    var display = data.length > 64 ? data.substring(0, 64) + '...' : data;
                    display = display.replace(/\n/g, '\\n').replace(/\r/g, '\\r').replace(/\t/g, '\\t');
                    console.log('      Data:    "' + display + '"');
                }
            }
        } catch (e) {
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

DangerousFunctionTracker.prototype.hookFunction = function(funcName, funcConfig) {
    var self = this;

    var funcPtr = Module.findExportByName(null, funcName);
    if (funcPtr === null) {
        funcPtr = Module.findExportByName(null, '_' + funcName);
    }

    if (funcPtr === null) {
        return false;
    }

    try {
        var hook = Interceptor.attach(funcPtr, {
            onEnter: function(args) {
                self.stats.total_calls++;

                var taintedArgs = [];

                for (var i = 0; i < funcConfig.arg_checks.length; i++) {
                    var argCheck = funcConfig.arg_checks[i];
                    var result = self.checkArgument(this.context, argCheck);

                    if (result && result.tainted) {
                        taintedArgs.push(result);
                    }
                }

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

DangerousFunctionTracker.prototype.initialize = function() {
    var totalHooked = 0;
    var totalAttempted = 0;

    console.log('[*] Initializing dangerous function tracker...');
    console.log('');

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

DangerousFunctionTracker.prototype.getStats = function() {
    return this.stats;
};

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

DangerousFunctionTracker.prototype.cleanup = function() {
    for (var i = 0; i < this.hooks.length; i++) {
        this.hooks[i].hook.detach();
    }
    this.hooks = [];
};

// ============================================================================
// Module: tracker.js
// ============================================================================

// Initialize taint engine components
var memory = new TaintMemory();
var regs = new Registers(arch);

var taintEngine = {
    memory: memory,
    regs: regs,
    arch: arch
};

var dangerousTracker = null;

function log(module, str) {
    console.log("<" + module + ": " + str + ">");
}

// Instruction handlers
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

var syscallPreHook = function(ctx) {};
var syscallPostHook = function(ctx) {};

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
                    iterator.putCallout(syscallPreHook);
                    iterator.keep();
                    iterator.putCallout(syscallPostHook);
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

    if (dangerousTracker !== null) {
        dangerousTracker.report();
    }
}

function initDangerousFunctions(configPath) {
    configPath = configPath || '/home/user/taint-with-frida/dangerous-functions.json';

    try {
        var configData = File.readAllText(configPath);
        var config = JSON.parse(configData);

        dangerousTracker = new DangerousFunctionTracker(taintEngine, config);

        dangerousTracker.initialize();

        log("tracker", "dangerous function tracking initialized");

        return dangerousTracker;
    } catch (e) {
        console.log("Error initializing dangerous function tracker: " + e.message);
        console.log("Make sure to run: python3 config-converter.py");
        return null;
    }
}

// ============================================================================
// Example Script Logic
// ============================================================================

// Initialize dangerous function tracking
initDangerousFunctions();

// Hook main to start taint tracking
var mainPtr = Module.findExportByName(null, 'main');
if (mainPtr !== null) {
    Interceptor.attach(mainPtr, {
        onEnter: function(args) {
            log("example", "=== Entering main() ===");

            // Start taint tracking
            startTracing(true);

            // Taint command line arguments
            var argc = this.context.rdi.toInt32();
            var argv = this.context.rsi;

            log("example", "argc = " + argc);

            for (var i = 0; i < argc; i++) {
                var argPtr = Memory.readPointer(argv.add(i * Process.pointerSize));
                var argStr = Memory.readCString(argPtr);
                var argLen = argStr.length;

                log("example", "Tainting argv[" + i + "]: " + argStr);
                memory.taint(argPtr, argLen);
            }
        }
    });
}

// Hook read syscall to taint data from stdin
syscallPreHook = function(ctx) {
    var syscallNum = ctx.rax.toInt32();

    if (syscallNum === 0) {
        var fd = ctx.rdi.toInt32();
        var buf = ctx.rsi;
        var count = ctx.rdx.toInt32();

        log("syscall", "read(fd=" + fd + ", buf=" + buf + ", count=" + count + ")");

        if (fd === 0 || fd >= 3) {
            memory.taint(buf, count);
            log("syscall", "Tainted " + count + " bytes from read()");
        }
    }
    else if (syscallNum === 60 || syscallNum === 231) {
        log("syscall", "exit() called - generating report");
        stopTracing();
        report();
    }
};

syscallPostHook = function(ctx) {
};

// Cleanup on exit
Process.setExceptionHandler(function(details) {
    log("exception", "Exception occurred: " + details.type);
    stopTracing();
    report();
    return false;
});

log("example", "Dangerous function tracker initialized");
log("example", "Waiting for program execution...");
