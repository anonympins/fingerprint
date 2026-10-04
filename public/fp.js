var createFingerprintModule = (() => {
    var _scriptName = globalThis.document?.currentScript?.src;
    return async function (moduleArg = {}) {
        var Module = Object.assign({}, moduleArg);
        var ENVIRONMENT_IS_NODE = typeof process === "object" && Boolean(process?.versions?.node);
        var scriptDirectory = "";

        if (typeof __filename !== "undefined") {
            scriptDirectory = __dirname + "/";
        } else if (_scriptName) {
            try {
                scriptDirectory = new URL(".", _scriptName).href;
            } catch {}
        }

        function locateFile(path) {
            if (Module["locateFile"]) {
                return Module"locateFile";
            }
            return scriptDirectory + path;
        }

        async function getBinary(path) {
            if (Module["wasmBinary"]) {
                return Module["wasmBinary"];
            }
            if (ENVIRONMENT_IS_NODE) {
                var fs = await import("node:fs");
                return fs.readFileSync(path);
            }
            var response = await fetch(path, { credentials: "same-origin" });
            if (!response.ok) {
                throw new Error("Failed to fetch wasm binary at: " + path);
            }
            return response.arrayBuffer();
        }

        var wasmPath = locateFile("fp.wasm");
        var wasmBinary = await getBinary(wasmPath);
        var instantiated = await WebAssembly.instantiate(wasmBinary, {});
        var wasmExports = instantiated.instance.exports;
        var wasmMemory = wasmExports.memory;

        function updateMemoryViews() {
            var b = wasmMemory.buffer;
            Module.HEAP8 = new Int8Array(b);
            Module.HEAPU8 = new Uint8Array(b);
            Module.HEAPU32 = new Uint32Array(b);
            Module.HEAPF32 = new Float32Array(b);
            Module.buffer = b;
        }
        updateMemoryViews();

        var textEncoder = new TextEncoder();
        var textDecoder = new TextDecoder();

        Module["_malloc"] = Module["malloc"] = function (size) {
            var ptr = wasmExports.malloc(size);
            updateMemoryViews();
            return ptr;
        };

        Module["_free"] = Module["free"] = function (ptr) {
            wasmExports.free(ptr);
            updateMemoryViews();
        };

        Module["stringToUTF8"] = function (str, outPtr, maxBytes) {
            var encoded = textEncoder.encode(str);
            var len = maxBytes !== undefined ? Math.min(encoded.length, maxBytes - 1) : encoded.length;
            updateMemoryViews();
            Module.HEAPU8.set(encoded.subarray(0, len), outPtr);
            Module.HEAPU8[outPtr + len] = 0;
            return len;
        };

        Module["UTF8ToString"] = function (ptr) {
            updateMemoryViews();
            var end = ptr;
            while (Module.HEAPU8[end] !== 0) end++;
            return textDecoder.decode(Module.HEAPU8.subarray(ptr, end));
        };

        Module["_hash_string"] = function (strOrPtr) {
            updateMemoryViews();
            var ptr = strOrPtr;
            var mustFree = false;
            if (typeof strOrPtr === "string") {
                var encoded = textEncoder.encode(strOrPtr);
                ptr = Module"_malloc";
                Module.HEAPU8.set(encoded, ptr);
                Module.HEAPU8[ptr + encoded.length] = 0;
                mustFree = true;
            }
            var res = wasmExports.hash_string(ptr);
            if (mustFree) Module"_free";
            return typeof res === "bigint" ? Number(res) : res;
        };

        Module["_solve_cpu_target"] = function (baseBlockPtr, baseBlockLen, targetHexPtr) {
            updateMemoryViews();
            return wasmExports.solve_cpu_target(baseBlockPtr, baseBlockLen, targetHexPtr);
        };

        Module["_solve_memory_challenge"] = function (seedPtr, difficultyMb) {
            updateMemoryViews();
            var ptr = seedPtr;
            var mustFree = false;
            if (typeof seedPtr === "string") {
                var encoded = textEncoder.encode(seedPtr);
                ptr = Module"_malloc";
                Module.HEAPU8.set(encoded, ptr);
                Module.HEAPU8[ptr + encoded.length] = 0;
                mustFree = true;
            }
            var res = wasmExports.solve_memory_challenge(ptr, difficultyMb);
            if (mustFree) Module"_free";
            return res;
        };

        Module["_generate_gpu_pow_trajectory"] = function (seedPtr, iterations, outputPtr) {
            updateMemoryViews();
            var ptr = seedPtr;
            var mustFree = false;
            if (typeof seedPtr === "string") {
                var encoded = textEncoder.encode(seedPtr);
                ptr = Module"_malloc";
                Module.HEAPU8.set(encoded, ptr);
                Module.HEAPU8[ptr + encoded.length] = 0;
                mustFree = true;
            }
            wasmExports.generate_gpu_pow_trajectory(ptr, iterations, outputPtr);
            if (mustFree) Module"_free";
            updateMemoryViews();
        };

        Module["memory"] = wasmMemory;
        Module["wasmExports"] = wasmExports;

        if (typeof Module["onRuntimeInitialized"] === "function") {
            Module"onRuntimeInitialized";
        }

        return Module;
    };
})();

if (typeof exports === "object" && typeof module === "object") {
    module.exports = createFingerprintModule;
    module.exports.default = createFingerprintModule;
} else if (typeof define === "function" && define["amd"]) {
    define([], () => createFingerprintModule);
}
