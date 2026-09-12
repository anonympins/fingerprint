import crypto from "node:crypto";

function encodeULEB128(val) {
    const bytes = [];
    let num = val >>> 0;
    do {
        let byte = num & 0x7f;
        num >>>= 7;
        if (num !== 0) byte |= 0x80;
        bytes.push(byte);
    } while (num !== 0);
    return bytes;
}

function encodeSLEB128(val) {
    const bytes = [];
    let num = val | 0;
    while (true) {
        let byte = num & 0x7f;
        num >>= 7;
        if ((num === 0 && (byte & 0x40) === 0) || (num === -1 && (byte & 0x40) !== 0)) {
            bytes.push(byte);
            break;
        }
        bytes.push(byte | 0x80);
    }
    return bytes;
}

function getRandomNonTrivialOpcodes(tempLocal) {
    const insts = [];
    const ops = [
        // local.get tempLocal, i32.const rand, rotl, local.set tempLocal
        () => [0x20, tempLocal, 0x41, ...encodeSLEB128(Math.floor(Math.random() * 31) + 1), 0x77, 0x21, tempLocal],
        // local.get tempLocal, i32.const rand, rotr, local.set tempLocal
        () => [0x20, tempLocal, 0x41, ...encodeSLEB128(Math.floor(Math.random() * 31) + 1), 0x78, 0x21, tempLocal],
        // local.get tempLocal, i32.const rand, xor, local.set tempLocal
        () => [0x20, tempLocal, 0x41, ...encodeSLEB128(Math.floor(Math.random() * 10000)), 0x73, 0x21, tempLocal],
        // local.get tempLocal, popcnt, i32.const rand, mul, local.set tempLocal
        () => [0x20, tempLocal, 0x69, 0x41, ...encodeSLEB128(Math.floor(Math.random() * 1000) + 1), 0x6c, 0x21, tempLocal],
        // local.get tempLocal, clz, local.get tempLocal, ctz, add, local.set tempLocal
        () => [0x20, tempLocal, 0x67, 0x20, tempLocal, 0x68, 0x6a, 0x21, tempLocal]
    ];
    const count = 2 + Math.floor(Math.random() * 3);
    for (let i = 0; i < count; i++) {
        const op = ops[Math.floor(Math.random() * ops.length)];
        insts.push(...op());
    }
    return insts;
}

function generatePolymorphicInstructions(stateLocal = 4, tempLocal = 5) {
    const insts = [];
    
    // Initialize tempLocal with a random value
    const initVal = Math.floor(Math.random() * 1000) - 500;
    insts.push(0x41, ...encodeSLEB128(initVal), 0x21, tempLocal);

    // Initialize stateLocal to 0
    insts.push(0x41, ...encodeSLEB128(0), 0x21, stateLocal);

    // Loop & Block for state machine
    insts.push(0x03, 0x40); // loop
    insts.push(0x02, 0x40); // block

    for (let state = 0; state < 3; state++) {
        insts.push(0x20, stateLocal, 0x41, ...encodeSLEB128(state), 0x46); // state == expected
        insts.push(0x04, 0x40); // if
        insts.push(...getRandomNonTrivialOpcodes(tempLocal));
        insts.push(0x41, ...encodeSLEB128(state + 1), 0x21, stateLocal); // transit to state + 1
        insts.push(0x0c, ...encodeULEB128(2)); // br 2 (targets loop start)
        insts.push(0x0b); // end if
    }

    // Fallthrough / Default break (targets block depth 0, which exits the loop)
    insts.push(0x0c, ...encodeULEB128(0));

    // end block
    insts.push(0x0b);
    // end loop
    insts.push(0x0b);

    return insts;
}

export class DynamicWasmGenerator {
    /**
     * Generates a unique polymorphic WebAssembly module containing a custom hash function
     * with randomized constants and control flow variables.
     * @param {object} constants - Custom seed, multiplier and adder.
     * @returns {Buffer} Valid WebAssembly binary buffer.
     */
    static generate(constants) {
        const { seed, multiplier, adder } = constants;

        const preLoopPoly = generatePolymorphicInstructions(4, 5);
        const midLoopPoly = generatePolymorphicInstructions(4, 5);

        const inst = [
            0x01, 0x06, 0x7f, // Locals: 1 entry of 6 locals of type i32
            ...preLoopPoly,
            // h = seed
            0x41, ...encodeSLEB128(seed),
            0x21, 0x03,
            // i = 0
            0x41, 0x00,
            0x21, 0x02,

            // block
            0x02, 0x40,
            // loop
            0x03, 0x40,

            // if i >= len break
            0x20, 0x02,
            0x20, 0x01,
            0x4f,
            0x0d, 0x01,

            // byte = load8_u(ptr + i)
            0x20, 0x00,
            0x20, 0x02,
            0x6a,
            0x2d, 0x00, 0x00,

            // h = h ^ byte
            0x20, 0x03,
            0x73,

            // h = h * multiplier
            0x41, ...encodeSLEB128(multiplier),
            0x6c,

            // h = h + adder
            0x41, ...encodeSLEB128(adder),
            0x6a,

            // local.set 3
            0x21, 0x03,
            ...midLoopPoly,

            // i = i + 1
            0x20, 0x02,
            0x41, 0x01,
            0x6a,
            0x21, 0x02,

            // br 0
            0x0c, 0x00,

            0x0b, // end loop
            0x0b, // end block

            // return h
            0x20, 0x03,
            0x0b // end function
        ];

        const funcBody = [
            ...encodeULEB128(inst.length),
            ...inst
        ];

        const codeSectionPayload = [
            ...encodeULEB128(1),
            ...funcBody
        ];

        const codeSection = [
            0x0a,
            ...encodeULEB128(codeSectionPayload.length),
            ...codeSectionPayload
        ];

        const typeSection = [
            0x01, 0x07, 0x01, 0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f
        ];

        const funcSection = [
            0x03, 0x02, 0x01, 0x00
        ];

        const memSection = [
            0x05, 0x03, 0x01, 0x00, 0x01
        ];

        const exportSection = [
            0x07, 0x11, 0x02, 0x04, 0x68, 0x61, 0x73, 0x68, 0x00, 0x00, 0x06, 0x6d, 0x65, 0x6d, 0x6f, 0x72, 0x79, 0x02, 0x00
        ];

        const wasm = [
            0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
            ...typeSection,
            ...funcSection,
            ...memSection,
            ...exportSection,
            ...codeSection
        ];

        return Buffer.from(wasm);
    }

    /**
     * Pure JavaScript fallback equivalent of the custom polymorphic hash.
     * @param {string} str Input string.
     * @param {object} constants Parameters.
     * @returns {number} 32-bit unsigned integer hash.
     */
    static hashJs(str, constants) {
        const { seed, multiplier, adder } = constants;
        let h = seed | 0;
        for (let i = 0; i < str.length; i++) {
            const byte = str.charCodeAt(i) & 0xff;
            h = h ^ byte;
            h = Math.imul(h, multiplier) + adder;
        }
        return h >>> 0;
    }
}