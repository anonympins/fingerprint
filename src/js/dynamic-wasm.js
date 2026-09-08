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

export class DynamicWasmGenerator {
    /**
     * Generates a unique polymorphic WebAssembly module containing a custom hash function
     * with randomized constants and control flow variables.
     * @param {object} constants - Custom seed, multiplier and adder.
     * @returns {Buffer} Valid WebAssembly binary buffer.
     */
    static generate(constants) {
        const { seed, multiplier, adder } = constants;

        const inst = [
            0x01, 0x02, 0x7f, // Locals: 1 entry of 2 locals of type i32
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