/**
 * GPU Proof-of-Work Solver (WebGPU with WebGL2 Fallback)
 * Forces massive parallel floats computation to exhaust CPU emulators (SwiftShader).
 */
export class GpuPowSolver {
    /**
     * Solve the GPU challenge.
     * @param {string} seed - The hexadecimal/string challenge seed from the server.
     * @param {number} iterations - Number of chaotic map iterations per thread.
     * @returns {Promise<{solution: string, platform: string, duration: number}>}
     */
    static async solve(seed, iterations = 200000) {
        const start = performance.now();
        const numericSeed = this._hashSeedToFloat(seed);

        try {
            if (navigator.gpu) {
                const result = await this._solveWebGPU(numericSeed, iterations);
                return {
                    solution: result,
                    platform: 'webgpu',
                    duration: performance.now() - start
                };
            }
        } catch (e) {
            console.warn('[GPU-PoW] WebGPU failed or disabled, falling back to WebGL2:', e);
            // Fallthrough to WebGL2
        }

        // Fallback to WebGL2
        try {
            const result = await this._solveWebGL2(numericSeed, iterations);
            return {
                solution: result,
                platform: 'webgl2',
                duration: performance.now() - start
            };
        } catch (e) {
            console.warn('[GPU-PoW] WebGL2 failed or disabled, falling back to WebGL1:', e);
            // Fallthrough to WebGL1
        }

        // Fallback to WebGL1
        try {
            const result = await this._solveWebGL1(numericSeed, iterations);
            return {
                solution: result,
                platform: 'webgl1',
                duration: performance.now() - start
            };
        } catch (e) {
            throw new Error(`[GPU-PoW] All GPU solvers (WebGPU, WebGL2, WebGL1) failed: ${e.message}`);
        }
    }

    /**
     * Verifies a GPU PoW solution.
     * To prevent server-side DoS, it verifies a sample of the 64 channels.
     * @param {string} seed - The challenge seed.
     * @param {number} iterations - Number of iterations.
     * @param {string} solution - The comma-separated solution string.
     * @param {Array<number>} [sampleIndices=[0, 12, 35, 57]] - Indices to verify.
     * @returns {boolean} True if the solution is valid.
     */
    static verify(seed, iterations, solution, sampleIndices = [0, 12, 35, 57]) {
        if (!solution || typeof solution !== 'string') return false;
        const values = solution.split(',');
        if (values.length !== 64) return false;

        const numericSeed = this._hashSeedToFloat(seed);
        const r = 3.9999;

        for (const idx of sampleIndices) {
            if (idx < 0 || idx >= 64) return false;
            let x = Math.fround(numericSeed + idx * 0.015);
            const rFloat = Math.fround(r);
            for (let i = 0; i < iterations; i++) {
                x = Math.fround(rFloat * x * Math.fround(1.0 - x));
            }
            const clientVal = parseFloat(values[idx]);
            if (isNaN(clientVal) || Math.abs(clientVal - x) > 1e-4) {
                return false;
            }
        }
        return true;
    }

    static _hashSeedToFloat(seed) {
        let hash = 0;
        for (let i = 0; i < seed.length; i++) {
            hash = (hash << 5) - hash + seed.charCodeAt(i);
            hash |= 0;
        }
        return Math.abs(hash % 1000000) / 1000000;
    }

    static async _solveWebGPU(seed, iterations) {
        const adapter = await navigator.gpu.requestAdapter();
        if (!adapter) throw new Error('No compatible GPU adapter found.');
        const device = await adapter.requestDevice();

        // Compute shader performing a chaotic logistic map iteration
        const shaderCode = `
            @group(0) @binding(0) var<storage, read_write> data: array<f32>;
            @compute @workgroup_size(64)
            fn main(@builtin(global_invocation_id) global_id: vec3<u32>) {
                let index = global_id.x;
                if (index >= 64) { return; }
                
                var x: f32 = data[index];
                let r: f32 = 3.9999; // Chaotic regime
                
                for (var i: u32 = 0u; i < ${iterations}u; i = i + 1u) {
                    x = r * x * (1.0 - x);
                }
                data[index] = x;
            }
        `;

        const shaderModule = device.createShaderModule({ code: shaderCode });
        const pipeline = device.createComputePipeline({
            layout: 'auto',
            compute: { module: shaderModule, entryPoint: 'main' }
        });

        const inputData = new Float32Array(64);
        for (let i = 0; i < 64; i++) {
            inputData[i] = seed + (i * 0.015);
        }

        const gpuBuffer = device.createBuffer({
            size: inputData.byteLength,
            usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_SRC | GPUBufferUsage.COPY_DST,
            mappedAtCreation: true
        });
        new Float32Array(gpuBuffer.getMappedRange()).set(inputData);
        gpuBuffer.unmap();

        const readBuffer = device.createBuffer({
            size: inputData.byteLength,
            usage: GPUBufferUsage.COPY_DST | GPUBufferUsage.MAP_READ
        });

        const bindGroup = device.createBindGroup({
            layout: pipeline.getBindGroupLayout(0),
            entries: [{ binding: 0, resource: { buffer: gpuBuffer } }]
        });

        const commandEncoder = device.createCommandEncoder();
        const passEncoder = commandEncoder.beginComputePass();
        passEncoder.setPipeline(pipeline);
        passEncoder.setBindGroup(0, bindGroup);
        passEncoder.dispatchWorkgroups(1);
        passEncoder.end();

        commandEncoder.copyBufferToBuffer(gpuBuffer, 0, readBuffer, 0, inputData.byteLength);
        device.queue.submit([commandEncoder.finish()]);

        await readBuffer.mapAsync(GPUMapMode.READ);
        const result = new Float32Array(readBuffer.getMappedRange());
        const solutionHash = Array.from(result).map(v => v.toFixed(6)).join(',');
        readBuffer.unmap();

        return solutionHash;
    }

    static async _solveWebGL2(seed, iterations) {
        const canvas = document.createElement('canvas');
        canvas.width = 8;
        canvas.height = 8; // 64 pixels total matching WebGPU size
        const gl = canvas.getContext('webgl2');
        if (!gl) throw new Error('WebGL2 context not supported.');

        const vs = `#version 300 es\nin vec4 pos; void main() { gl_Position = pos; }`;
        const fs = `#version 300 es
            precision highp float;
            out vec4 outColor;
            uniform float uSeed;
            uniform int uIterations;
            void main() {
                float index = gl_FragCoord.x + (gl_FragCoord.y * 8.0);
                float x = uSeed + (index * 0.015);
                float r = 3.9999;
                for(int i = 0; i < uIterations; i++) {
                    x = r * x * (1.0 - x);
                }
                outColor = vec4(x, 0.0, 0.0, 1.0);
            }`;

        // Setup programs, draw fullscreen quad, etc.
        const program = this._createProgram(gl, vs, fs);
        gl.useProgram(program);

        const posAttr = gl.getAttribLocation(program, 'pos');
        const buffer = gl.createBuffer();
        gl.bindBuffer(gl.ARRAY_BUFFER, buffer);
        gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1,-1, 1,-1, -1,1, -1,1, 1,-1, 1,1]), gl.STATIC_DRAW);
        gl.enableVertexAttribArray(posAttr);
        gl.vertexAttribPointer(posAttr, 2, gl.FLOAT, false, 0, 0);

        gl.uniform1f(gl.getUniformLocation(program, 'uSeed'), seed);
        gl.uniform1i(gl.getUniformLocation(program, 'uIterations'), iterations);

        gl.drawArrays(gl.TRIANGLES, 0, 6);

        const pixels = new Float32Array(8 * 8 * 4);
        gl.readPixels(0, 0, 8, 8, gl.RGBA, gl.FLOAT, pixels);

        const result = [];
        for (let i = 0; i < 64; i++) {
            result.push(pixels[i * 4]);
        }

        return result.map(v => v.toFixed(6)).join(',');
    }

    static async _solveWebGL1(seed, iterations) {
        const canvas = document.createElement('canvas');
        canvas.width = 8;
        canvas.height = 8; // 64 pixels total matching WebGPU size
        const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl'); // Get WebGL1 context with legacy fallback
        if (!gl) throw new Error('WebGL1 context not supported.');

        // WebGL1 Vertex Shader
        const vs = `
            attribute vec4 pos;
            void main() {
                gl_Position = pos;
            }`;
        // WebGL1 Fragment Shader
        const fs = `
            precision highp float; // highp float is an extension in WebGL1, but generally available
            uniform float uSeed;
            uniform int uIterations;
            void main() {
                float index = gl_FragCoord.x + (gl_FragCoord.y * 8.0);
                float x = uSeed + (index * 0.015);
                float r = 3.9999;
                for(int i = 0; i < uIterations; i++) {
                    x = r * x * (1.0 - x);
                }
                gl_FragColor = vec4(x, 0.0, 0.0, 1.0); // Use gl_FragColor for WebGL1
            }`;

        const program = this._createProgram(gl, vs, fs);
        gl.useProgram(program);

        const posAttr = gl.getAttribLocation(program, 'pos');
        const buffer = gl.createBuffer();
        gl.bindBuffer(gl.ARRAY_BUFFER, buffer);
        gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1,-1, 1,-1, -1,1, -1,1, 1,-1, 1,1]), gl.STATIC_DRAW);
        gl.enableVertexAttribArray(posAttr);
        gl.vertexAttribPointer(posAttr, 2, gl.FLOAT, false, 0, 0);

        gl.uniform1f(gl.getUniformLocation(program, 'uSeed'), seed);
        gl.uniform1i(gl.getUniformLocation(program, 'uIterations'), iterations);

        // Check for OES_texture_float and WEBGL_color_buffer_float extensions for float textures and readPixels
        const floatTextureExt = gl.getExtension('OES_texture_float');
        const floatColorBufferExt = gl.getExtension('WEBGL_color_buffer_float');

        if (!floatTextureExt || !floatColorBufferExt) {
            throw new Error('WebGL1 float texture/color buffer extensions not supported. Cannot read float pixels.');
        }

        // Create a framebuffer to render to a float texture
        const texture = gl.createTexture();
        gl.bindTexture(gl.TEXTURE_2D, texture);
        gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, canvas.width, canvas.height, 0, gl.RGBA, gl.FLOAT, null);
        gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.NEAREST);
        gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.NEAREST);
        gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
        gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);

        const fb = gl.createFramebuffer();
        gl.bindFramebuffer(gl.FRAMEBUFFER, fb);
        gl.framebufferTexture2D(gl.FRAMEBUFFER, gl.COLOR_ATTACHMENT0, gl.TEXTURE_2D, texture, 0);

        const status = gl.checkFramebufferStatus(gl.FRAMEBUFFER);
        if (status !== gl.FRAMEBUFFER_COMPLETE) {
            throw new Error('WebGL1 framebuffer not complete: ' + status);
        }

        gl.viewport(0, 0, canvas.width, canvas.height);
        gl.drawArrays(gl.TRIANGLES, 0, 6);

        const pixels = new Float32Array(canvas.width * canvas.height * 4);
        gl.readPixels(0, 0, canvas.width, canvas.height, gl.RGBA, gl.FLOAT, pixels);

        const result = [];
        for (let i = 0; i < 64; i++) {
            result.push(pixels[i * 4]); // Only take the R component
        }

        return result.map(v => v.toFixed(6)).join(',');
    }

    static _createProgram(gl, vsSource, fsSource) {
        const vs = gl.createShader(gl.VERTEX_SHADER);
        gl.shaderSource(vs, vsSource);
        gl.compileShader(vs);
        const fs = gl.createShader(gl.FRAGMENT_SHADER);
        gl.shaderSource(fs, fsSource);
        gl.compileShader(fs);
        
        const program = gl.createProgram();
        gl.attachShader(program, vs);
        gl.attachShader(program, fs);
        gl.linkProgram(program);
        return program;
    }
}