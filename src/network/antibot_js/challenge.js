(function () {
  const P = __PARAMS__;
  const KEY = "__KEY__", TOKEN = "__TOKEN__", WORKER = __WORKER__;
  // The solution travels encrypted (AES-256-GCM) with a key that exists only
  // for this challenge, sent in this script — served once, at a URL unique
  // to this page — and forgotten by ProxyAuth after one use or two minutes.
  const b64u = (b) => btoa(String.fromCharCode.apply(null, Array.from(new Uint8Array(b))))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const unb64 = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
  async function seal(text) {
    const enc = new TextEncoder();
    const k = await crypto.subtle.importKey("raw", unb64(KEY), "AES-GCM", false, ["encrypt"]);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv, additionalData: enc.encode(TOKEN) }, k, enc.encode(text));
    return { iv: b64u(iv), c: b64u(ct) };
  }
  const $ = (id) => document.getElementById(id);
  const say = (t) => { $("status").textContent = t; };
  const fail = (t) => { say(t); $("status").style.color = "#ff6868"; };
  const pct = (p, extra) => { $("pa-fill").style.width = p.toFixed(1) + "%"; if (extra !== undefined) $("pa-stats").textContent = extra; };

  // The search runs in plain JavaScript; WebCrypto only encrypts the answer.
  if (!window.Worker || !window.crypto || !crypto.subtle) { fail(P.t.need_https); return; }
  const w = window.innerWidth || 0, h = window.innerHeight || 0;
  const wd = navigator.webdriver ? 1 : 0;

  // ── Rendu WebGL : 4 passes d'un shader dont la couleur dépend du challenge.
  let wg = "", renderer = "", vendor = "", glver = "";
  function webgl() {
    const c = document.createElement("canvas"); c.width = c.height = 16;
    const gl = c.getContext("webgl", { preserveDrawingBuffer: true, antialias: false }) || c.getContext("experimental-webgl");
    if (!gl) return false;
    const dbg = gl.getExtension("WEBGL_debug_renderer_info");
    renderer = String(dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER));
    vendor = String(dbg ? gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) : gl.getParameter(gl.VENDOR));
    glver = String(gl.getParameter(gl.VERSION));
    const sh = (t, s) => { const x = gl.createShader(t); gl.shaderSource(x, s); gl.compileShader(x); return x; };
    const prog = gl.createProgram();
    gl.attachShader(prog, sh(gl.VERTEX_SHADER, "attribute vec2 p;void main(){gl_Position=vec4(p,0.0,1.0);}"));
    gl.attachShader(prog, sh(gl.FRAGMENT_SHADER,
      "precision highp float;uniform vec3 u;uniform float k;" +
      "void main(){vec3 v=mod(u*7.0+vec3(k*31.0,k*17.0+3.0,k*13.0+11.0),256.0);gl_FragColor=vec4(v/255.0,1.0);}"));
    gl.linkProgram(prog);
    if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) return false;
    gl.useProgram(prog);
    const buf = gl.createBuffer(); gl.bindBuffer(gl.ARRAY_BUFFER, buf);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW);
    const loc = gl.getAttribLocation(prog, "p"); gl.enableVertexAttribArray(loc); gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);
    const uu = gl.getUniformLocation(prog, "u"), uk = gl.getUniformLocation(prog, "k");
    const px = new Uint8Array(4), out = [];
    for (let k = 0; k < 4; k++) {
      const b = (i) => parseInt(P.challenge.substr((k * 3 + i) * 2, 2), 16);
      gl.uniform3f(uu, b(0), b(1), b(2)); gl.uniform1f(uk, k);
      gl.viewport(0, 0, 16, 16); gl.drawArrays(gl.TRIANGLES, 0, 3);
      gl.readPixels(8, 8, 1, 1, gl.RGBA, gl.UNSIGNED_BYTE, px);
      out.push(px[0], px[1], px[2]);
    }
    wg = out.map((x) => x.toString(16).padStart(2, "0")).join("");
    return true;
  }


  // ── Graphics-card check (gpu_check): a nonce search in a WebGPU compute
  // shader, else in a WebGL 2 fragment shader. ProxyAuth times it itself,
  // between /start (which reveals the seed) and /done.
  let gpuAdapter = "";
  // Extra bits the server requires after the GPU test (on_software: harder).
  let gpuExtra = 0;
  const gpuDone = async (base, query) => {
    try {
      const r = await fetch(base + "/done?" + query + "&r=" + encodeURIComponent(renderer) + "&ga=" + encodeURIComponent(gpuAdapter), { credentials: "same-origin" });
      const x = await r.json();
      gpuExtra = Math.max(0, Math.min(16, x.extra | 0));
    } catch (e) {}
  };
  const GPU_HASH_WGSL = `fn h(seed: u32, n: u32) -> u32 { var x = seed ^ n; for (var i = 0u; i < 32u; i++) {
      x ^= x >> 16u; x *= 0x7feb352du; x ^= x >> 15u; x *= 0x846ca68bu; x ^= x >> 16u; x += 0x9e3779b9u + i; } return x; }`;
  async function webgpuRunner() {
    if (!navigator.gpu) return null;
    const adapter = await navigator.gpu.requestAdapter();
    if (!adapter) return null;
    try { const i = adapter.info || (adapter.requestAdapterInfo ? await adapter.requestAdapterInfo() : {}); gpuAdapter = [i.vendor, i.architecture].filter(Boolean).join("/"); } catch (e) {}
    const device = await adapter.requestDevice();
    const module = device.createShaderModule({ code: GPU_HASH_WGSL + `
      @group(0) @binding(0) var<storage, read_write> found: atomic<u32>;
      @group(0) @binding(1) var<uniform> p: vec4<u32>;
      @compute @workgroup_size(256) fn main(@builtin(global_invocation_id) id: vec3<u32>) {
        let n = p.z + id.x;
        if ((h(p.x, n) >> (32u - p.y)) == 0u) { atomicMin(&found, n); } }` });
    const pipeline = device.createComputePipeline({ layout: "auto", compute: { module, entryPoint: "main" } });
    const found = device.createBuffer({ size: 4, usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_SRC | GPUBufferUsage.COPY_DST });
    const params = device.createBuffer({ size: 16, usage: GPUBufferUsage.UNIFORM | GPUBufferUsage.COPY_DST });
    const read = device.createBuffer({ size: 4, usage: GPUBufferUsage.MAP_READ | GPUBufferUsage.COPY_DST });
    const group = device.createBindGroup({ layout: pipeline.getBindGroupLayout(0), entries: [{ binding: 0, resource: { buffer: found } }, { binding: 1, resource: { buffer: params } }] });
    const BATCH = 65535 * 256;
    return { api: "webgpu", batch: BATCH, async search(seed, bits, start) {
      device.queue.writeBuffer(found, 0, new Uint32Array([0xffffffff]));
      device.queue.writeBuffer(params, 0, new Uint32Array([seed, bits, start, 0]));
      const enc = device.createCommandEncoder(); const pass = enc.beginComputePass();
      pass.setPipeline(pipeline); pass.setBindGroup(0, group); pass.dispatchWorkgroups(65535); pass.end();
      enc.copyBufferToBuffer(found, 0, read, 0, 4); device.queue.submit([enc.finish()]);
      await read.mapAsync(GPUMapMode.READ); const v = new Uint32Array(read.getMappedRange())[0]; read.unmap();
      return v === 0xffffffff ? -1 : v; } };
  }
  function webgl2Runner() {
    const c = document.createElement("canvas"); const S = 1024; c.width = c.height = S;
    const gl = c.getContext("webgl2", { antialias: false, preserveDrawingBuffer: false });
    if (!gl) return null;
    const sh = (t, src) => { const x = gl.createShader(t); gl.shaderSource(x, src); gl.compileShader(x); return x; };
    const prog = gl.createProgram();
    gl.attachShader(prog, sh(gl.VERTEX_SHADER, "#version 300 es\nin vec2 q; void main(){ gl_Position = vec4(q, 0.0, 1.0); }"));
    gl.attachShader(prog, sh(gl.FRAGMENT_SHADER, "#version 300 es\nprecision highp float; precision highp int;\n" +
      "uniform uint seed; uniform uint bits; uniform uint start; out vec4 o;\n" +
      "uint h(uint s, uint n){ uint x = s ^ n; for (uint i = 0u; i < 32u; i++) { x ^= x >> 16u; x *= 0x7feb352du; x ^= x >> 15u; x *= 0x846ca68bu; x ^= x >> 16u; x += 0x9e3779b9u + i; } return x; }\n" +
      "void main(){ uint n = start + uint(gl_FragCoord.y) * 1024u + uint(gl_FragCoord.x); o = ((h(seed, n) >> (32u - bits)) == 0u) ? vec4(1.0) : vec4(0.0); }"));
    gl.linkProgram(prog);
    if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) return null;
    gl.useProgram(prog);
    const buf = gl.createBuffer(); gl.bindBuffer(gl.ARRAY_BUFFER, buf);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW);
    const loc = gl.getAttribLocation(prog, "q"); gl.enableVertexAttribArray(loc); gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);
    const us = gl.getUniformLocation(prog, "seed"), ub = gl.getUniformLocation(prog, "bits"), ut = gl.getUniformLocation(prog, "start");
    const px = new Uint8Array(S * S * 4);
    return { api: "webgl2", batch: S * S, async search(seed, bits, start) {
      gl.uniform1ui(us, seed); gl.uniform1ui(ub, bits); gl.uniform1ui(ut, start >>> 0);
      gl.viewport(0, 0, S, S); gl.drawArrays(gl.TRIANGLES, 0, 3);
      gl.readPixels(0, 0, S, S, gl.RGBA, gl.UNSIGNED_BYTE, px);
      for (let i = 0; i < S * S; i++) if (px[i * 4]) return (start + i) >>> 0;
      return -1; } };
  }
  async function gpuStage() {
    if (!P.gpu) return;
    const base = "/.proxyauth/antibot/gpu/" + TOKEN;
    let runner = null;
    try {
      if (P.gpu.mode !== "webgl2") runner = await webgpuRunner();
      if (!runner && P.gpu.mode !== "webgpu") runner = webgl2Runner();
    } catch (e) { runner = null; }
    if (!runner) { await gpuDone(base, "api=none"); return; }
    say(P.t.gpu);
    const st = await (await fetch(base + "/start", { credentials: "same-origin" })).json();
    const t0 = performance.now(); let found = -1, start = 0;
    while (found < 0 && performance.now() - t0 < P.gpu.budget && start < 4294967296) {
      found = await runner.search(st.seed, st.bits, start);
      start += runner.batch;
    }
    await gpuDone(base, "api=" + runner.api + "&n=" + found);
  }
  // ── Preuve de travail.
  function work() {
    // `client_cores`: every core (0), or cores / n - 1, at least 1.
    const hw = navigator.hardwareConcurrency || 2;
    const threads = P.single ? 1 : (P.cores ? Math.max(1, Math.floor(hw / P.cores) - 1) : Math.max(1, hw));
    // `scale_with_workers`: one more bit (twice the work) per doubling of
    // the workers, so every visitor waits about as long.
    const extra = P.scale ? Math.min(8, Math.floor(Math.log2(threads))) : 0;
    const bits = 4 * P.d + extra + gpuExtra;
    const expected = Math.pow(2, bits);
    const src = WORKER;
    const url = URL.createObjectURL(new Blob([src], { type: "text/javascript" }));
    const workers = []; let total = 0, finished = false; const t0 = performance.now();
    say(P.t.running.replace("{d}", P.d + (extra ? " +" + extra + " bits" : "")).replace("{a}", P.a).replace("{n}", threads).replace("{cores}", threads > 1 ? P.t.cores : P.t.core));
    for (let i = 0; i < threads; i++) {
      const wk = new Worker(url);
      wk.onmessage = (e) => {
        if (finished) return;
        if (e.data.progress) {
          total += e.data.progress;
          const s = (performance.now() - t0) / 1000;
          pct(Math.min(99, (1 - Math.exp(-total / expected)) * 100),
              total.toLocaleString() + " hashes · " + (s > 0.2 ? Math.round(total / s).toLocaleString() + " H/s" : "–"));
          return;
        }
        if (e.data.found !== undefined) {
          finished = true; total += e.data.done;
          workers.forEach((x) => x.terminate());
          pct(100, total.toLocaleString() + " hashes");
          say(P.t.done);
          const q = new URLSearchParams({ challenge: P.challenge, ts: P.ts, d: P.d, a: P.a, ttl: P.ttl, s: P.s, f: P.f,
            nonce: e.data.found, redir: P.redir, wk: threads, ga: gpuAdapter, wg: wg, r: renderer, v: vendor, gv: glver, w: w, h: h, wd: wd,
            sw: (screen && screen.width) || 0, sh: (screen && screen.height) || 0, dpr: window.devicePixelRatio || 1,
            c: navigator.hardwareConcurrency || 0, l: navigator.language || "",
            p: (navigator.userAgentData && navigator.userAgentData.platform) || navigator.platform || "",
            tz: (Intl.DateTimeFormat().resolvedOptions().timeZone) || "",
            elapsed: Math.round(performance.now() - t0) });
          const payload = JSON.stringify(Object.fromEntries(q.entries()));
          seal(payload)
            .then((x) => location.replace(P.pass + "?t=" + TOKEN + "&iv=" + x.iv + "&c=" + x.c))
            .catch(() => fail(P.t.need_https));
        }
      };
      wk.onerror = () => fail(P.t.worker_failed);
      wk.postMessage({ challenge: P.challenge, bits: bits, a: P.a, start: i, step: threads });
      workers.push(wk);
    }
  }

  // Le rendu est toujours tenté (ses informations vont au journal) ; il
  // n'est exigé qu'avec `webgl: true`.
  let glOk = false; try { glOk = webgl(); } catch (e) { glOk = false; }
  if (P.webgl && !glOk) { fail(P.t.need_webgl); return; }
  // ── Délai de démarrage, imposé par le serveur.
  const begin = performance.now();
  (function tick() {
    const left = P.s - (performance.now() - begin);
    if (left <= 0) { pct(0, ""); gpuStage().catch(() => {}).finally(work); return; }
    say(P.t.starting.replace("{s}", Math.ceil(left / 1000)));
    pct(0, "");
    setTimeout(tick, Math.min(250, left));
  })();
})();
