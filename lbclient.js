// lbclient: 门锁协议的客户端。网页和 Node 测试共用这一份。
// 依赖全局 crypto.subtle（浏览器 HTTPS 页面里有；Node 18+ 也有）。

export const SERVICE_UUID = '7fccd1ac-2263-4a58-a41d-ad562b49f039';
export const CHAL_UUID    = '7fccd1ad-2263-4a58-a41d-ad562b49f039';
export const CMD_UUID     = '7fccd1ae-2263-4a58-a41d-ad562b49f039';
export const RESP_UUID    = '7fccd1af-2263-4a58-a41d-ad562b49f039';
export const RDY_UUID     = '7fccd1b0-2263-4a58-a41d-ad562b49f039';  // 只用来通知"结果好了"

export const OP = { UNLOCK: 0x01, ADD_USER: 0x10, DEL_USER: 0x11, LIST: 0x12, LOG: 0x13, CONFIG: 0x14, MOTOR_TEST: 0x15, DFU: 0x16 };
export const ROLE = { NONE: 0, USER: 1, ADMIN: 2 };
export const STATUS = ['OK', 'BAD_MAC', 'NO_USER', 'NOT_ADMIN', 'BAD_ARGS', 'NO_NONCE', 'BUSY', 'BAD_FRAME', 'BAD_OP', 'FULL'];
export const NAME_LEN = 12;
export const CHUNK = 19;   // 每次写最多 19 字节数据 + 1 字节头，最小 MTU(23) 也能过

const te = new TextEncoder();

export function concat(...parts) {
  const n = parts.reduce((a, p) => a + p.length, 0);
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

export function toHex(b) { return [...b].map(x => x.toString(16).padStart(2, '0')).join(''); }
export function fromHex(s) {
  if (!/^([0-9a-fA-F]{2})*$/.test(s)) throw new Error('bad hex');
  return new Uint8Array(s.match(/../g)?.map(h => parseInt(h, 16)) ?? []);
}
export function toB64u(b) {
  let s = ''; for (const x of b) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
export function fromB64u(s) {
  const t = atob(s.replace(/-/g, '+').replace(/_/g, '/'));
  return Uint8Array.from(t, ch => ch.charCodeAt(0));
}

export async function hmac(key, data) {
  const k = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', k, data));
}

export function randomKey() { return crypto.getRandomValues(new Uint8Array(32)); }

export function nameBytes(name) {
  const b = new Uint8Array(NAME_LEN);
  b.set(te.encode(name).slice(0, NAME_LEN));
  return b;
}
export function nameString(b) {
  let n = b.indexOf(0); if (n < 0) n = b.length;
  return new TextDecoder().decode(b.slice(0, n));
}

// 一条命令帧：ver | user | op | len | args | mac16
export async function buildFrame(user, op, args, key, nonce) {
  const hdr = concat(new Uint8Array([1, user, op, args.length]), args);
  const mac = (await hmac(key, concat(te.encode('LBL1'), nonce, hdr))).slice(0, 16);
  return concat(hdr, mac);
}

export async function wrapKey(adminKey, nonce, newKey) {
  const pad = await hmac(adminKey, concat(te.encode('WRAP'), nonce));
  return newKey.map((x, i) => x ^ pad[i]);
}

export function parseChal(b) {
  return {
    nonce: b.slice(0, 16), proto: b[16], fw: b[17],
    battMv: b[18] | b[19] << 8, nonceValid: !!(b[20] & 1), busy: !!(b[20] & 2), users: b[21],
  };
}

export function parseResp(b) {
  return { status: b[0], statusName: STATUS[b[0]] ?? `ERR${b[0]}`, op: b[1], nonce: b.slice(2, 18), data: b.slice(18) };
}

// 把一帧切成带头的小块：头 = 块序号 | (最后一块 ? 0x80 : 0)
export function chunks(frame) {
  const out = [];
  for (let i = 0, k = 0; i < frame.length; i += CHUNK, k++) {
    const last = i + CHUNK >= frame.length;
    out.push(concat(new Uint8Array([k | (last ? 0x80 : 0)]), frame.slice(i, i + CHUNK)));
  }
  return out;
}

const u16 = v => new Uint8Array([v & 255, v >> 8 & 255]);
const u32 = v => new Uint8Array([v & 255, v >>> 8 & 255, v >>> 16 & 255, v >>> 24 & 255]);
const rd16 = (b, o) => b[o] | b[o + 1] << 8;
const rd32 = (b, o) => (b[o] | b[o + 1] << 8 | b[o + 2] << 16 | b[o + 3] << 24) >>> 0;

// 会话：transport 需要 readChal() 和 send(frame) -> 响应字节
export class Session {
  constructor(transport, slot, key) { this.t = transport; this.slot = slot; this.key = key; this.nonce = null; }

  async chal() { const c = parseChal(await this.t.readChal()); this.nonce = c.nonce; this.info = c; return c; }

  async cmd(op, args = new Uint8Array(0), argsFn = null) {
    // 手里的题可能已经被别人（同一连接上的另一个会话）用掉了：这种情况重新取题再试一次
    for (let attempt = 0; ; attempt++) {
      const fresh = !this.nonce;
      if (fresh) await this.chal();
      const a = argsFn ? await argsFn(this.nonce) : args;
      const frame = await buildFrame(this.slot, op, a, this.key, this.nonce);
      const r = parseResp(await this.t.send(frame));
      this.nonce = r.nonce;
      if (!fresh && attempt === 0 && (r.statusName === 'BAD_MAC' || r.statusName === 'NO_NONCE')) { this.nonce = null; continue; }
      return r;
    }
  }

  unlock(now = Math.floor(Date.now() / 1000)) { return this.cmd(OP.UNLOCK, u32(now)); }

  addUser(slot, role, name, newKey) {
    // 密钥加密要用当次的挑战码，所以参数在拿到题之后才算
    return this.cmd(OP.ADD_USER, null, async nonce =>
      concat(new Uint8Array([slot, role]), nameBytes(name), await wrapKey(this.key, nonce, newKey)));
  }

  delUser(slot) { return this.cmd(OP.DEL_USER, new Uint8Array([slot])); }

  async list() {
    const users = [];
    let start = 0;
    while (start !== 0xFF) {
      const r = await this.cmd(OP.LIST, new Uint8Array([start]));
      if (r.status) throw new Error('LIST ' + r.statusName);
      const d = r.data, n = d[1];
      for (let i = 0; i < n; i++) {
        const p = 2 + i * 14;
        users.push({ slot: d[p], role: d[p + 1], name: nameString(d.slice(p + 2, p + 14)) });
      }
      start = d[0];
    }
    return users;
  }

  // 日志：从第 start 条（0=最新）往旧的取，最多 limit 条。顺便把手机时间告诉锁（锁没有时钟）
  // 返回 { total, entries }。每条 count>1 表示合并了几次同样的失败；op=0xFF 表示那条断电写坏了
  async log(start = 0, limit = 50, now = Math.floor(Date.now() / 1000)) {
    const entries = [];
    let total = 0;
    for (;;) {
      const r = await this.cmd(OP.LOG, concat(u32(start + entries.length), u32(now)));
      if (r.status) throw new Error('LOG ' + r.statusName);
      const d = r.data, n = d[4];
      total = rd32(d, 0);
      for (let i = 0; i < n && entries.length < limit; i++) {
        const p = 5 + i * 14;
        entries.push({ index: start + entries.length, time: rd32(d, p), uptime: rd32(d, p + 4),
                       slot: d[p + 8], op: d[p + 9], result: d[p + 10], count: d[p + 11] });
      }
      if (n === 0 || entries.length >= limit || start + entries.length >= total) return { total, entries };
    }
  }

  async config(set) {
    // set.swap（0/1，可省）：电机线接反了就设 1，开关两路对调
    let args = new Uint8Array(0);
    if (set) {
      args = concat(u16(set.open_ms), u16(set.hold_ms), u16(set.close_ms));
      if (set.swap !== undefined) args = concat(args, new Uint8Array([set.swap ? 1 : 0]));
    }
    const r = await this.cmd(OP.CONFIG, args);
    if (r.status) return { status: r.statusName };
    return { status: 'OK', open_ms: rd16(r.data, 0), hold_ms: rd16(r.data, 2), close_ms: rd16(r.data, 4),
             swap: r.data.length > 6 ? r.data[6] : 0 };
  }

  motorTest(dir, ms) { return this.cmd(OP.MOTOR_TEST, concat(new Uint8Array([dir]), u16(ms))); }

  // 锁回完话以后重启进蓝牙升级模式（名字变 AdaDFU），用 nRF Connect 传固件
  enterDfu() { return this.cmd(OP.DFU); }
}

// 网页蓝牙的 transport
export class WebBleTransport {
  static async connect() {
    const dev = await navigator.bluetooth.requestDevice({ filters: [{ services: [SERVICE_UUID] }] });
    const t = new WebBleTransport();
    t.dev = dev;
    const gatt = await dev.gatt.connect();
    const svc = await gatt.getPrimaryService(SERVICE_UUID);
    t.chalC = await svc.getCharacteristic(CHAL_UUID);
    t.cmdC = await svc.getCharacteristic(CMD_UUID);
    t.respC = await svc.getCharacteristic(RESP_UUID);
    t.rdyC = await svc.getCharacteristic(RDY_UUID);
    t.waiter = null;
    t.rdyC.addEventListener('characteristicvaluechanged', () => { if (t.waiter) { const w = t.waiter; t.waiter = null; w(); } });
    await t.rdyC.startNotifications();
    return t;
  }
  async readChal() { return new Uint8Array((await this.chalC.readValue()).buffer); }
  async send(frame) {
    const done = new Promise((res, rej) => {
      this.waiter = res;
      setTimeout(() => { if (this.waiter === res) { this.waiter = null; rej(new Error('lock did not answer')); } }, 5000);
    });
    for (const c of chunks(frame)) await this.cmdC.writeValueWithResponse(c);
    await done;
    // 通知只说"好了"，完整结果用读的（长读，不受 MTU 限制）
    return new Uint8Array((await this.respC.readValue()).buffer);
  }
  disconnect() { try { this.dev.gatt.disconnect(); } catch {} }
}
