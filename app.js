const el = {
  pInput: document.getElementById("pInput"),
  qInput: document.getElementById("qInput"),
  eInput: document.getElementById("eInput"),
  plainInput: document.getElementById("plainInput"),
  keyOutput: document.getElementById("keyOutput"),
  cipherOutput: document.getElementById("cipherOutput"),
  decryptOutput: document.getElementById("decryptOutput"),
  timeline: document.getElementById("timeline"),
  genBtn: document.getElementById("genBtn"),
  encryptBtn: document.getElementById("encryptBtn"),
  decryptBtn: document.getElementById("decryptBtn"),
};

const state = {
  key: null,
  cipher: [],
};

function addStep(text, level = "ok") {
  const item = document.createElement("li");
  item.textContent = `${new Date().toLocaleTimeString()} - ${text}`;
  item.className = level;
  item.style.animationDelay = `${Math.min(el.timeline.children.length * 0.06, 0.5)}s`;
  el.timeline.appendChild(item);
}

function gcd(a, b) {
  let x = a;
  let y = b;
  while (y !== 0n) {
    const t = y;
    y = x % y;
    x = t;
  }
  return x;
}

function isPrime(n) {
  if (n < 2n) return false;
  if (n === 2n || n === 3n) return true;
  if (n % 2n === 0n) return false;
  for (let i = 3n; i * i <= n; i += 2n) {
    if (n % i === 0n) return false;
  }
  return true;
}

function modPow(base, exp, mod) {
  let result = 1n;
  let b = base % mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % mod;
    b = (b * b) % mod;
    e >>= 1n;
  }
  return result;
}

function modInverse(a, m) {
  let t = 0n;
  let newT = 1n;
  let r = m;
  let newR = a;

  while (newR !== 0n) {
    const q = r / newR;
    [t, newT] = [newT, t - q * newT];
    [r, newR] = [newR, r - q * newR];
  }

  if (r !== 1n) throw new Error("e 与 phi(n) 不互素，无法求逆元");
  if (t < 0n) t += m;
  return t;
}

function generateKeys() {
  const p = BigInt(el.pInput.value);
  const q = BigInt(el.qInput.value);
  const e = BigInt(el.eInput.value);

  if (!isPrime(p) || !isPrime(q)) {
    throw new Error("p 和 q 必须为质数");
  }

  const n = p * q;
  const phi = (p - 1n) * (q - 1n);

  if (gcd(e, phi) !== 1n) {
    throw new Error("e 必须与 phi(n) 互素");
  }

  const d = modInverse(e, phi);

  state.key = {
    p,
    q,
    n,
    phi,
    e,
    d,
  };

  el.keyOutput.textContent = [
    `p = ${p}`,
    `q = ${q}`,
    `n = p*q = ${n}`,
    `phi(n) = (p-1)*(q-1) = ${phi}`,
    `公钥 (e, n) = (${e}, ${n})`,
    `私钥 (d) = (${d})`,
  ].join("\n");

  addStep("已生成 RSA 密钥对", "ok");
}

function encryptText(text) {
  if (!state.key) throw new Error("请先生成密钥");

  const { e, n } = state.key;
  const cipher = [];

  for (const ch of text) {
    const m = BigInt(ch.charCodeAt(0));
    if (m >= n) {
      throw new Error("字符编码值大于等于 n，请增大 p 和 q");
    }
    cipher.push(modPow(m, e, n));
  }

  state.cipher = cipher;
  el.cipherOutput.textContent = `密文数组 C = [${cipher.map(String).join(", ")}]`;
  addStep(`完成加密，共 ${cipher.length} 个字符`, "ok");
}

function decryptCipher() {
  if (!state.key) throw new Error("请先生成密钥");
  if (state.cipher.length === 0) throw new Error("请先执行加密");

  const { d, n } = state.key;
  let plain = "";

  for (const c of state.cipher) {
    const m = modPow(c, d, n);
    plain += String.fromCharCode(Number(m));
  }

  el.decryptOutput.textContent = `解密结果 M = ${plain}`;
  addStep("完成解密，已恢复明文", "ok");
}

el.genBtn.addEventListener("click", () => {
  try {
    generateKeys();
  } catch (err) {
    addStep(err.message, "warn");
  }
});

el.encryptBtn.addEventListener("click", () => {
  try {
    encryptText(el.plainInput.value);
  } catch (err) {
    addStep(err.message, "warn");
  }
});

el.decryptBtn.addEventListener("click", () => {
  try {
    decryptCipher();
  } catch (err) {
    addStep(err.message, "warn");
  }
});

addStep("页面已加载，点击“生成 RSA 密钥”开始实验", "ok");
