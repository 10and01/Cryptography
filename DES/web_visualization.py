"""DES Web 可视化：仅保留浏览器滚动演示，并内置每阶段模块框架图。"""

import html
import os
import webbrowser

try:
  from Des import DES as _DESBase
except ImportError:
  from Des import PureDES as _DESBase


class DESTrace(_DESBase):
  """在原 DES 算法上补充轮次追踪数据。"""

  def fmt_hex(self, b):
    return hex(int(b, 2))[2:].upper().zfill(len(b) // 4)

  def f_trace(self, r_block, subkey):
    expanded = self._permute(r_block, self.E)
    xor_res = self._xor(expanded, subkey)

    s_out = ""
    for i in range(8):
      block = xor_res[i * 6:i * 6 + 6]
      row = int(block[0] + block[5], 2)
      col = int(block[1:5], 2)
      s_out += f"{self.S_BOX[i][row][col]:04b}"

    p_out = self._permute(s_out, self.P)
    return {
      "expanded": expanded,
      "xor_res": xor_res,
      "s_out": s_out,
      "p_out": p_out,
    }

  def process_block_trace(self, block_64, decrypt=False):
    ip_block = self._permute(block_64, self.IP)
    l, r = ip_block[:32], ip_block[32:]

    keys = list(reversed(self.subkeys)) if decrypt else list(self.subkeys)
    rounds = []
    for i, key in enumerate(keys, 1):
      f_data = self.f_trace(r, key)
      l_next = r
      r_next = self._xor(l, f_data["p_out"])

      rounds.append({
        "round": i,
        "key_label": 17 - i if decrypt else i,
        "subkey": self.fmt_hex(key),
        "l_before": l,
        "r_before": r,
        "expanded": f_data["expanded"],
        "xor_res": f_data["xor_res"],
        "s_out": f_data["s_out"],
        "f_result": f_data["p_out"],
        "l_after": l_next,
        "r_after": r_next,
      })
      l, r = l_next, r_next

    pre_output = r + l
    out_block = self._permute(pre_output, self.PI)
    return {
      "ip_block": ip_block,
      "l0": ip_block[:32],
      "r0": ip_block[32:],
      "rounds": rounds,
      "pre_output": pre_output,
      "out_block": out_block,
    }


class DESHTMLVisualizer:
  """Web 浏览器可视化（PPT 风格滚动）。"""

  def __init__(self, key_str):
    self.key = key_str[:8].ljust(8, "0")
    self.des = DESTrace(self.key)

  def _fmt_bin(self, b, group=8):
    return " ".join(b[i:i + group] for i in range(0, len(b), group))

  def _kv(self, label, value):
    return f"<div class='kv'><span>{label}</span><code>{html.escape(value)}</code></div>"

  def _framework(self, active):
    stages = [
      ("input", "输入/填充"),
      ("ip", "初始置换 IP"),
      ("key", "子密钥生成 PC1/PC2"),
      ("expand", "扩展置换 E"),
      ("xor", "与子密钥 XOR"),
      ("sbox", "S 盒替换"),
      ("pbox", "P 盒置换"),
      ("feistel", "Feistel 更新"),
      ("final", "交换 + PI"),
      ("output", "输出"),
    ]
    cells = []
    for key, label in stages:
      cls = "module active" if key == active else "module"
      cells.append(f"<div class='{cls}'>{label}</div>")
    return f"<div class='framework'>{''.join(cells)}</div>"

  def _f_diagram(self):
    return """
    <div class='f-diagram'>
      <div class='f-box'>R(32)</div>
      <div class='f-arrow'>-></div>
      <div class='f-box'>E 扩展(48)</div>
      <div class='f-arrow'>-></div>
      <div class='f-box'>XOR 子密钥</div>
      <div class='f-arrow'>-></div>
      <div class='f-box'>S 盒(32)</div>
      <div class='f-arrow'>-></div>
      <div class='f-box'>P 置换(32)</div>
    </div>
    """

  def _slide(self, title, subtitle, content, active_stage):
    return f"""
    <section class='slide'>
      <div class='card'>
      <h2>{title}</h2>
      <p class='slide-subtitle'>{subtitle}</p>
      {self._framework(active_stage)}
      {content}
      </div>
    </section>
    """

  def _collect_trace(self, plaintext):
    padded = self.des._pad(plaintext)
    bin_text = self.des._str_to_bin(padded)

    enc_blocks = []
    cipher_bin = ""
    for i in range(0, len(bin_text), 64):
      in_block = bin_text[i:i + 64]
      trace = self.des.process_block_trace(in_block, decrypt=False)
      cipher_bin += trace["out_block"]
      enc_blocks.append({
        "index": i // 64 + 1,
        "in_block": in_block,
        "trace": trace,
      })

    cipher_hex = hex(int(cipher_bin, 2))[2:].upper().zfill(len(cipher_bin) // 4)

    dec_blocks = []
    recovered_bin = ""
    for i in range(0, len(cipher_bin), 64):
      in_block = cipher_bin[i:i + 64]
      trace = self.des.process_block_trace(in_block, decrypt=True)
      recovered_bin += trace["out_block"]
      dec_blocks.append({
        "index": i // 64 + 1,
        "in_block": in_block,
        "trace": trace,
      })

    recovered_padded = self.des._bin_to_str(recovered_bin)
    recovered = self.des._unpad(recovered_padded)
    return {
      "plaintext": plaintext,
      "padded": padded,
      "cipher_hex": cipher_hex,
      "enc_blocks": enc_blocks,
      "dec_blocks": dec_blocks,
      "recovered": recovered,
    }

  def generate_html(self, plaintext):
    trace = self._collect_trace(plaintext)
    slides = []

    intro = "".join([
      self._kv("密钥", repr(self.key)),
      self._kv("原始明文", repr(trace["plaintext"])),
      self._kv("填充后明文", repr(trace["padded"])),
      self._kv("最终密文(HEX)", trace["cipher_hex"]),
    ])
    slides.append(self._slide(
      "DES Web 可视化演示",
      "仅保留浏览器滚动演示，向下滚动像 PPT 一样播放",
      intro,
      "input",
    ))

    for block in trace["enc_blocks"]:
      t = block["trace"]
      slides.append(self._slide(
        f"加密块 {block['index']} - IP 阶段",
        "本页对应模块：初始置换 IP",
        "".join([
          self._kv("输入块(HEX)", self.des.fmt_hex(block["in_block"])),
          self._kv("输入块(BIN)", self._fmt_bin(block["in_block"])),
          self._kv("IP 后 L0", self._fmt_bin(t["l0"])),
          self._kv("IP 后 R0", self._fmt_bin(t["r0"])),
        ]),
        "ip",
      ))

      for r in t["rounds"]:
        round_kv = "".join([
          self._f_diagram(),
          self._kv(f"子密钥 K{r['key_label']}", r["subkey"]),
          self._kv(f"L{r['round'] - 1}", self._fmt_bin(r["l_before"])),
          self._kv(f"R{r['round'] - 1}", self._fmt_bin(r["r_before"])),
          self._kv("E 扩展输出", self._fmt_bin(r["expanded"], 6)),
          self._kv("XOR 输出", self._fmt_bin(r["xor_res"], 6)),
          self._kv("S 盒输出", self._fmt_bin(r["s_out"], 4)),
          self._kv("f(R,K)=P 输出", self._fmt_bin(r["f_result"])),
          self._kv(f"L{r['round']}", self._fmt_bin(r["l_after"])),
          self._kv(f"R{r['round']}", self._fmt_bin(r["r_after"])),
        ])
        slides.append(self._slide(
          f"加密第 {r['round']} 轮",
          f"本页对应模块：E -> XOR -> S 盒 -> P 盒 -> Feistel 更新（K{r['key_label']}）",
          round_kv,
          "expand",
        ))

      slides.append(self._slide(
        f"加密块 {block['index']} - 输出阶段",
        "本页对应模块：交换 + PI",
        "".join([
          self._kv("交换后(PI 前)", self._fmt_bin(t["pre_output"])),
          self._kv("块输出(HEX)", self.des.fmt_hex(t["out_block"])),
          self._kv("块输出(BIN)", self._fmt_bin(t["out_block"])),
        ]),
        "final",
      ))

    for block in trace["dec_blocks"]:
      t = block["trace"]
      slides.append(self._slide(
        f"解密块 {block['index']} - IP 阶段",
        "本页对应模块：初始置换 IP（子密钥逆序使用）",
        "".join([
          self._kv("输入密文块(HEX)", self.des.fmt_hex(block["in_block"])),
          self._kv("IP 后 L0", self._fmt_bin(t["l0"])),
          self._kv("IP 后 R0", self._fmt_bin(t["r0"])),
        ]),
        "ip",
      ))

      for r in t["rounds"]:
        slides.append(self._slide(
          f"解密第 {r['round']} 轮 (K{r['key_label']})",
          "本页对应模块：轮函数与 Feistel 更新",
          "".join([
            self._f_diagram(),
            self._kv(f"子密钥 K{r['key_label']}", r["subkey"]),
            self._kv(f"L{r['round'] - 1}", self._fmt_bin(r["l_before"])),
            self._kv(f"R{r['round'] - 1}", self._fmt_bin(r["r_before"])),
            self._kv("f(R,K)=P 输出", self._fmt_bin(r["f_result"])),
            self._kv(f"L{r['round']}", self._fmt_bin(r["l_after"])),
            self._kv(f"R{r['round']}", self._fmt_bin(r["r_after"])),
          ]),
          "feistel",
        ))

      slides.append(self._slide(
        f"解密块 {block['index']} - 输出阶段",
        "本页对应模块：交换 + PI",
        "".join([
          self._kv("交换后(PI 前)", self._fmt_bin(t["pre_output"])),
          self._kv("块输出(HEX)", self.des.fmt_hex(t["out_block"])),
        ]),
        "final",
      ))

    slides.append(self._slide(
      "最终验证",
      "本页对应模块：输出",
      "".join([
        self._kv("原始明文", repr(trace["plaintext"])),
        self._kv("解密明文", repr(trace["recovered"])),
        self._kv("一致性", "YES" if trace["plaintext"] == trace["recovered"] else "NO"),
      ]),
      "output",
    ))

    total = len(slides)
    slides_html = "\n".join(slides)
    return f"""<!DOCTYPE html>
<html lang='zh-CN'>
<head>
  <meta charset='UTF-8' />
  <meta name='viewport' content='width=device-width, initial-scale=1.0' />
  <title>DES Web 滚动可视化</title>
  <style>
  :root {{
    --bg1:#082f49;
    --bg2:#0f766e;
    --bg3:#f97316;
    --card:rgba(255,255,255,.94);
    --text:#111827;
    --muted:#334155;
    --line:#cbd5e1;
    --mod:#e2e8f0;
    --active:#f97316;
  }}
  * {{ box-sizing: border-box; }}
  html,body {{ height:100%; margin:0; }}
  body {{
    overflow:hidden;
    font-family:"Trebuchet MS","Microsoft YaHei",sans-serif;
    color:var(--text);
    background:
    radial-gradient(circle at 18% 18%, color-mix(in srgb, var(--bg3) 65%, white 35%) 0%, transparent 28%),
    linear-gradient(130deg, var(--bg1), var(--bg2));
  }}
  .deck {{ height:100vh; overflow-y:auto; scroll-snap-type:y mandatory; scroll-behavior:smooth; }}
  .slide {{ min-height:100vh; scroll-snap-align:start; display:flex; align-items:center; justify-content:center; padding:24px; }}
  .card {{ width:min(1140px,96vw); background:var(--card); border:1px solid var(--line); border-radius:20px; padding:20px; box-shadow:0 20px 60px rgba(0,0,0,.26); }}
  h2 {{ margin:0 0 6px; font-size:clamp(24px,3.2vw,42px); }}
  .slide-subtitle {{ margin:0 0 14px; color:var(--muted); }}
  .framework {{ display:grid; grid-template-columns:repeat(5,1fr); gap:8px; margin-bottom:12px; }}
  .module {{ background:var(--mod); border:1px solid var(--line); border-radius:10px; padding:8px; font-size:12px; text-align:center; font-weight:700; }}
  .module.active {{ background:var(--active); color:#fff; border-color:#ea580c; }}
  .kv {{ margin:8px 0; background:#f8fafc; border:1px solid var(--line); border-radius:10px; padding:9px 11px; }}
  .kv span {{ display:block; font-size:12px; color:#9a3412; font-weight:700; margin-bottom:5px; }}
  .kv code {{ display:block; white-space:pre-wrap; word-break:break-all; font-family:"Cascadia Code","Consolas",monospace; font-size:12px; line-height:1.45; }}
  .f-diagram {{ display:flex; align-items:center; flex-wrap:wrap; gap:6px; margin:8px 0 10px; }}
  .f-box {{ background:#dbeafe; border:1px solid #93c5fd; border-radius:8px; padding:6px 8px; font-size:12px; font-weight:700; }}
  .f-arrow {{ color:#2563eb; font-weight:900; }}
  .hud {{ position:fixed; top:12px; right:12px; z-index:5; color:#fff; background:rgba(15,23,42,.55); border:1px solid rgba(255,255,255,.28); border-radius:999px; padding:5px 12px; font-size:12px; }}
  .hint {{ position:fixed; left:12px; bottom:12px; z-index:5; color:#e2e8f0; background:rgba(15,23,42,.55); border:1px solid rgba(255,255,255,.28); border-radius:999px; padding:5px 10px; font-size:12px; }}
  @media (max-width: 900px) {{
    .framework {{ grid-template-columns:repeat(2,1fr); }}
    .card {{ padding:14px; }}
  }}
  </style>
</head>
<body>
  <div class='hud' id='counter'>1 / {total}</div>
  <div class='hint'>滚轮/方向键/PageDown/PageUp 切页</div>
  <main class='deck' id='deck'>{slides_html}</main>
  <script>
  const deck = document.getElementById('deck');
  const slides = Array.from(document.querySelectorAll('.slide'));
  const counter = document.getElementById('counter');
  function currentIndex() {{
    let idx = 0, best = Infinity;
    slides.forEach((s, i) => {{
    const d = Math.abs(s.getBoundingClientRect().top);
    if (d < best) {{ best = d; idx = i; }}
    }});
    return idx;
  }}
  function updateCounter() {{
    counter.textContent = `${{currentIndex() + 1}} / {total}`;
  }}
  function go(delta) {{
    const i = currentIndex();
    const n = Math.max(0, Math.min(slides.length - 1, i + delta));
    slides[n].scrollIntoView({{ behavior: 'smooth', block: 'start' }});
  }}
  deck.addEventListener('scroll', updateCounter, {{ passive: true }});
  window.addEventListener('keydown', (e) => {{
    if (['ArrowDown', 'PageDown', ' ', 'Enter'].includes(e.key)) {{ e.preventDefault(); go(1); }}
    if (['ArrowUp', 'PageUp', 'Backspace'].includes(e.key)) {{ e.preventDefault(); go(-1); }}
  }});
  updateCounter();
  </script>
</body>
</html>"""

  def save_html(self, plaintext, filename="des_visualization_slides.html"):
    page = self.generate_html(plaintext)
    with open(filename, "w", encoding="utf-8") as f:
      f.write(page)
    abs_path = os.path.realpath(filename)
    webbrowser.open("file://" + abs_path)
    return abs_path


def create_web_visualization():
  key = input("请输入密钥(默认 MySecret): ").strip() or "MySecret"
  key = key[:8].ljust(8, "0")
  plaintext = input("请输入明文(可超过8字节): ").strip() or "Hello!!!"
  visualizer = DESHTMLVisualizer(key)
  out = visualizer.save_html(plaintext)
  trace = visualizer._collect_trace(plaintext)
  print("\n已生成 DES Web 滚动可视化。")
  print(f"HTML: {out}")
  print(f"密文(HEX): {trace['cipher_hex']}")
  print(f"解密验证: {'通过' if trace['recovered'] == plaintext else '失败'}")


if __name__ == "__main__":
  create_web_visualization()
