"""HTML-шаблони (Jinja): головна, пристрій, інструменти, історія."""

BASE_STYLE = """
<style>
  :root { --bg:#0f172a; --card:#1e293b; --text:#e2e8f0; --muted:#94a3b8; --accent:#38bdf8; --ok:#4ade80; --bad:#f87171; }
  * { box-sizing: border-box; }
  body { margin:0; font-family: system-ui, Segoe UI, sans-serif; background:var(--bg); color:var(--text); }
  .wrap { max-width: 1100px; margin: 0 auto; padding: 24px 16px; }
  h1 { margin: 0 0 4px; }
  .muted { color: var(--muted); font-size: 14px; }
  a { color: var(--accent); text-decoration: none; }
  a:hover { text-decoration: underline; }
  .nav { display:flex; gap:18px; flex-wrap:wrap; padding-bottom:14px; margin-bottom:18px; border-bottom:1px solid #334155; }
  .bar { display:flex; justify-content:space-between; align-items:center; gap:12px; flex-wrap:wrap; margin:16px 0; }
  button { background:var(--accent); color:#0f172a; border:0; padding:9px 16px; border-radius:8px;
           font-weight:600; cursor:pointer; margin:4px 6px 4px 0; }
  button:disabled { opacity:.5; cursor:default; }
  button.sec { background:#334155; color:var(--text); }
  input { width:100%; background:#0f172a; color:var(--text); border:1px solid #475569; border-radius:6px;
          padding:8px 10px; margin:4px 0 10px; font-size:14px; }
  label { display:block; font-size:13px; color:var(--muted); }
  table { width:100%; border-collapse:collapse; background:var(--card); border-radius:10px; overflow:hidden; }
  th, td { text-align:left; padding:12px 14px; border-bottom:1px solid #334155; }
  th { color:var(--muted); font-size:13px; text-transform:uppercase; letter-spacing:.04em; }
  tr:last-child td { border-bottom:0; }
  tr.off td { opacity:.55; }
  .tag { display:inline-block; background:#334155; padding:2px 8px; border-radius:6px; font-size:12px; margin:2px 4px 2px 0; }
  .tag.new { background:#facc15; color:#422006; font-weight:700; }
  .tag.on { background:#14532d; color:var(--ok); }
  .tag.offl { background:#450a0a; color:var(--bad); }
  .card { background:var(--card); border-radius:10px; padding:20px; margin-bottom:16px; }
  .row { display:flex; padding:8px 0; border-bottom:1px solid #334155; }
  .row:last-child { border-bottom:0; }
  .row .k { width:200px; color:var(--muted); flex-shrink:0; }
  .grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(320px,1fr)); gap:16px; }
  .grid .card { margin:0; }
  pre.out { background:#020617; border-radius:8px; padding:12px; margin:10px 0 0; font-size:12.5px;
            white-space:pre-wrap; word-break:break-word; max-height:340px; overflow:auto; color:#cbd5e1; }
  pre.out:empty { display:none; }
  .pulse { color:var(--ok); }
</style>
"""

NAV = """
<div class="nav">
  <a href="/">Пристрої</a>
  <a href="/tools">Інструменти</a>
  <a href="/history">Історія</a>
  <a href="/export.csv">Експорт CSV</a>
  <a href="/export.json">Експорт JSON</a>
</div>
"""

SCRIPT = """
<script>
function fmt(d) {
  if (d.error) return "Помилка: " + d.error;
  const rest = Object.assign({}, d);
  const text = rest.output;
  delete rest.output;
  let s = Object.keys(rest).length ? JSON.stringify(rest, null, 2) : "";
  if (typeof text === "string") s += (s ? "\\n\\n" : "") + text;
  return s || "(порожньо)";
}
async function runTool(name, params, out, btn) {
  if (typeof out === "string") out = document.getElementById(out);
  out.textContent = "Виконується...";
  if (btn) btn.disabled = true;
  try {
    const r = await fetch("/api/" + name, {method: "POST", body: new URLSearchParams(params)});
    out.textContent = fmt(await r.json());
  } catch (e) {
    out.textContent = "Помилка: " + e;
  } finally {
    if (btn) btn.disabled = false;
  }
}
function runCard(btn) {
  const card = btn.closest(".tool");
  const params = {};
  card.querySelectorAll("input").forEach(function (i) { params[i.name] = i.value; });
  runTool(card.dataset.tool, params, card.querySelector("pre"), btn);
}
</script>
"""

HEAD = """<!doctype html>
<html lang="uk">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
"""

INDEX_HTML = HEAD + """
{% if scanning %}<meta http-equiv="refresh" content="3">{% endif %}
<title>Network Scanner</title>
""" + BASE_STYLE + """
</head>
<body>
<div class="wrap">
  """ + NAV + """
  <h1>Network Scanner</h1>
  <div class="muted">
    Мережа: {{ network or "—" }} · Твій IP: {{ local_ip or "—" }}
    {% if last_scan %}· Останнє сканування: {{ last_scan }}{% endif %}
  </div>

  <div class="bar">
    <div>
      {% if scanning %}<span class="pulse">● Сканування: {{ stage }}</span>
      {% else %}Знайдено пристроїв: <b>{{ devices|length }}</b>{% endif %}
    </div>
    <form method="post" action="/rescan">
      <button type="submit" {% if scanning %}disabled{% endif %}>Сканувати знову</button>
    </form>
  </div>

  <table>
    <tr><th>IP</th><th>Назва</th><th>Тип</th><th>Виробник</th><th>Порти</th></tr>
    {% for d in devices %}
    <tr>
      <td>
        <a href="/device/{{ d.ip }}">{{ d.ip }}</a>
        {% if d.is_self %}<span class="tag">це ти</span>{% endif %}
        {% if d.new %}<span class="tag new">НОВИЙ</span>{% endif %}
      </td>
      <td>{{ d.label or d.hostname or "—" }}</td>
      <td>{{ d.type }}</td>
      <td>{{ d.vendor or "—" }}</td>
      <td>{% for p in d.ports %}<span class="tag">{{ p.port }}</span>{% else %}—{% endfor %}</td>
    </tr>
    {% else %}
    <tr><td colspan="5" class="muted">Поки нічого не знайдено.</td></tr>
    {% endfor %}
  </table>
</div>
</body>
</html>
"""

DEVICE_HTML = HEAD + """
<title>{{ d.ip }} — Network Scanner</title>
""" + BASE_STYLE + """
</head>
<body>
<div class="wrap">
  """ + NAV + """
  <h1>{{ d.label or d.hostname or d.ip }}
    {% if d.new %}<span class="tag new">НОВИЙ</span>{% endif %}</h1>
  <div class="muted">{{ d.type }}</div>

  <div class="card" style="margin-top:16px">
    <div class="row"><div class="k">IP-адреса</div><div>{{ d.ip }}</div></div>
    <div class="row"><div class="k">MAC-адреса</div><div>{{ d.mac }}</div></div>
    <div class="row"><div class="k">Ім'я (hostname)</div><div>{{ d.hostname or "невідомо" }}</div></div>
    <div class="row"><div class="k">Виробник</div><div>{{ d.vendor or "невідомо" }}</div></div>
    <div class="row"><div class="k">Тип (припущення)</div><div>{{ d.type }}</div></div>
    <div class="row"><div class="k">Вперше побачили</div><div>{{ d.first_seen }}</div></div>
    <div class="row"><div class="k">Востаннє бачили</div><div>{{ d.seen }}</div></div>
    <form method="post" action="/device/{{ d.ip }}/label" style="margin-top:14px">
      <label>Своя назва пристрою (наприклад «Телефон Олега»)
        <input name="label" value="{{ d.label }}" maxlength="60">
      </label>
      <button type="submit">Зберегти назву</button>
    </form>
  </div>

  <div class="card">
    <h3 style="margin-top:0">Інструменти для цього пристрою</h3>
    <button onclick="runTool('ping', {host: '{{ d.ip }}', count: 4}, 'out', this)">Ping</button>
    <button onclick="runTool('traceroute', {host: '{{ d.ip }}'}, 'out', this)">Traceroute</button>
    <button onclick="runTool('portscan', {host: '{{ d.ip }}', ports: '1-1024'}, 'out', this)">Порти 1–1024</button>
    <button onclick="runTool('banners', {host: '{{ d.ip }}'}, 'out', this)">Банери</button>
    <button onclick="runTool('httpinfo', {host: '{{ d.ip }}'}, 'out', this)">HTTP-інфо</button>
    <button onclick="runTool('netbios', {host: '{{ d.ip }}'}, 'out', this)">NetBIOS</button>
    <button onclick="runTool('dns', {name: '{{ d.ip }}'}, 'out', this)">DNS</button>
    {% if d.mac != "—" %}
    <button class="sec" onclick="runTool('wol', {mac: '{{ d.mac }}'}, 'out', this)">Розбудити (Wake-on-LAN)</button>
    {% endif %}
    <pre class="out" id="out"></pre>
  </div>

  <div class="card">
    <h3 style="margin-top:0">Відкриті порти (зі швидкого сканування)</h3>
    {% for p in d.ports %}
    <div class="row">
      <div class="k">{{ p.port }}</div>
      <div>
        {{ p.service }}
        {% if p.port in (80, 8080) %}— <a href="http://{{ d.ip }}:{{ p.port }}" target="_blank" rel="noopener">відкрити веб-інтерфейс</a>{% endif %}
        {% if p.port == 443 %}— <a href="https://{{ d.ip }}" target="_blank" rel="noopener">відкрити веб-інтерфейс</a>{% endif %}
      </div>
    </div>
    {% else %}
    <div class="muted">Відкритих портів зі списку не знайдено.</div>
    {% endfor %}
    <p class="muted">Відкритий порт не означає, що до пристрою можна отримати доступ.</p>
  </div>
</div>
""" + SCRIPT + """
</body>
</html>
"""

TOOLS_HTML = HEAD + """
<title>Інструменти — Network Scanner</title>
""" + BASE_STYLE + """
</head>
<body>
<div class="wrap">
  """ + NAV + """
  <h1>Інструменти</h1>
  <div class="muted">Сканування портів, банерів і Wake-on-LAN працюють лише з адресами локальної мережі.</div>
  <div class="grid" style="margin-top:16px">
    {% for t in tools %}
    <div class="card tool" data-tool="{{ t.id }}">
      <h3 style="margin-top:0">{{ t.title }}</h3>
      <div class="muted" style="margin-bottom:10px">{{ t.desc }}</div>
      {% for f in t.fields %}
      <label>{{ f.label }}<input name="{{ f.name }}" value="{{ f.default }}"></label>
      {% endfor %}
      <button onclick="runCard(this)">Запустити</button>
      <pre class="out"></pre>
    </div>
    {% endfor %}
  </div>
</div>
""" + SCRIPT + """
</body>
</html>
"""

HISTORY_HTML = HEAD + """
<title>Історія — Network Scanner</title>
""" + BASE_STYLE + """
</head>
<body>
<div class="wrap">
  """ + NAV + """
  <h1>Історія пристроїв</h1>
  <div class="muted">Усі пристрої, які сканер бачив раніше (зберігається у history.json).</div>
  <table style="margin-top:16px">
    <tr><th>Статус</th><th>Назва</th><th>IP (останній)</th><th>MAC</th><th>Виробник</th><th>Вперше</th><th>Востаннє</th></tr>
    {% for r in rows %}
    <tr class="{{ '' if r.online else 'off' }}">
      <td>{% if r.online %}<span class="tag on">онлайн</span>{% else %}<span class="tag offl">офлайн</span>{% endif %}</td>
      <td>{{ r.label or r.hostname or "—" }}</td>
      <td>{{ r.ip }}</td>
      <td>{{ r.key }}</td>
      <td>{{ r.vendor or "—" }}</td>
      <td>{{ r.first_seen }}</td>
      <td>{{ r.last_seen }}</td>
    </tr>
    {% else %}
    <tr><td colspan="7" class="muted">Історія порожня — дочекайся першого сканування.</td></tr>
    {% endfor %}
  </table>
</div>
</body>
</html>
"""
