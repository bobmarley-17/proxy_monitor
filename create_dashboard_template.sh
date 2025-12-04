cat > templates/dashboard/index.html << 'HTMLEOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Proxy Monitor</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-900 text-white min-h-screen">
<div class="flex h-screen">
    <aside class="w-64 bg-slate-800 border-r border-slate-700 flex flex-col">
        <div class="p-6 border-b border-slate-700"><h1 class="font-bold text-xl">🌐 ProxyMonitor</h1><p class="text-xs text-slate-400">Traffic Analyzer</p></div>
        <nav class="flex-1 p-4 space-y-2">
            <button onclick="showTab('dashboard')" id="tab-dashboard" class="tab-btn w-full text-left px-4 py-3 rounded-lg bg-blue-600">📊 Dashboard</button>
            <button onclick="showTab('requests')" id="tab-requests" class="tab-btn w-full text-left px-4 py-3 rounded-lg text-slate-400 hover:bg-slate-700">📋 Requests</button>
            <button onclick="showTab('blocklist')" id="tab-blocklist" class="tab-btn w-full text-left px-4 py-3 rounded-lg text-slate-400 hover:bg-slate-700">🛡️ Block List</button>
            <a href="/admin/" class="block px-4 py-3 rounded-lg text-slate-400 hover:bg-slate-700">⚙️ Admin</a>
        </nav>
        <div class="p-4 border-t border-slate-700"><div id="status" class="px-4 py-2 rounded-lg bg-red-900/30 text-red-400 text-sm">● Disconnected</div></div>
    </aside>
    <main class="flex-1 overflow-auto p-6">
        <div id="content-dashboard" class="tab-content">
            <h2 class="text-2xl font-bold mb-6">Dashboard</h2>
            <div class="grid grid-cols-4 gap-4 mb-6">
                <div class="bg-slate-800 rounded-xl p-6 border border-slate-700"><p class="text-slate-400 text-sm">Total Requests</p><p id="stat-total" class="text-3xl font-bold">0</p></div>
                <div class="bg-slate-800 rounded-xl p-6 border border-slate-700"><p class="text-slate-400 text-sm">Blocked</p><p id="stat-blocked" class="text-3xl font-bold text-red-400">0</p></div>
                <div class="bg-slate-800 rounded-xl p-6 border border-slate-700"><p class="text-slate-400 text-sm">Domains</p><p id="stat-domains" class="text-3xl font-bold">0</p></div>
                <div class="bg-slate-800 rounded-xl p-6 border border-slate-700"><p class="text-slate-400 text-sm">Blocked Domains</p><p id="stat-blocked-domains" class="text-3xl font-bold">0</p></div>
            </div>
            <div class="grid grid-cols-2 gap-6">
                <div class="bg-slate-800 rounded-xl p-6 border border-slate-700"><h3 class="font-semibold mb-4">🔴 Live Requests</h3><div id="live" class="space-y-2 max-h-80 overflow-auto"></div></div>
                <div class="bg-slate-800 rounded-xl p-6 border border-slate-700"><h3 class="font-semibold mb-4">📈 Top Domains</h3><div id="top" class="space-y-2 max-h-80 overflow-auto"></div></div>
            </div>
        </div>
        <div id="content-requests" class="tab-content hidden">
            <div class="flex justify-between mb-6"><h2 class="text-2xl font-bold">Requests</h2><div class="flex gap-4"><input id="search" type="text" placeholder="Search..." class="px-4 py-2 bg-slate-800 border border-slate-700 rounded-lg"><button onclick="clearReqs()" class="px-4 py-2 bg-red-600 rounded-lg">Clear All</button></div></div>
            <div class="bg-slate-800 rounded-xl border border-slate-700 overflow-hidden"><table class="w-full"><thead class="bg-slate-700/50"><tr><th class="px-4 py-3 text-left">Time</th><th class="px-4 py-3 text-left">Method</th><th class="px-4 py-3 text-left">Domain</th><th class="px-4 py-3 text-left">Status</th></tr></thead><tbody id="table" class="divide-y divide-slate-700"></tbody></table></div>
        </div>
        <div id="content-blocklist" class="tab-content hidden">
            <h2 class="text-2xl font-bold mb-6">Block List</h2>
            <div class="bg-slate-800 rounded-xl p-6 border border-slate-700 mb-6"><form onsubmit="addBlock(event)" class="flex gap-4"><input id="newdomain" type="text" placeholder="example.com" required class="flex-1 px-4 py-2 bg-slate-700 rounded-lg"><button type="submit" class="px-6 py-2 bg-red-600 rounded-lg">Block</button></form></div>
            <div class="bg-slate-800 rounded-xl p-6 border border-slate-700 mb-6"><h3 class="font-semibold mb-4">Quick Presets</h3><div class="flex gap-3"><button onclick="preset(['facebook.com','instagram.com','twitter.com','tiktok.com'])" class="px-4 py-2 bg-blue-600/20 text-blue-400 rounded-lg">Social Media</button><button onclick="preset(['youtube.com','netflix.com','twitch.tv'])" class="px-4 py-2 bg-purple-600/20 text-purple-400 rounded-lg">Video</button><button onclick="preset(['steampowered.com','epicgames.com'])" class="px-4 py-2 bg-green-600/20 text-green-400 rounded-lg">Gaming</button></div></div>
            <div class="bg-slate-800 rounded-xl border border-slate-700"><div class="px-6 py-4 border-b border-slate-700 font-semibold">Blocked Domains</div><div id="blocklist" class="divide-y divide-slate-700 max-h-96 overflow-auto"></div></div>
        </div>
    </main>
</div>
<script>
let requests=[], stats=[], blocked=[], ws;
function connect(){
    ws = new WebSocket(`ws://${location.host}/ws/dashboard/`);
    ws.onopen = () => { document.getElementById('status').className='px-4 py-2 rounded-lg bg-green-900/30 text-green-400 text-sm'; document.getElementById('status').textContent='● Connected'; };
    ws.onclose = () => { document.getElementById('status').className='px-4 py-2 rounded-lg bg-red-900/30 text-red-400 text-sm'; document.getElementById('status').textContent='● Disconnected'; setTimeout(connect, 3000); };
    ws.onmessage = (e) => {
        const d = JSON.parse(e.data);
        if(d.type==='initial_data'){ requests=d.requests||[]; stats=d.stats||[]; render(); }
        else if(d.type==='new_request'){ requests.unshift(d.data); requests=requests.slice(0,100); render(); }
        else if(d.type==='stats_update'){ const i=stats.findIndex(s=>s.hostname===d.data.hostname); if(i>=0)stats[i]=d.data; else stats.push(d.data); stats.sort((a,b)=>b.request_count-a.request_count); renderTop(); }
    };
}
function showTab(t){ document.querySelectorAll('.tab-content').forEach(e=>e.classList.add('hidden')); document.querySelectorAll('.tab-btn').forEach(e=>{e.classList.remove('bg-blue-600');e.classList.add('text-slate-400');}); document.getElementById('content-'+t).classList.remove('hidden'); document.getElementById('tab-'+t).classList.remove('text-slate-400'); document.getElementById('tab-'+t).classList.add('bg-blue-600'); }
function render(){ renderLive(); renderTable(); renderTop(); updateStats(); }
function updateStats(){ document.getElementById('stat-total').textContent=requests.length; document.getElementById('stat-blocked').textContent=requests.filter(r=>r.blocked).length; document.getElementById('stat-domains').textContent=stats.length; }
function renderLive(){ document.getElementById('live').innerHTML = requests.slice(0,15).map(r=>`<div class="flex justify-between p-3 bg-slate-700/50 rounded-lg ${r.blocked?'border border-red-500/30':''}"><div class="flex gap-3"><span class="px-2 py-1 rounded text-xs ${r.method==='GET'?'bg-green-900/50 text-green-400':r.method==='CONNECT'?'bg-purple-900/50 text-purple-400':'bg-blue-900/50 text-blue-400'}">${r.method}</span><span class="truncate max-w-xs">${r.hostname}</span></div><span class="${r.blocked?'text-red-400':'text-green-400'}">${r.blocked?'BLOCKED':r.status_code||'-'}</span></div>`).join('') || '<p class="text-slate-400 text-center py-8">Waiting for requests...</p>'; }
function renderTable(){ const s=document.getElementById('search').value.toLowerCase(); document.getElementById('table').innerHTML = requests.filter(r=>!s||r.hostname.toLowerCase().includes(s)).slice(0,50).map(r=>`<tr class="hover:bg-slate-700/50 ${r.blocked?'bg-red-900/10':''}"><td class="px-4 py-3 text-sm text-slate-400">${new Date(r.timestamp).toLocaleTimeString()}</td><td class="px-4 py-3"><span class="px-2 py-1 rounded text-xs ${r.method==='GET'?'bg-green-900/50 text-green-400':'bg-purple-900/50 text-purple-400'}">${r.method}</span></td><td class="px-4 py-3">${r.hostname}</td><td class="px-4 py-3 ${r.blocked?'text-red-400':'text-green-400'}">${r.blocked?'BLOCKED':r.status_code||'-'}</td></tr>`).join(''); }
function renderTop(){ const max=Math.max(...stats.map(s=>s.request_count),1); document.getElementById('top').innerHTML = stats.slice(0,10).map(s=>`<div><div class="flex justify-between text-sm mb-1"><span>${s.hostname}</span><span class="text-slate-400">${s.request_count}</span></div><div class="h-2 bg-slate-700 rounded-full"><div class="h-full bg-blue-500 rounded-full" style="width:${s.request_count/max*100}%"></div></div></div>`).join('') || '<p class="text-slate-400 text-center py-8">No data yet...</p>'; }
async function loadBlocked(){ const r=await fetch('/api/blocklist/domains/'); blocked=(await r.json()).results||[]; document.getElementById('stat-blocked-domains').textContent=blocked.length; renderBlocked(); }
function renderBlocked(){ document.getElementById('blocklist').innerHTML = blocked.length?blocked.map(b=>`<div class="flex justify-between px-6 py-4 hover:bg-slate-700/50"><span>🌐 ${b.domain}</span><button onclick="removeBlock('${b.domain}')" class="text-red-400 hover:text-red-300">🗑️</button></div>`).join(''):'<p class="text-center py-8 text-slate-400">No domains blocked</p>'; }
async function addBlock(e){ e.preventDefault(); await fetch('/api/blocklist/domains/',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({domain:document.getElementById('newdomain').value.trim()})}); document.getElementById('newdomain').value=''; loadBlocked(); }
async function removeBlock(d){ if(confirm('Remove '+d+'?')){ await fetch('/api/blocklist/domains/'+encodeURIComponent(d)+'/',{method:'DELETE'}); loadBlocked(); }}
async function preset(domains){ await fetch('/api/blocklist/domains/bulk_add/',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({domains})}); loadBlocked(); }
async function clearReqs(){ if(confirm('Clear all?')){ await fetch('/api/requests/clear_all/',{method:'DELETE'}); requests=[]; stats=[]; render(); }}
document.getElementById('search').addEventListener('input', renderTable);
connect(); loadBlocked();
fetch('/api/stats/overview/').then(r=>r.json()).then(d=>{ document.getElementById('stat-total').textContent=d.total_requests; document.getElementById('stat-blocked').textContent=d.blocked_requests; document.getElementById('stat-domains').textContent=d.unique_domains; document.getElementById('stat-blocked-domains').textContent=d.blocked_domains; });
</script>
</body>
</html>
HTMLEOF

echo "✅ Dashboard template created!"
