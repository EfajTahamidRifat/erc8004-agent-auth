"""Regenerates the animated README banner and flow diagram (light and dark): python docs/assets/make_assets.py"""
import pathlib
OUT = pathlib.Path(__file__).resolve().parent
FONT = "font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Inter,Helvetica,Arial,sans-serif"
MONO = "font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace"
T = {
 "dark":  dict(bg="#0A0C12", bg2="#111521", fg="#F2F4F8", mut="#8A93A6", line="#262C3B", card="#121722", a1="#7C5CFF", a2="#22D3EE", ok="#34D399"),
 "light": dict(bg="#FFFFFF", bg2="#F4F6FB", fg="#0D1220", mut="#5B6476", line="#E2E6EF", card="#FFFFFF", a1="#6D4AFF", a2="#0891B2", ok="#059669"),
}
def hero(t):
    c = T[t]
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="380" viewBox="0 0 1200 380">
<defs>
 <linearGradient id="g" x1="0" x2="1"><stop offset="0" stop-color="{c['a1']}"/><stop offset="1" stop-color="{c['a2']}"/></linearGradient>
 <radialGradient id="o1"><stop offset="0" stop-color="{c['a1']}" stop-opacity=".55"/><stop offset="1" stop-color="{c['a1']}" stop-opacity="0"/></radialGradient>
 <radialGradient id="o2"><stop offset="0" stop-color="{c['a2']}" stop-opacity=".45"/><stop offset="1" stop-color="{c['a2']}" stop-opacity="0"/></radialGradient>
 <pattern id="grid" width="32" height="32" patternUnits="userSpaceOnUse"><path d="M32 0H0V32" fill="none" stroke="{c['line']}" stroke-width="1"/></pattern>
 <clipPath id="r"><rect width="1200" height="380" rx="20"/></clipPath>
 <linearGradient id="fade" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="{c['bg']}" stop-opacity="0"/><stop offset="1" stop-color="{c['bg']}"/></linearGradient>
</defs>
<style>
 .o1{{animation:d1 14s ease-in-out infinite alternate}} .o2{{animation:d2 18s ease-in-out infinite alternate}}
 @keyframes d1{{from{{transform:translate(0,0)}}to{{transform:translate(260px,60px)}}}}
 @keyframes d2{{from{{transform:translate(0,0)}}to{{transform:translate(-300px,-40px)}}}}
 .up{{opacity:0;animation:up .9s cubic-bezier(.2,.7,.2,1) forwards}}
 .u2{{animation-delay:.25s}} .u3{{animation-delay:.5s}} .u4{{animation-delay:.8s}}
 @keyframes up{{from{{opacity:0;transform:translateY(14px)}}to{{opacity:1;transform:none}}}}
 .cur{{animation:blink 1.1s steps(1) infinite}} @keyframes blink{{50%{{opacity:0}}}}
 .pulse{{animation:pulse 2.4s ease-out infinite;transform-origin:925px 92px}}
 @keyframes pulse{{0%{{opacity:.7;transform:scale(1)}}100%{{opacity:0;transform:scale(2.6)}}}}
 .scan{{animation:scan 4.5s ease-in-out infinite}} @keyframes scan{{0%{{transform:translateX(-260px)}}100%{{transform:translateX(1400px)}}}}
</style>
<g clip-path="url(#r)">
 <rect width="1200" height="380" fill="{c['bg']}"/>
 <rect width="1200" height="380" fill="url(#grid)" opacity=".6"/>
 <circle class="o1" cx="260" cy="120" r="300" fill="url(#o1)"/>
 <circle class="o2" cx="980" cy="300" r="320" fill="url(#o2)"/>
 <rect y="180" width="1200" height="200" fill="url(#fade)"/>
 <rect class="scan" x="0" y="0" width="160" height="380" fill="url(#g)" opacity=".06"/>
 <g class="up" style="{MONO}"><rect x="72" y="70" width="300" height="34" rx="17" fill="{c['card']}" stroke="{c['line']}"/>
  <circle cx="94" cy="87" r="5" fill="{c['ok']}"/><text x="108" y="92" font-size="14" fill="{c['mut']}">erc8004-agent-auth/1 · draft</text></g>
 <text class="up u2" x="70" y="178" font-size="64" font-weight="800" letter-spacing="-2" fill="{c['fg']}" style="{FONT}">Know which agent</text>
 <text class="up u2" x="70" y="250" font-size="64" font-weight="800" letter-spacing="-2" fill="url(#g)" style="{FONT}">is calling your API.</text>
 <text class="up u3" x="72" y="300" font-size="21" fill="{c['mut']}" style="{FONT}">Signed requests from ERC-8004 agents, verified against the on-chain Identity Registry.</text>
 <text class="up u3" x="72" y="330" font-size="21" fill="{c['mut']}" style="{FONT}">No API keys. No middleman. MIT licensed.</text>
 <g class="up u4">
  <circle class="pulse" cx="925" cy="92" r="16" fill="none" stroke="{c['ok']}" stroke-width="2"/>
  <rect x="900" y="70" width="228" height="44" rx="22" fill="{c['card']}" stroke="{c['line']}"/>
  <circle cx="1046" cy="92" r="0"/>
  <circle cx="925" cy="92" r="11" fill="{c['ok']}"/><path d="M919 92l4 4 8-8" fill="none" stroke="{c['bg']}" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
  <text x="944" y="98" font-size="16" font-weight="600" fill="{c['fg']}" style="{FONT}">eip155:8453:1203</text>
 </g>
 <rect x=".5" y=".5" width="1199" height="379" rx="20" fill="none" stroke="{c['line']}"/>
</g></svg>'''

def flow(t):
    c = T[t]
    def node(x, title, sub, icon):
        return f'''<g><rect x="{x}" y="70" width="280" height="96" rx="18" fill="{c['card']}" stroke="{c['line']}"/>
 <rect x="{x+22}" y="92" width="44" height="44" rx="12" fill="url(#g)" opacity=".14"/>
 <text x="{x+44}" y="122" text-anchor="middle" font-size="20" fill="{c['a1']}" style="{MONO}">{icon}</text>
 <text x="{x+82}" y="112" font-size="20" font-weight="700" fill="{c['fg']}" style="{FONT}">{title}</text>
 <text x="{x+82}" y="136" font-size="14" fill="{c['mut']}" style="{FONT}">{sub}</text></g>'''
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="290" viewBox="0 0 1200 290">
<defs><linearGradient id="g" x1="0" x2="1"><stop offset="0" stop-color="{c['a1']}"/><stop offset="1" stop-color="{c['a2']}"/></linearGradient>
<filter id="glow" x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="4"/></filter></defs>
<style>
 .dash{{stroke-dasharray:6 8;animation:dash 1.2s linear infinite}} @keyframes dash{{to{{stroke-dashoffset:-14}}}}
 .p1{{animation:p1 3.6s cubic-bezier(.6,0,.4,1) infinite}} @keyframes p1{{0%{{transform:translateX(0);opacity:0}}8%{{opacity:1}}38%{{transform:translateX(180px);opacity:1}}42%,100%{{transform:translateX(180px);opacity:0}}}}
 .p2{{animation:p2 3.6s cubic-bezier(.6,0,.4,1) infinite}} @keyframes p2{{0%,40%{{transform:translateX(0);opacity:0}}46%{{opacity:1}}72%{{transform:translateX(180px);opacity:1}}76%,100%{{transform:translateX(180px);opacity:0}}}}
 .ok{{opacity:0;animation:ok 3.6s ease infinite}} @keyframes ok{{0%,76%{{opacity:0;transform:translateY(6px)}}82%,96%{{opacity:1;transform:none}}100%{{opacity:0}}}}
</style>
<rect width="1200" height="290" rx="20" fill="{c['bg2']}"/>
{node(60,"AI agent","signs with its wallet","✎")}
{node(460,"Your API","checks the signature","{ }")}
{node(860,"Identity Registry","ERC-8004 · on chain","⛓")}
<path class="dash" d="M350 118H450" stroke="{c['mut']}" stroke-width="2" fill="none"/>
<path class="dash" d="M750 118H850" stroke="{c['mut']}" stroke-width="2" fill="none"/>
<g class="p1"><circle cx="350" cy="118" r="9" fill="{c['a1']}" filter="url(#glow)"/><circle cx="350" cy="118" r="5" fill="{c['a1']}"/></g>
<g class="p2"><circle cx="750" cy="118" r="9" fill="{c['a2']}" filter="url(#glow)"/><circle cx="750" cy="118" r="5" fill="{c['a2']}"/></g>
<text x="400" y="104" text-anchor="middle" font-size="13" fill="{c['mut']}" style="{MONO}">signed request</text>
<text x="800" y="104" text-anchor="middle" font-size="13" fill="{c['mut']}" style="{MONO}">eth_call</text>
<g style="{MONO}" font-size="14" fill="{c['mut']}">
 <text x="82" y="206">method · url · body · nonce</text>
 <text x="482" y="206">ownerOf · getAgentWallet</text>
 <text x="882" y="206">ERC-1271 for smart wallets</text>
</g>
<g class="ok"><rect x="460" y="232" width="280" height="34" rx="17" fill="{c['ok']}" opacity=".14"/>
 <text x="600" y="254" text-anchor="middle" font-size="15" font-weight="700" fill="{c['ok']}" style="{FONT}">✓ verified · role: agent_wallet</text></g>
</svg>'''
for t in T:
    (OUT / f"hero-{t}.svg").write_text(hero(t))
    (OUT / f"flow-{t}.svg").write_text(flow(t))
print("ok")
