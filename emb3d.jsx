import React, { useState, useMemo } from “react”;
import { ChevronRight, ChevronDown, Download, Search, AlertTriangle, X, ExternalLink, Cpu, Terminal, Layers, Wifi, Shield, Crosshair } from “lucide-react”;

// =====================================================================
// MITRE ESTM Tactics (Embedded Systems Threat Matrix)
// Includes ATT&CK-aligned tactics + 2 embedded-specific:
//   “Impair Process Control” and “Inhibit Response Function”
// =====================================================================
const ESTM_TACTICS = {
“Reconnaissance”:     { id: “TA-REC”,  desc: “Gather information to plan attack against embedded device”, color: “#7a8db5” },
“Resource Development”:{ id: “TA-RD”,  desc: “Establish resources (tools, infrastructure) to support attack”, color: “#7a8db5” },
“Initial Access”:     { id: “TA-IA”,   desc: “Gain initial foothold on embedded system via hardware, network, or supply chain”, color: “#d97757” },
“Execution”:          { id: “TA-EX”,   desc: “Run adversary-controlled code on the embedded device”, color: “#d97757” },
“Persistence”:        { id: “TA-PER”,  desc: “Maintain foothold across reboots and firmware cycles”, color: “#c6a664” },
“Privilege Escalation”:{ id: “TA-PE”,  desc: “Gain higher-level permissions on the embedded system”, color: “#c6a664” },
“Defense Evasion”:    { id: “TA-DE”,   desc: “Avoid detection by security mechanisms on device”, color: “#c6a664” },
“Credential Access”:  { id: “TA-CA”,   desc: “Steal credentials, keys, or authentication tokens”, color: “#b87a6b” },
“Discovery”:          { id: “TA-DIS”,  desc: “Discover device internals, firmware layout, memory maps”, color: “#6b9a8b” },
“Lateral Movement”:   { id: “TA-LM”,   desc: “Move to other systems/buses/components from compromised device”, color: “#6b9a8b” },
“Collection”:         { id: “TA-COL”,  desc: “Gather data of interest from the embedded device”, color: “#6b9a8b” },
“Command and Control”:{ id: “TA-C2”,   desc: “Communicate with compromised device to control it remotely”, color: “#8b7ab5” },
“Exfiltration”:       { id: “TA-EXF”,  desc: “Steal data from the embedded device”, color: “#8b7ab5” },
“Impact”:             { id: “TA-IMP”,  desc: “Manipulate, disrupt, or destroy embedded system functionality”, color: “#b84d3c” },
“Impair Process Control”: { id: “TA-IPC”, desc: “Manipulate, disable, or damage physical control processes (embedded-specific)”, color: “#b84d3c” },
“Inhibit Response Function”: { id: “TA-IRF”, desc: “Prevent safety, protection, or operator intervention functions (embedded-specific)”, color: “#b84d3c” },
};

// =====================================================================
// EMB3D Threats with names and ESTM tactic mappings
// Mapping based on MITRE’s guidance that EMB3D threats map to ESTM
// tactics representing HOW an attacker achieves each threat objective
// =====================================================================
const THREATS = {
“TID-101”: { name: “Power Consumption Analysis Side Channel”, tactics: [“Reconnaissance”,“Discovery”,“Collection”,“Credential Access”] },
“TID-102”: { name: “Electromagnetic Analysis Side Channel”, tactics: [“Reconnaissance”,“Discovery”,“Collection”,“Credential Access”] },
“TID-103”: { name: “Microarchitectural Side Channels”, tactics: [“Discovery”,“Collection”,“Credential Access”] },
“TID-105”: { name: “Hardware Fault Injection – Control Flow Modification”, tactics: [“Execution”,“Privilege Escalation”,“Defense Evasion”,“Impair Process Control”] },
“TID-106”: { name: “Data Bus Interception”, tactics: [“Collection”,“Discovery”,“Credential Access”,“Reconnaissance”] },
“TID-107”: { name: “Unauthorized Direct Memory Access (DMA)”, tactics: [“Initial Access”,“Execution”,“Privilege Escalation”,“Collection”,“Defense Evasion”] },
“TID-108”: { name: “ROM/NVRAM Data Extraction or Modification”, tactics: [“Collection”,“Credential Access”,“Persistence”,“Defense Evasion”] },
“TID-109”: { name: “RAM Chip Contents Readout”, tactics: [“Collection”,“Credential Access”,“Discovery”] },
“TID-110”: { name: “Hardware Fault Injection – Data Manipulation”, tactics: [“Impact”,“Impair Process Control”,“Defense Evasion”] },
“TID-111”: { name: “Untrusted External Storage”, tactics: [“Initial Access”,“Execution”,“Persistence”,“Lateral Movement”] },
“TID-113”: { name: “Unverified Peripheral Firmware Loaded”, tactics: [“Initial Access”,“Persistence”,“Execution”,“Defense Evasion”] },
“TID-114”: { name: “Peripheral Data Bus Interception”, tactics: [“Collection”,“Discovery”,“Lateral Movement”] },
“TID-115”: { name: “Firmware/Data Extraction via Hardware Interface”, tactics: [“Initial Access”,“Collection”,“Discovery”,“Credential Access”,“Exfiltration”] },
“TID-116”: { name: “Latent Privileged Access Port”, tactics: [“Initial Access”,“Privilege Escalation”,“Persistence”] },
“TID-118”: { name: “Weak Peripheral Port Electrical Damage Protection”, tactics: [“Impact”,“Initial Access”] },
“TID-119”: { name: “Latent Hardware Debug Port Allows Memory/Code Manipulation”, tactics: [“Initial Access”,“Execution”,“Privilege Escalation”,“Persistence”,“Collection”] },
“TID-201”: { name: “Inadequate Bootloader Protection and Verification”, tactics: [“Persistence”,“Execution”,“Defense Evasion”,“Privilege Escalation”] },
“TID-202”: { name: “Exploitable System Network Stack Component”, tactics: [“Initial Access”,“Execution”,“Privilege Escalation”] },
“TID-203”: { name: “Malicious OS Kernel Driver/Module Installable”, tactics: [“Persistence”,“Privilege Escalation”,“Execution”,“Defense Evasion”] },
“TID-204”: { name: “Untrusted Programs Can Access Privileged OS Functions”, tactics: [“Privilege Escalation”,“Execution”,“Defense Evasion”] },
“TID-205”: { name: “Existing OS Tools Maliciously Used for Device Manipulation”, tactics: [“Execution”,“Discovery”,“Defense Evasion”,“Lateral Movement”,“Impact”] },
“TID-206”: { name: “Memory Management Protections Subverted”, tactics: [“Privilege Escalation”,“Execution”,“Defense Evasion”] },
“TID-207”: { name: “Container Escape”, tactics: [“Privilege Escalation”,“Defense Evasion”,“Lateral Movement”] },
“TID-208”: { name: “Virtual Machine Escape”, tactics: [“Privilege Escalation”,“Defense Evasion”,“Lateral Movement”] },
“TID-209”: { name: “Host Can Manipulate Guest Virtual Machines”, tactics: [“Privilege Escalation”,“Collection”,“Impact”] },
“TID-210”: { name: “Device Vulnerabilities Unpatchable”, tactics: [“Persistence”,“Impact”,“Inhibit Response Function”] },
“TID-211”: { name: “Device Allows Unauthenticated Firmware Installation”, tactics: [“Persistence”,“Execution”,“Initial Access”,“Defense Evasion”] },
“TID-212”: { name: “FW/SW Update Integrity Shared Secrets Extraction”, tactics: [“Credential Access”,“Defense Evasion”,“Persistence”] },
“TID-213”: { name: “Faulty FW/SW Update Integrity Verification”, tactics: [“Defense Evasion”,“Persistence”,“Execution”] },
“TID-214”: { name: “Secrets Extracted from Device Root of Trust”, tactics: [“Credential Access”,“Collection”,“Defense Evasion”] },
“TID-215”: { name: “Unencrypted SW/FW Updates”, tactics: [“Collection”,“Discovery”,“Exfiltration”,“Defense Evasion”] },
“TID-216”: { name: “Firmware Update Rollbacks Allowed”, tactics: [“Persistence”,“Defense Evasion”,“Inhibit Response Function”] },
“TID-217”: { name: “Remotely Initiated Updates Can Cause DoS”, tactics: [“Impact”,“Inhibit Response Function”,“Impair Process Control”] },
“TID-218”: { name: “Operating System Susceptible to Rootkit”, tactics: [“Persistence”,“Defense Evasion”,“Privilege Escalation”] },
“TID-219”: { name: “OS/Kernel Privilege Escalation”, tactics: [“Privilege Escalation”,“Execution”] },
“TID-220”: { name: “Unpatchable Hardware Root of Trust”, tactics: [“Persistence”,“Impact”,“Inhibit Response Function”] },
“TID-221”: { name: “Authentication Bypass By Message Replay”, tactics: [“Initial Access”,“Credential Access”,“Defense Evasion”,“Lateral Movement”] },
“TID-222”: { name: “Critical System Service May Be Disabled”, tactics: [“Impact”,“Inhibit Response Function”,“Impair Process Control”] },
“TID-223”: { name: “System Susceptible to RAM Scraping”, tactics: [“Collection”,“Credential Access”,“Discovery”] },
“TID-224”: { name: “Excessive Access via Software Diagnostic Features”, tactics: [“Initial Access”,“Discovery”,“Privilege Escalation”,“Collection”] },
“TID-225”: { name: “Logs can be manipulated on the device”, tactics: [“Defense Evasion”,“Impact”,“Inhibit Response Function”] },
“TID-226”: { name: “Device leaks security information in logs”, tactics: [“Discovery”,“Collection”,“Credential Access”,“Reconnaissance”] },
“TID-301”: { name: “Applications Binaries Modified”, tactics: [“Persistence”,“Execution”,“Defense Evasion”,“Impact”] },
“TID-302”: { name: “Install Untrusted Application”, tactics: [“Execution”,“Persistence”,“Initial Access”] },
“TID-303”: { name: “Excessive Trust in Offboard Management/IDE Software”, tactics: [“Initial Access”,“Execution”,“Lateral Movement”,“Command and Control”] },
“TID-304”: { name: “Manipulate Runtime Environment”, tactics: [“Execution”,“Persistence”,“Defense Evasion”,“Privilege Escalation”] },
“TID-305”: { name: “Program Executes Dangerous System Calls”, tactics: [“Execution”,“Privilege Escalation”,“Impact”,“Impair Process Control”] },
“TID-306”: { name: “Sandboxed Environments Escaped”, tactics: [“Privilege Escalation”,“Defense Evasion”,“Lateral Movement”] },
“TID-307”: { name: “Device Code Representations Inconsistent”, tactics: [“Defense Evasion”,“Persistence”,“Impact”] },
“TID-308”: { name: “Code Overwritten to Avoid Detection”, tactics: [“Defense Evasion”,“Persistence”,“Execution”] },
“TID-309”: { name: “Device Exploits Engineering Workstation”, tactics: [“Lateral Movement”,“Initial Access”,“Execution”,“Collection”] },
“TID-310”: { name: “Remotely Accessible Unauthenticated Services”, tactics: [“Initial Access”,“Discovery”,“Execution”] },
“TID-311”: { name: “Default Credentials”, tactics: [“Initial Access”,“Credential Access”,“Privilege Escalation”] },
“TID-312”: { name: “Credential Change Mechanism Can Be Abused”, tactics: [“Credential Access”,“Persistence”,“Privilege Escalation”] },
“TID-313”: { name: “Unauthenticated Session Changes Credential”, tactics: [“Credential Access”,“Initial Access”,“Privilege Escalation”] },
“TID-314”: { name: “Passwords Can Be Guessed Using Brute-Force Attempts”, tactics: [“Credential Access”,“Initial Access”] },
“TID-315”: { name: “Password Retrieval Mechanism Abused”, tactics: [“Credential Access”,“Initial Access”] },
“TID-316”: { name: “Incorrect Certificate Verification Allows Authentication Bypass”, tactics: [“Initial Access”,“Defense Evasion”,“Credential Access”,“Lateral Movement”] },
“TID-317”: { name: “Predictable Cryptographic Key”, tactics: [“Credential Access”,“Initial Access”,“Defense Evasion”] },
“TID-318”: { name: “Insecure Cryptographic Implementation”, tactics: [“Credential Access”,“Defense Evasion”,“Collection”] },
“TID-319”: { name: “Cross Site Scripting (XSS)”, tactics: [“Initial Access”,“Execution”,“Credential Access”,“Collection”] },
“TID-320”: { name: “SQL Injection”, tactics: [“Initial Access”,“Execution”,“Collection”,“Privilege Escalation”] },
“TID-321”: { name: “HTTP Application Session Hijacking”, tactics: [“Credential Access”,“Initial Access”,“Lateral Movement”] },
“TID-322”: { name: “Cross Site Request Forgery (CSRF)”, tactics: [“Execution”,“Initial Access”] },
“TID-323”: { name: “Path Traversal”, tactics: [“Discovery”,“Collection”,“Exfiltration”] },
“TID-324”: { name: “HTTP Direct Object Reference”, tactics: [“Discovery”,“Collection”,“Privilege Escalation”] },
“TID-325”: { name: “HTTP Injection/Response Splitting”, tactics: [“Execution”,“Defense Evasion”,“Initial Access”] },
“TID-326”: { name: “Insecure Deserialization”, tactics: [“Execution”,“Privilege Escalation”,“Initial Access”] },
“TID-327”: { name: “Out of Bounds Memory Access”, tactics: [“Execution”,“Privilege Escalation”,“Impact”] },
“TID-328”: { name: “Hardcoded Credentials”, tactics: [“Credential Access”,“Initial Access”,“Persistence”] },
“TID-329”: { name: “Improper Password Storage”, tactics: [“Credential Access”,“Discovery”] },
“TID-330”: { name: “Cryptographic Timing Side-Channel”, tactics: [“Credential Access”,“Discovery”,“Collection”] },
“TID-401”: { name: “Undocumented Protocol Features”, tactics: [“Initial Access”,“Discovery”,“Defense Evasion”,“Execution”] },
“TID-404”: { name: “Remotely Triggerable Deadlock/DoS”, tactics: [“Impact”,“Inhibit Response Function”,“Impair Process Control”] },
“TID-405”: { name: “Network Stack Resource Exhaustion”, tactics: [“Impact”,“Inhibit Response Function”] },
“TID-406”: { name: “Unauthorized Messages or Connections”, tactics: [“Initial Access”,“Lateral Movement”,“Command and Control”,“Impair Process Control”] },
“TID-407”: { name: “Missing Message Replay Protection”, tactics: [“Initial Access”,“Credential Access”,“Lateral Movement”,“Impair Process Control”] },
“TID-408”: { name: “Unencrypted Sensitive Data Communication”, tactics: [“Collection”,“Credential Access”,“Exfiltration”,“Discovery”] },
“TID-410”: { name: “Cryptographic Protocol Side Channel”, tactics: [“Credential Access”,“Discovery”,“Collection”] },
“TID-411”: { name: “Weak/Insecure Cryptographic Protocol”, tactics: [“Credential Access”,“Defense Evasion”,“Initial Access”,“Collection”] },
“TID-412”: { name: “Network Routing Capability Abuse”, tactics: [“Lateral Movement”,“Command and Control”,“Collection”,“Defense Evasion”] },
};

// =====================================================================
// EMB3D Property Tree (same as before, unchanged)
// =====================================================================
const PROPERTY_TREE = [
{ category: “Hardware”, icon: Cpu, properties: [
{ id: “PID-11”, label: “Device includes a microprocessor”, threats: [“TID-101”,“TID-102”,“TID-103”,“TID-105”] },
{ id: “PID-12”, label: “Device includes Memory/Storage (external to CPU)”, threats: [], children: [
{ id: “PID-121”, label: “Device includes buses for external memory/storage”, threats: [“TID-106”] },
{ id: “PID-122”, label: “Device includes discrete chips/devices with shared physical memory”, threats: [“TID-107”] },
{ id: “PID-123”, label: “Device includes ROM, VRAM, or removable Storage”, threats: [“TID-108”] },
{ id: “PID-124”, label: “Device includes Random Access Memory (RAM) chips”, threats: [“TID-109”], children: [
{ id: “PID-1241”, label: “Device includes DDR DRAM”, threats: [“TID-110”] },
]},
]},
{ id: “PID-13”, label: “Device includes peripheral chips and integrated data buses”, threats: [“TID-113”,“TID-114”] },
{ id: “PID-14”, label: “Device includes external peripheral interconnects (e.g., USB, Serial)”, threats: [“TID-111”,“TID-118”] },
{ id: “PID-15”, label: “Device includes a hardware access port (e.g., UART, JTAG)”, threats: [“TID-115”,“TID-116”,“TID-119”] },
]},
{ category: “System Software”, icon: Terminal, properties: [
{ id: “PID-21”, label: “Device includes a bootloader”, threats: [“TID-201”] },
{ id: “PID-22”, label: “Device includes debugging capabilities”, threats: [“TID-224”] },
{ id: “PID-23”, label: “Device includes OS/kernel”, threats: [“TID-202”,“TID-218”], children: [
{ id: “PID-231”, label: “OS uses drivers/modules that can be loaded”, threats: [“TID-203”] },
{ id: “PID-232”, label: “Separate users/processes with different OS access”, threats: [], children: [
{ id: “PID-2321”, label: “Device lacks access enforcement/privilege mechanism”, threats: [“TID-204”] },
{ id: “PID-2322”, label: “Device deploys access enforcement/privilege mechanism”, threats: [], children: [
{ id: “PID-23221”, label: “Device includes and enforces OS user accounts”, threats: [“TID-205”,“TID-219”] },
{ id: “PID-23222”, label: “Device includes memory management protections (r/w/x)”, threats: [“TID-206”,“TID-223”] },
]},
]},
]},
{ id: “PID-24”, label: “Device includes virtualization and containers”, threats: [], children: [
{ id: “PID-241”, label: “Device includes containers”, threats: [“TID-207”] },
{ id: “PID-242”, label: “Device includes hypervisor”, threats: [“TID-208”,“TID-209”] },
]},
{ id: “PID-25”, label: “Device includes software/hardware root of trust”, threats: [], children: [
{ id: “PID-251”, label: “Root of Trust is physically accessible or not immutable”, threats: [“TID-214”] },
{ id: “PID-252”, label: “Root of Trust is immutable”, threats: [“TID-220”] },
]},
{ id: “PID-26”, label: “Device lacks firmware/software update support”, threats: [“TID-210”] },
{ id: “PID-27”, label: “Device includes support for firmware/software updates”, threats: [], children: [
{ id: “PID-271”, label: “FW/SW not cryptographically checked for integrity”, threats: [“TID-211”] },
{ id: “PID-272”, label: “Device includes cryptographic FW/SW integrity protection”, threats: [“TID-214”,“TID-330”], children: [
{ id: “PID-2721”, label: “Shared key for firmware integrity validation”, threats: [“TID-212”] },
{ id: “PID-2722”, label: “Digitally signed firmware (with private key)”, threats: [“TID-213”] },
]},
{ id: “PID-273”, label: “Device has unencrypted firmware updates”, threats: [“TID-215”] },
{ id: “PID-274”, label: “User FW/SW version selection during updates”, threats: [“TID-216”] },
{ id: “PID-275”, label: “Remotely-initiated firmware/software updates”, threats: [“TID-217”] },
]},
{ id: “PID-28”, label: “Device stores logs of system events and information”, threats: [“TID-225”,“TID-226”] },
]},
{ category: “Application Software”, icon: Layers, properties: [
{ id: “PID-31”, label: “Application-level software running on the device”, threats: [“TID-301”], children: [
{ id: “PID-311”, label: “Device includes web/HTTP applications”, threats: [“TID-319”,“TID-320”,“TID-321”,“TID-322”,“TID-323”,“TID-324”,“TID-325”] },
{ id: “PID-312”, label: “Device includes programming languages and libraries”, threats: [], children: [
{ id: “PID-3121”, label: “Support for OOP languages (Java, Python, PHP, C++)”, threats: [“TID-326”] },
{ id: “PID-3122”, label: “Support for manual memory management languages (C, C++)”, threats: [“TID-327”] },
]},
]},
{ id: “PID-32”, label: “Ability to deploy custom/external programs”, threats: [“TID-302”], children: [
{ id: “PID-321b”, label: “Deploy custom programs from engineering software/IDE”, threats: [“TID-303”] },
{ id: “PID-322b”, label: “Program runtime environment for custom/external programs”, threats: [“TID-304”] },
{ id: “PID-323b”, label: “Support for program executable formats”, threats: [], children: [
{ id: “PID-3231”, label: “Run native binary without confined environment”, threats: [“TID-305”] },
{ id: “PID-3232”, label: “Run programs through execution sandboxed environment”, threats: [“TID-306”] },
]},
{ id: “PID-324b”, label: “Support for ‘program uploads’ to retrieve programs from device”, threats: [“TID-307”,“TID-308”,“TID-309”] },
]},
{ id: “PID-33”, label: “Device includes interactive applications/services/UIs”, threats: [], children: [
{ id: “PID-331”, label: “Device includes unauthenticated services”, threats: [“TID-310”] },
{ id: “PID-332”, label: “Device includes authenticated services”, threats: [“TID-311”,“TID-312”,“TID-313”,“TID-328”], children: [
{ id: “PID-3321”, label: “Passwords to authenticate users”, threats: [“TID-314”,“TID-315”,“TID-329”] },
{ id: “PID-3322”, label: “Cryptographic mechanism to authenticate users/sessions”, threats: [“TID-316”,“TID-317”,“TID-318”,“TID-330”,“TID-411”] },
]},
]},
{ id: “PID-34”, label: “Device stores logs of application events”, threats: [“TID-225”,“TID-226”] },
]},
{ category: “Networking”, icon: Wifi, properties: [
{ id: “PID-41”, label: “Device exposes remote network services”, threats: [“TID-222”,“TID-310”,“TID-401”,“TID-404”,“TID-405”,“TID-407”], children: [
{ id: “PID-411”, label: “Remote services for sensitive info/configurations”, threats: [], children: [
{ id: “PID-4111”, label: “Lacks protocol support for message authentication”, threats: [“TID-406”] },
{ id: “PID-4112”, label: “Lacks protocol support for message encryption”, threats: [“TID-408”] },
{ id: “PID-4113”, label: “Includes cryptographic functions for sensitive data”, threats: [“TID-221”,“TID-316”,“TID-317”,“TID-318”,“TID-410”,“TID-411”] },
]},
]},
{ id: “PID-42”, label: “Device forwards or routes network messages”, threats: [“TID-412”] },
]},
];

function flatten(nodes, acc = {}) {
for (const n of nodes) { acc[n.id] = n; if (n.children) flatten(n.children, acc); }
return acc;
}
const FLAT_PROPS = PROPERTY_TREE.reduce((acc, cat) => flatten(cat.properties, acc), {});

function threatCat(tid) {
const n = parseInt(tid.split(”-”)[1], 10);
if (n < 200) return { n: “Hardware”, c: “#d97757” };
if (n < 300) return { n: “System Software”, c: “#c6a664” };
if (n < 400) return { n: “Application Software”, c: “#6b9a8b” };
return { n: “Networking”, c: “#7a8db5” };
}

// =====================================================================
// Property Node
// =====================================================================
function PropNode({ node, depth, selected, onToggle, expanded, onExpand }) {
const has = node.children?.length > 0;
const isExp = expanded.has(node.id);
const isSel = selected.has(node.id);
return (
<div>
<div className={`group flex items-start gap-2 py-1.5 pr-2 transition-colors ${isSel ? "bg-[#2a2416]" : "hover:bg-[#181818]"}`} style={{ paddingLeft: `${depth * 18 + 8}px` }}>
<button onClick={() => has && onExpand(node.id)} className={`mt-0.5 shrink-0 ${has ? "text-stone-500 hover:text-stone-200" : "opacity-0"}`}>
{has ? (isExp ? <ChevronDown size={13}/> : <ChevronRight size={13}/>) : <ChevronRight size={13}/>}
</button>
<label className="flex items-start gap-2 cursor-pointer flex-1 min-w-0">
<input type=“checkbox” checked={isSel} onChange={() => onToggle(node.id)} className=“mt-1 shrink-0 accent-[#d97757] cursor-pointer”/>
<span className="flex flex-col gap-0.5 min-w-0">
<span className="flex items-center gap-2 flex-wrap">
<span className={`font-mono text-[10px] tracking-wider shrink-0 ${isSel ? "text-[#d97757]" : "text-stone-400"}`}>{node.id.replace(/b$/,’’)}</span>
{node.threats.length > 0 && <span className="text-[9px] font-mono px-1 py-0.5 bg-[#1f1a12] text-[#c6a664] border border-[#3a2e1c]">{node.threats.length}T</span>}
</span>
<span className={`text-[12px] leading-snug ${isSel ? "text-stone-100" : "text-stone-300"}`}>{node.label}</span>
</span>
</label>
</div>
{has && isExp && <div>{node.children.map(c => <PropNode key={c.id} node={c} depth={depth+1} selected={selected} onToggle={onToggle} expanded={expanded} onExpand={onExpand}/>)}</div>}
</div>
);
}

// =====================================================================
// Main App
// =====================================================================
export default function EMB3DMapper() {
const [selected, setSelected] = useState(new Set());
const [expanded, setExpanded] = useState(new Set());
const [search, setSearch] = useState(””);
const [activeThreat, setActiveThreat] = useState(null);
const [view, setView] = useState(“threats”); // “threats” | “tactics”

const toggle = (id) => setSelected(p => { const n = new Set(p); n.has(id) ? n.delete(id) : n.add(id); return n; });
const toggleExp = (id) => setExpanded(p => { const n = new Set(p); n.has(id) ? n.delete(id) : n.add(id); return n; });

// Compute threats
const threatMap = useMemo(() => {
const m = new Map();
for (const pid of selected) {
const node = FLAT_PROPS[pid];
if (!node) continue;
for (const tid of node.threats) { if (!m.has(tid)) m.set(tid, new Set()); m.get(tid).add(pid); }
}
return m;
}, [selected]);

// Compute tactic heatmap
const tacticHeat = useMemo(() => {
const heat = {};
for (const t of Object.keys(ESTM_TACTICS)) heat[t] = { count: 0, threats: new Set() };
for (const tid of threatMap.keys()) {
const tt = THREATS[tid];
if (!tt) continue;
for (const tac of tt.tactics) { if (heat[tac]) { heat[tac].count++; heat[tac].threats.add(tid); } }
}
return heat;
}, [threatMap]);

const sortedThreats = useMemo(() => {
const arr = Array.from(threatMap.keys()).sort((a, b) => parseInt(a.split(”-”)[1]) - parseInt(b.split(”-”)[1]));
if (!search.trim()) return arr;
const q = search.toLowerCase();
return arr.filter(tid => tid.toLowerCase().includes(q) || THREATS[tid].name.toLowerCase().includes(q));
}, [threatMap, search]);

const threatsByCat = useMemo(() => {
const g = { Hardware: [], “System Software”: [], “Application Software”: [], Networking: [] };
for (const tid of sortedThreats) g[threatCat(tid).n].push(tid);
return g;
}, [sortedThreats]);

const clearAll = () => { setSelected(new Set()); setActiveThreat(null); };
const expandAll = () => { const a = new Set(); const w = ns => { for (const n of ns) { if (n.children) { a.add(n.id); w(n.children); } } }; PROPERTY_TREE.forEach(c => w(c.properties)); setExpanded(a); };

const downloadCSV = () => {
const rows = [[“Threat ID”,“Threat Name”,“Category”,“ESTM Tactics”,“Triggered by Properties”]];
for (const tid of sortedThreats) {
const sources = Array.from(threatMap.get(tid)).sort().join(”; “);
const tactics = THREATS[tid].tactics.join(”; “);
rows.push([tid, THREATS[tid].name, threatCat(tid).n, tactics, sources]);
}
const csv = rows.map(r => r.map(c => `"${String(c).replace(/"/g,'""')}"`).join(”,”)).join(”\n”);
const blob = new Blob([csv], { type: “text/csv” });
const url = URL.createObjectURL(blob);
const a = document.createElement(“a”); a.href = url; a.download = `emb3d-estm-${new Date().toISOString().slice(0,10)}.csv`; a.click(); URL.revokeObjectURL(url);
};

const totalThreats = threatMap.size;
const activeTactics = Object.values(tacticHeat).filter(v => v.count > 0).length;
const maxHeat = Math.max(1, …Object.values(tacticHeat).map(v => v.count));
const severity = totalThreats === 0 ? “—” : totalThreats < 10 ? “LOW” : totalThreats < 25 ? “MOD” : totalThreats < 50 ? “HIGH” : “CRIT”;
const sevColor = totalThreats === 0 ? “#57534e” : totalThreats < 10 ? “#6b9a8b” : totalThreats < 25 ? “#c6a664” : totalThreats < 50 ? “#d97757” : “#b84d3c”;

const [selectedTactic, setSelectedTactic] = useState(null);

return (
<div className=“min-h-screen bg-[#0f0f0f] text-stone-200” style={{ fontFamily: “‘JetBrains Mono’, ‘IBM Plex Mono’, ui-monospace, monospace” }}>
<style>{`@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=Fraunces:opsz,wght@9..144,400;9..144,600;9..144,700&display=swap'); .serif{font-family:'Fraunces',Georgia,serif} ::-webkit-scrollbar{width:6px;height:6px} ::-webkit-scrollbar-track{background:#0f0f0f} ::-webkit-scrollbar-thumb{background:#2a2a2a} ::-webkit-scrollbar-thumb:hover{background:#3a3a3a}`}</style>

```
  {/* Header */}
  <header className="border-b border-stone-800">
    <div className="max-w-[1440px] mx-auto px-5 py-5">
      <div className="flex items-start justify-between flex-wrap gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1.5">
            <div className="w-1.5 h-1.5 bg-[#d97757] animate-pulse"/>
            <span className="text-[9px] tracking-[0.3em] text-stone-500 uppercase">MITRE EMB3D™ + ESTM™ · Property → Threat → Tactic Mapper</span>
          </div>
          <h1 className="serif text-3xl md:text-4xl font-bold text-stone-100 leading-none tracking-tight">
            Threat <span className="italic text-[#d97757]">Surface</span> Analyzer
          </h1>
        </div>
        <div className="flex items-center gap-3 text-center">
          {[
            { label: "Props", val: selected.size, col: "#stone-100" },
            { label: "Threats", val: totalThreats, col: sevColor },
            { label: "Tactics", val: activeTactics, col: activeTactics > 10 ? "#b84d3c" : activeTactics > 5 ? "#c6a664" : "#6b9a8b" },
            { label: "Severity", val: severity, col: sevColor, small: true },
          ].map((s, i) => (
            <React.Fragment key={s.label}>
              {i > 0 && <div className="w-px h-10 bg-stone-800"/>}
              <div>
                <div className="text-[9px] tracking-widest text-stone-500 uppercase">{s.label}</div>
                <div className={`serif ${s.small ? "text-sm font-bold tracking-wider" : "text-2xl font-bold"}`} style={{ color: s.col }}>{s.val}</div>
              </div>
            </React.Fragment>
          ))}
        </div>
      </div>
    </div>
  </header>

  <div className="max-w-[1440px] mx-auto px-5 py-4">
    <div className="grid lg:grid-cols-[1fr_1fr] gap-4">
      {/* LEFT: properties */}
      <section className="border border-stone-800 bg-[#141414]">
        <div className="flex items-center justify-between border-b border-stone-800 px-3 py-2.5">
          <span className="text-[9px] tracking-[0.25em] text-stone-500 uppercase">01 · Device Properties</span>
          <div className="flex items-center gap-1">
            <button onClick={expandAll} className="text-[9px] tracking-wider text-stone-400 hover:text-stone-100 px-2 py-0.5 border border-stone-800 hover:border-stone-600 transition-colors uppercase">Expand</button>
            <button onClick={() => setExpanded(new Set())} className="text-[9px] tracking-wider text-stone-400 hover:text-stone-100 px-2 py-0.5 border border-stone-800 hover:border-stone-600 transition-colors uppercase">Collapse</button>
            <button onClick={clearAll} className="text-[9px] tracking-wider text-[#d97757] hover:text-[#ee8f6d] px-2 py-0.5 border border-[#3a2419] hover:border-[#d97757] transition-colors uppercase">Clear</button>
          </div>
        </div>
        <div className="max-h-[72vh] overflow-y-auto">
          {PROPERTY_TREE.map(cat => {
            const Icon = cat.icon;
            return (
              <div key={cat.category} className="border-b border-stone-800 last:border-b-0">
                <div className="flex items-center gap-2 px-3 py-2.5 bg-[#191919] sticky top-0 z-10 border-b border-stone-800">
                  <Icon size={13} className="text-[#d97757]"/>
                  <h3 className="serif text-sm font-semibold text-stone-100">{cat.category}</h3>
                  <div className="flex-1 border-t border-dashed border-stone-800"/>
                </div>
                <div className="py-0.5">{cat.properties.map(p => <PropNode key={p.id} node={p} depth={0} selected={selected} onToggle={toggle} expanded={expanded} onExpand={toggleExp}/>)}</div>
              </div>
            );
          })}
        </div>
      </section>

      {/* RIGHT: threats + tactics */}
      <section className="border border-stone-800 bg-[#141414] flex flex-col">
        {/* Tab bar */}
        <div className="flex items-center border-b border-stone-800">
          <button onClick={() => setView("threats")} className={`flex items-center gap-1.5 px-4 py-2.5 text-[10px] tracking-[0.2em] uppercase transition-colors border-b-2 ${view === "threats" ? "border-[#d97757] text-stone-100" : "border-transparent text-stone-500 hover:text-stone-300"}`}>
            <AlertTriangle size={12}/> Threats
            {totalThreats > 0 && <span className="ml-1 font-bold">{totalThreats}</span>}
          </button>
          <button onClick={() => setView("tactics")} className={`flex items-center gap-1.5 px-4 py-2.5 text-[10px] tracking-[0.2em] uppercase transition-colors border-b-2 ${view === "tactics" ? "border-[#d97757] text-stone-100" : "border-transparent text-stone-500 hover:text-stone-300"}`}>
            <Crosshair size={12}/> ESTM Tactics
            {activeTactics > 0 && <span className="ml-1 font-bold">{activeTactics}</span>}
          </button>
          <div className="flex-1"/>
          <button onClick={downloadCSV} disabled={totalThreats === 0} className="flex items-center gap-1 text-[9px] tracking-wider px-2.5 py-1 mr-2 border border-stone-800 hover:border-[#d97757] hover:text-[#d97757] text-stone-400 disabled:opacity-30 disabled:cursor-not-allowed transition-colors uppercase">
            <Download size={10}/> CSV
          </button>
        </div>

        {view === "threats" && (
          <>
            <div className="border-b border-stone-800 px-3 py-2 flex items-center gap-2">
              <Search size={12} className="text-stone-500"/>
              <input type="text" value={search} onChange={e => setSearch(e.target.value)} placeholder="Filter threats..." disabled={totalThreats === 0} className="flex-1 bg-transparent text-[11px] text-stone-200 placeholder-stone-600 outline-none disabled:opacity-40"/>
              {search && <button onClick={() => setSearch("")} className="text-stone-500 hover:text-stone-300"><X size={12}/></button>}
            </div>
            <div className="flex-1 overflow-y-auto max-h-[66vh]">
              {totalThreats === 0 ? (
                <div className="flex flex-col items-center justify-center px-8 py-16 text-stone-500">
                  <AlertTriangle size={28} className="text-stone-700 mb-3"/>
                  <div className="serif text-lg text-stone-400 mb-1">No threats yet</div>
                  <p className="text-[11px] max-w-xs text-center leading-relaxed">Select device properties to reveal applicable threats and their ESTM tactic mappings.</p>
                </div>
              ) : sortedThreats.length === 0 ? (
                <div className="px-8 py-10 text-center text-stone-500 text-[11px]">No threats match "{search}"</div>
              ) : (
                Object.entries(threatsByCat).map(([catName, tids]) => {
                  if (!tids.length) return null;
                  const col = threatCat(tids[0]).c;
                  return (
                    <div key={catName} className="border-b border-stone-800 last:border-b-0">
                      <div className="flex items-center gap-2 px-3 py-2 bg-[#191919] border-b border-stone-800">
                        <div className="w-1.5 h-1.5" style={{ background: col }}/>
                        <span className="text-[9px] tracking-[0.2em] uppercase" style={{ color: col }}>{catName}</span>
                        <div className="flex-1 border-t border-dashed border-stone-800"/>
                        <span className="text-[9px] text-stone-500">{tids.length}</span>
                      </div>
                      {tids.map(tid => {
                        const sources = Array.from(threatMap.get(tid)).sort();
                        const isAct = activeThreat === tid;
                        const tt = THREATS[tid];
                        return (
                          <div key={tid} className={`border-b border-stone-900 last:border-b-0 transition-colors ${isAct ? "bg-[#1a1612]" : "hover:bg-[#181818]"}`}>
                            <button onClick={() => setActiveThreat(isAct ? null : tid)} className="w-full text-left px-3 py-2.5 flex items-start gap-2.5">
                              <span className="font-mono text-[10px] tracking-wider shrink-0 pt-0.5" style={{ color: col }}>{tid}</span>
                              <span className="flex-1 text-[12px] text-stone-200 leading-snug">{tt.name}</span>
                              <ChevronDown size={12} className={`text-stone-500 shrink-0 mt-0.5 transition-transform ${isAct ? "rotate-180" : ""}`}/>
                            </button>
                            {isAct && (
                              <div className="px-3 pb-3 pt-1 ml-[52px]">
                                <div className="text-[9px] tracking-widest text-stone-500 uppercase mb-1">Triggered by</div>
                                <div className="flex flex-wrap gap-1 mb-2.5">
                                  {sources.map(pid => <span key={pid} className="font-mono text-[9px] px-1 py-0.5 bg-[#2a2416] text-[#d97757] border border-[#3a2419]">{pid.replace(/b$/,'')}</span>)}
                                </div>
                                <div className="text-[9px] tracking-widest text-stone-500 uppercase mb-1">ESTM Tactics</div>
                                <div className="flex flex-wrap gap-1 mb-2.5">
                                  {tt.tactics.map(tac => (
                                    <span key={tac} className="text-[9px] px-1.5 py-0.5 border" style={{
                                      borderColor: ESTM_TACTICS[tac]?.color + "44",
                                      color: ESTM_TACTICS[tac]?.color,
                                      background: ESTM_TACTICS[tac]?.color + "11",
                                    }}>{tac}</span>
                                  ))}
                                </div>
                                <a href={`https://emb3d.mitre.org/threats/${tid}.html`} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-[10px] text-stone-400 hover:text-[#d97757] tracking-wider">
                                  View on MITRE <ExternalLink size={9}/>
                                </a>
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  );
                })
              )}
            </div>
          </>
        )}

        {view === "tactics" && (
          <div className="flex-1 overflow-y-auto max-h-[70vh]">
            {totalThreats === 0 ? (
              <div className="flex flex-col items-center justify-center px-8 py-16 text-stone-500">
                <Crosshair size={28} className="text-stone-700 mb-3"/>
                <div className="serif text-lg text-stone-400 mb-1">No tactics active</div>
                <p className="text-[11px] max-w-xs text-center leading-relaxed">Select device properties to see which ESTM attack tactics apply to your device.</p>
              </div>
            ) : (
              <div className="p-3 space-y-1">
                {Object.entries(ESTM_TACTICS).map(([name, tac]) => {
                  const h = tacticHeat[name];
                  const pct = h.count / maxHeat;
                  const isActive = h.count > 0;
                  const isSel = selectedTactic === name;
                  return (
                    <div key={name}>
                      <button
                        onClick={() => isActive && setSelectedTactic(isSel ? null : name)}
                        disabled={!isActive}
                        className={`w-full text-left px-3 py-2.5 transition-colors border ${isSel ? "border-stone-600 bg-[#1a1612]" : isActive ? "border-stone-800 hover:border-stone-700 bg-[#141414]" : "border-stone-900 bg-[#111] opacity-40 cursor-default"}`}
                      >
                        <div className="flex items-center gap-2 mb-1.5">
                          <span className="font-mono text-[9px] tracking-wider text-stone-500">{tac.id}</span>
                          <span className={`text-[12px] font-medium ${isActive ? "text-stone-100" : "text-stone-500"}`}>{name}</span>
                          <div className="flex-1"/>
                          {isActive && <span className="font-mono text-[11px] font-bold" style={{ color: tac.color }}>{h.count}</span>}
                        </div>
                        <div className="h-1 bg-stone-900 overflow-hidden">
                          <div className="h-full transition-all duration-500" style={{ width: `${pct * 100}%`, background: isActive ? tac.color : "transparent" }}/>
                        </div>
                        <div className="text-[10px] text-stone-500 mt-1 leading-snug">{tac.desc}</div>
                      </button>
                      {isSel && h.count > 0 && (
                        <div className="border border-t-0 border-stone-700 bg-[#191612] px-3 py-2.5 space-y-1">
                          <div className="text-[9px] tracking-widest text-stone-500 uppercase mb-1">Contributing Threats ({h.count})</div>
                          {Array.from(h.threats).sort((a,b) => parseInt(a.split("-")[1]) - parseInt(b.split("-")[1])).map(tid => (
                            <div key={tid} className="flex items-center gap-2 text-[11px]">
                              <span className="font-mono text-[10px]" style={{ color: threatCat(tid).c }}>{tid}</span>
                              <span className="text-stone-300">{THREATS[tid].name}</span>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}
      </section>
    </div>

    <footer className="mt-4 pt-3 border-t border-stone-800 flex items-center justify-between text-[9px] tracking-wider text-stone-600 uppercase flex-wrap gap-2">
      <span>EMB3D v2.0.1 · {Object.keys(THREATS).length} threats · {Object.keys(FLAT_PROPS).length} properties · ESTM {Object.keys(ESTM_TACTICS).length} tactics</span>
      <div className="flex items-center gap-3">
        <a href="https://emb3d.mitre.org/" target="_blank" rel="noopener noreferrer" className="hover:text-[#d97757] flex items-center gap-1">emb3d.mitre.org <ExternalLink size={8}/></a>
        <a href="https://estm.mitre.org/" target="_blank" rel="noopener noreferrer" className="hover:text-[#d97757] flex items-center gap-1">estm.mitre.org <ExternalLink size={8}/></a>
      </div>
    </footer>
  </div>
</div>
```

);
}