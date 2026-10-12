---
title: "AI Agent Security Series: 1. Taking an AI Agent Apart"
date: 2026-10-10
tags: [ai-agent, attack-surface, architecture]
author: "iamelli0t"
ShowToc: true
TocOpen: true
url: /ai-agent-security/01/
---

Since 2025, mainstream coding agents have entered a period of frequent severe-vulnerability disclosures: Claude Code, Codex, Cursor, Gemini CLI, and GitHub Copilot have each produced vulnerabilities that a malicious repository can trigger remotely. In Claude Code's CVE-2025-59536, hooks configuration shipped by a malicious repository executed before the trust dialog appeared [1]; in Codex CLI's CVE-2025-61260, project-local MCP configuration was auto-loaded, so cloning a single repository handed over execution and the GitHub token [2]; in Cursor's DuneSlide (CVE-2026-50548/49), the sandbox write allowlist was built from model-supplied parameters, letting injected content point the allowlist at the sandbox executor itself [4].

In Gemini CLI's CVE-2026-12537, workspace-trust evaluation and the tool allowlist were both bypassed, ending in command injection in the container launcher [5]; in GitHub Copilot's CVE-2025-53773, a malicious repository wrote autoApprove into settings, dropping the agent straight into fully automatic mode [6]. In September 2026, Codex disclosed two further sandbox escapes without CVE IDs, Heapjack and Overpatch, whose shared root cause is that the sandbox's enforcement mechanism lives in the same trust domain as the code it constrains [3].

The immediate root causes differ, spanning execution timing, configuration auto-loading, sandbox construction, trust evaluation, and allowlist parsing, yet the failures concentrate in a handful of components: configuration loading, permission checking, the sandbox boundary, and the framework's own code. The concentration is not accidental; it follows directly from the agent's internal structure. To answer why the failures land on exactly these components, the agent first has to be taken apart: what it consists of, which inputs can reach it, and how many checkpoints stand in between.

This is the first article in the AI Agent Security series. The series proceeds in one direction: derive the attack surfaces from the internal structure, then the attack paths from each surface, corroborating every step against public CVEs and writeups.

## The Fundamental Difference from Traditional Software: Input Participates in Decisions

Traditional software also deals with untrusted input: browsers parse web pages, mail clients parse messages, and attacker-controlled content enters systems every day. But in traditional software, data and program are separate: the input is data and does not participate in deciding what the program does next. A browser takes a chunk of HTML and renders it by logic written in advance; an attacker who wants control must first find a flaw in the parser or the memory management and turn data into control flow, which is the classical path of vulnerability research and by no means a low bar.

Agents change this premise: web content, issue comments, annotations inside dependency packages, and results returned by MCP servers all enter the agent and directly shape the next tool call and its arguments, as the model turns a piece of text it has read into a tool call; input stops being data and becomes decision input itself.

The difference between the two models:

<svg viewBox="0 0 1050 560" width="680" style="display:block;max-width:100%;height:auto;margin:1.2rem auto" role="img" aria-label="Traditional software vs Agent: the data-control boundary">
  <!-- 上下对比:传统软件输入与控制流之间有一道墙,Agent 同位置墙被移除(虚线残影);配色沿用全文体系 -->
  <defs>
    <marker id="arr3" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor"/></marker>
  </defs>
  <text x="525" y="42" text-anchor="middle" fill="currentColor" font-size="16" font-weight="700">Traditional software</text>
  <g fill="currentColor">
    <rect x="60" y="105" width="170" height="64" rx="12" fill="rgba(100,150,220,0.16)" stroke="#6c8ebf" stroke-width="1.6"/>
    <text x="145" y="131" text-anchor="middle" font-size="13.5" font-weight="600">Untrusted input</text>
    <text x="145" y="151" text-anchor="middle" font-size="10" opacity="0.75">web page · email</text>
    <rect x="300" y="105" width="150" height="64" rx="12" fill="rgba(127,127,127,0.09)" stroke="currentColor" stroke-opacity="0.55" stroke-width="1.6"/>
    <text x="375" y="131" text-anchor="middle" font-size="13.5" font-weight="600">Parser</text>
    <text x="375" y="151" text-anchor="middle" font-size="10" opacity="0.75">strict format</text>
    <rect x="530" y="105" width="210" height="64" rx="12" fill="rgba(127,127,127,0.09)" stroke="currentColor" stroke-opacity="0.9" stroke-width="2.5"/>
    <text x="635" y="131" text-anchor="middle" font-size="13.5" font-weight="600">Program logic</text>
    <text x="635" y="151" text-anchor="middle" font-size="10" opacity="0.75">hard-coded</text>
    <rect x="800" y="105" width="180" height="64" rx="12" fill="rgba(127,127,127,0.09)" stroke="currentColor" stroke-opacity="0.55" stroke-width="1.6"/>
    <text x="890" y="131" text-anchor="middle" font-size="13.5" font-weight="600">Action</text>
    <text x="890" y="151" text-anchor="middle" font-size="10" opacity="0.75">render · compute</text>
  </g>
  <rect x="486" y="88" width="20" height="98" fill="rgba(212,60,60,0.30)" stroke="#d43c3c" stroke-width="1.8"/>
  <g stroke="currentColor" stroke-width="2" fill="none">
    <path d="M230,137 H296" marker-end="url(#arr3)"/>
    <path d="M450,137 H482" marker-end="url(#arr3)"/>
    <path d="M506,137 H526" marker-end="url(#arr3)"/>
    <path d="M740,137 H796" marker-end="url(#arr3)"/>
  </g>
  <text x="530" y="82" text-anchor="middle" fill="#d43c3c" font-size="10.5" font-weight="700">data | control</text>
  <text x="525" y="238" text-anchor="middle" fill="currentColor" font-size="11" opacity="0.8">attacker must find a parser or memory flaw to turn data into control flow</text>
  <line x1="80" y1="272" x2="970" y2="272" stroke="currentColor" stroke-opacity="0.3" stroke-width="1.2" stroke-dasharray="6 5"/>
  <text x="525" y="316" text-anchor="middle" fill="currentColor" font-size="16" font-weight="700">AI Agent</text>
  <g fill="currentColor">
    <rect x="60" y="385" width="170" height="64" rx="12" fill="rgba(212,60,60,0.12)" stroke="#d43c3c" stroke-opacity="0.7" stroke-width="1.6"/>
    <text x="145" y="411" text-anchor="middle" font-size="13.5" font-weight="600">Untrusted input</text>
    <text x="145" y="431" text-anchor="middle" font-size="10" opacity="0.75">web page · issue · MCP result</text>
    <rect x="300" y="385" width="220" height="64" rx="12" fill="rgba(127,127,127,0.09)" stroke="currentColor" stroke-opacity="0.55" stroke-width="1.6"/>
    <text x="410" y="411" text-anchor="middle" font-size="13.5" font-weight="600">Model reads content</text>
    <text x="410" y="431" text-anchor="middle" font-size="10" opacity="0.75">content → decision input</text>
    <rect x="620" y="385" width="180" height="64" rx="12" fill="rgba(247,223,168,0.35)" stroke="#c9a53f" stroke-opacity="0.9" stroke-width="1.6"/>
    <text x="710" y="411" text-anchor="middle" font-size="13.5" font-weight="600">Next tool call</text>
    <text x="710" y="431" text-anchor="middle" font-size="10" opacity="0.75">which tool · what args</text>
  </g>
  <rect x="486" y="385" width="20" height="64" fill="none" stroke="#d43c3c" stroke-width="1.5" stroke-dasharray="5 4"/>
  <text x="530" y="379" text-anchor="middle" fill="#d43c3c" font-size="10.5" font-weight="700">boundary removed</text>
  <g stroke="#d43c3c" stroke-width="2" fill="none">
    <path d="M230,417 H296" marker-end="url(#arr3)"/>
    <path d="M520,417 H616" marker-end="url(#arr3)"/>
  </g>
  <text x="525" y="516" text-anchor="middle" fill="currentColor" font-size="11" opacity="0.8">content directly shapes decisions — no boundary between data and control</text>
</svg>

Input participating in decisions is the first fact; permissions are the second. A coding agent typically holds the developer's full privileges, from reading and writing files and executing commands to using their credentials, and this is the product's premise rather than implementation convenience: an agent that performs real work must hold the power to do it. The two facts together define the central question of agent security: untrusted content can influence decisions, and the execution of those decisions carries full privileges; what stands in between, and can it intercept effectively? Those defenses between input and execution are exactly what Agent security research studies.

The industry has a ready-made summary of this class of risk: the Lethal Trifecta [7]. It names three capabilities held simultaneously: exposure to untrusted content, access to sensitive data, and the ability to communicate outward. With all three present, an attacker can induce the agent to read sensitive data and send it out.

<svg viewBox="0 0 1050 520" width="680" style="display:block;max-width:100%;height:auto;margin:1.2rem auto" role="img" aria-label="Lethal Trifecta as a data flow">
  <!-- 三要素画成穿过 agent 的一条数据流:①不可信内容进 ②敏感数据被读入 ③数据出;配色按进/源/出,低透明度填充适配深浅主题 -->
  <defs>
    <marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor"/></marker>
  </defs>
  <rect x="30" y="95" width="170" height="90" rx="18" fill="rgba(212,60,60,0.10)" stroke="#d43c3c" stroke-opacity="0.8" stroke-width="2"/>
  <g fill="currentColor" text-anchor="middle" font-weight="600"><text x="115" y="133" font-size="19">Attacker</text><text x="115" y="160" font-size="14" font-weight="400">payload</text></g>
  <rect x="400" y="60" width="260" height="160" rx="20" fill="rgba(127,127,127,0.10)" stroke="currentColor" stroke-opacity="0.85" stroke-width="2.5"/>
  <g fill="currentColor" text-anchor="middle"><text x="530" y="122" font-size="22" font-weight="700">Agent</text><text x="530" y="152" font-size="14">context: flat token stream</text><text x="530" y="174" font-size="13" opacity="0.75">(no source tags)</text></g>
  <rect x="400" y="390" width="260" height="100" rx="18" fill="rgba(88,178,128,0.14)" stroke="#58b280" stroke-opacity="0.8" stroke-width="2"/>
  <g fill="currentColor" text-anchor="middle"><text x="530" y="428" font-size="18" font-weight="600">Sensitive data</text><text x="530" y="455" font-size="14">local files · credentials</text><text x="530" y="475" font-size="14">repo secrets</text></g>
  <rect x="850" y="95" width="170" height="90" rx="18" fill="rgba(96,146,220,0.14)" stroke="#6c8ebf" stroke-opacity="0.8" stroke-width="2"/>
  <g fill="currentColor" text-anchor="middle"><text x="935" y="133" font-size="19" font-weight="600">External channel</text><text x="935" y="160" font-size="14" font-weight="400">HTTP · comment · PR</text></g>
  <line x1="200" y1="140" x2="392" y2="140" stroke="currentColor" stroke-width="2.5" marker-end="url(#arr)"/>
  <line x1="660" y1="140" x2="842" y2="140" stroke="currentColor" stroke-width="2.5" marker-end="url(#arr)"/>
  <line x1="530" y1="390" x2="530" y2="228" stroke="currentColor" stroke-width="2.5" marker-end="url(#arr)"/>
  <g fill="currentColor" font-size="16" font-weight="700"><text x="296" y="118" text-anchor="middle">1</text><text x="751" y="118" text-anchor="middle">3</text><text x="556" y="316" text-anchor="start">2</text></g>
  <g fill="currentColor" font-size="14" text-anchor="middle"><text x="296" y="168" opacity="0.8">untrusted content</text><text x="296" y="188" opacity="0.8">issue · web · MCP result</text><text x="751" y="168" opacity="0.8">exfiltration</text><text x="556" y="336" opacity="0.8" text-anchor="start">read</text></g>
  <text x="525" y="30" text-anchor="middle" fill="#d43c3c" font-size="17" font-weight="700">All three present: attacker's content in, your data out, one session</text>
</svg>

The trifecta's three conditions map exactly onto the two facts above: untrusted content influencing decisions is the first fact, and full privileges cover the other two (sensitive data readable, an outbound channel available). It answers whether an attack chain can hold; where the break-in happens and why the defenses fail to intercept it, it does not answer, and those two questions are the subject of the articles that follow. The final article returns here.

## Anatomy of an AI Agent

Viewed as a whole, a running agent passes each request through six layers between the moment the user hits Enter and the moment a command actually executes; two further components sit alongside the six layers, the config plane and the sandbox, and while the config plane is not on the request path, it delivers tool registration, permission rules, and runtime parameters, deciding how the six layers operate; the external environment connects through three channels, content, service, and file. The overall structure and data paths:

<svg viewBox="0 0 900 960" width="620" style="display:block;max-width:100%;height:auto;margin:1.2rem auto" role="img" aria-label="Agent architecture: six layers, config plane, sandbox">
  <!-- 对称布局:主链居中,左栏 Environment / 右栏 Config 等高框外互为镜像;左带两条虚回线,跳弧表示跨线不相连 -->
  <defs>
    <marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor"/></marker>
  </defs>
  <rect x="200" y="110" width="500" height="760" rx="24" fill="rgba(127,127,127,0.05)" stroke="currentColor" stroke-opacity="0.6" stroke-width="1.8"/>
  <text x="700" y="98" text-anchor="end" fill="currentColor" font-size="14" font-weight="700" opacity="0.85">Agent</text>
  <rect x="380" y="30" width="140" height="56" rx="14" fill="rgba(127,127,127,0.10)" stroke="currentColor" stroke-opacity="0.7" stroke-width="1.8"/>
  <text x="450" y="64" text-anchor="middle" fill="currentColor" font-size="17" font-weight="600">User</text>
  <line x1="450" y1="86" x2="450" y2="150" stroke="currentColor" stroke-width="2" marker-start="url(#arr)" marker-end="url(#arr)"/>
  <text x="462" y="124" fill="currentColor" font-size="11.5" opacity="0.8">task / render</text>
  <g fill="currentColor">
    <rect x="250" y="150" width="400" height="64" rx="12" fill="rgba(127,127,127,0.09)" stroke="currentColor" stroke-opacity="0.55" stroke-width="1.6"/>
    <text x="450" y="177" text-anchor="middle" font-size="16.5" font-weight="600">L1 UI</text>
    <text x="450" y="199" text-anchor="middle" font-size="12" opacity="0.75">input · approval · rendering</text>
    <rect x="250" y="246" width="400" height="64" rx="12" fill="rgba(127,127,127,0.09)" stroke="currentColor" stroke-opacity="0.55" stroke-width="1.6"/>
    <text x="450" y="273" text-anchor="middle" font-size="16.5" font-weight="600">L2 Orchestration</text>
    <text x="450" y="295" text-anchor="middle" font-size="12" opacity="0.75">main loop · context · sub-agents</text>
    <rect x="250" y="342" width="400" height="64" rx="12" fill="rgba(127,127,127,0.09)" stroke="currentColor" stroke-opacity="0.55" stroke-width="1.6" stroke-dasharray="6 4"/>
    <text x="450" y="369" text-anchor="middle" font-size="16.5" font-weight="600">L3 Model</text>
    <text x="450" y="391" text-anchor="middle" font-size="12" opacity="0.75">reasoning · stateless</text>
    <rect x="250" y="438" width="400" height="64" rx="12" fill="rgba(247,223,168,0.35)" stroke="#c9a53f" stroke-opacity="0.9" stroke-width="1.6"/>
    <text x="450" y="465" text-anchor="middle" font-size="16.5" font-weight="600">L4 Permission Check</text>
    <text x="450" y="487" text-anchor="middle" font-size="12" opacity="0.8">allow / ask / deny</text>
    <rect x="250" y="534" width="400" height="64" rx="12" fill="rgba(127,127,127,0.09)" stroke="currentColor" stroke-opacity="0.55" stroke-width="1.6"/>
    <text x="450" y="561" text-anchor="middle" font-size="16.5" font-weight="600">L5 Tools</text>
    <text x="450" y="583" text-anchor="middle" font-size="12" opacity="0.75">read / write / exec / network</text>
    <rect x="250" y="650" width="220" height="64" rx="12" fill="rgba(88,178,128,0.14)" stroke="#58b280" stroke-width="1.6"/>
    <text x="360" y="677" text-anchor="middle" font-size="15" font-weight="600">L6 Memory + Storage</text>
    <text x="360" y="699" text-anchor="middle" font-size="11.5" opacity="0.75">memory · logs · credentials</text>
    <rect x="500" y="740" width="150" height="66" rx="12" fill="rgba(150,115,220,0.18)" stroke="#9673a6" stroke-width="1.8" stroke-dasharray="6 4"/>
    <text x="575" y="767" text-anchor="middle" font-size="15.5" font-weight="600">Sandbox</text>
    <text x="575" y="789" text-anchor="middle" font-size="11" opacity="0.8">file · process · network boundaries</text>
  </g>
  <g stroke="currentColor" stroke-width="2">
    <line x1="450" y1="214" x2="450" y2="246" marker-end="url(#arr)"/>
    <line x1="450" y1="310" x2="450" y2="342" marker-end="url(#arr)"/>
    <line x1="450" y1="406" x2="450" y2="438" marker-end="url(#arr)"/>
    <line x1="450" y1="502" x2="450" y2="534" marker-end="url(#arr)"/>
    <line x1="360" y1="598" x2="360" y2="650" marker-start="url(#arr)" marker-end="url(#arr)"/>
    <line x1="565" y1="598" x2="565" y2="740" marker-end="url(#arr)"/>
    <line x1="575" y1="806" x2="575" y2="908" marker-end="url(#arr)"/>
  </g>
  <text x="372" y="630" fill="currentColor" font-size="11" opacity="0.8">read / write</text>
  <text x="577" y="671" fill="currentColor" font-size="11" opacity="0.8">all exec</text>
  <text x="575" y="928" text-anchor="middle" fill="currentColor" font-size="12" opacity="0.8">actions: write · exec · network → external systems</text>
  <path d="M250,470 H222 V182 H250" fill="none" stroke="currentColor" stroke-width="1.6" stroke-dasharray="5 4" marker-start="url(#arr)" marker-end="url(#arr)"/>
  <text x="212" y="326" transform="rotate(-90 212 326)" text-anchor="middle" fill="currentColor" font-size="11" opacity="0.8">ask / approve</text>
  <path d="M360,714 V726 H238 V574 A8 8 0 0 0 238,558 V478 A8 8 0 0 0 238,462 V278 H250" fill="none" stroke="currentColor" stroke-width="1.6" stroke-dasharray="5 4" marker-end="url(#arr)"/>
  <text x="299" y="742" text-anchor="middle" fill="currentColor" font-size="11" opacity="0.8">memory recall</text>
  <rect x="40" y="290" width="120" height="370" rx="16" fill="rgba(100,150,220,0.08)" stroke="#6c8ebf" stroke-opacity="0.7" stroke-width="1.6"/>
  <g fill="currentColor" text-anchor="middle">
    <text x="100" y="330" font-size="11" font-weight="700">EXTERNAL</text>
    <text x="100" y="346" font-size="11" font-weight="700">ENVIRONMENT</text>
  </g>
  <g fill="currentColor">
    <rect x="52" y="375" width="96" height="56" rx="12" fill="rgba(100,150,220,0.16)" stroke="#6c8ebf" stroke-width="1.6"/>
    <text x="100" y="399" text-anchor="middle" font-size="13.5" font-weight="600">Content</text>
    <text x="100" y="419" text-anchor="middle" font-size="11" opacity="0.75">read</text>
    <rect x="52" y="451" width="96" height="56" rx="12" fill="rgba(100,150,220,0.16)" stroke="#6c8ebf" stroke-width="1.6"/>
    <text x="100" y="475" text-anchor="middle" font-size="13.5" font-weight="600">Service</text>
    <text x="100" y="495" text-anchor="middle" font-size="11" opacity="0.75">connect · invoke</text>
    <rect x="52" y="527" width="96" height="56" rx="12" fill="rgba(100,150,220,0.16)" stroke="#6c8ebf" stroke-width="1.6"/>
    <text x="100" y="551" text-anchor="middle" font-size="13.5" font-weight="600">File</text>
    <text x="100" y="571" text-anchor="middle" font-size="11" opacity="0.75">load</text>
  </g>
  <g stroke="#6c8ebf" stroke-width="1.6" fill="none">
    <path d="M148,403 H155 V555 H148"/>
  </g>
  <path d="M155,479 H210 V566 H250" fill="none" stroke="#6c8ebf" stroke-width="2.5" marker-end="url(#arr)"/>
  <text x="182" y="494" text-anchor="middle" fill="#6c8ebf" font-size="10.5">channels</text>
  <rect x="740" y="290" width="120" height="370" rx="16" fill="rgba(255,230,204,0.10)" stroke="#d79b00" stroke-opacity="0.8" stroke-width="1.6"/>
  <text x="800" y="330" text-anchor="middle" fill="currentColor" font-size="11" font-weight="700">CONFIG</text>
  <g fill="currentColor">
    <rect x="752" y="362" width="96" height="50" rx="12" fill="rgba(255,230,204,0.25)" stroke="#d79b00" stroke-width="1.6"/>
    <text x="800" y="383" text-anchor="middle" font-size="12.5" font-weight="600">Hooks</text>
    <text x="800" y="400" text-anchor="middle" font-size="9.5" opacity="0.75">trigger commands</text>
    <rect x="752" y="428" width="96" height="50" rx="12" fill="rgba(255,230,204,0.25)" stroke="#d79b00" stroke-width="1.6"/>
    <text x="800" y="449" text-anchor="middle" font-size="12.5" font-weight="600">Policies</text>
    <text x="800" y="466" text-anchor="middle" font-size="9.5" opacity="0.75">allow · deny</text>
    <rect x="752" y="494" width="96" height="50" rx="12" fill="rgba(255,230,204,0.25)" stroke="#d79b00" stroke-width="1.6"/>
    <text x="800" y="515" text-anchor="middle" font-size="12.5" font-weight="600">Components</text>
    <text x="800" y="532" text-anchor="middle" font-size="9.5" opacity="0.75">MCP · plugins</text>
    <rect x="752" y="560" width="96" height="50" rx="12" fill="rgba(255,230,204,0.25)" stroke="#d79b00" stroke-width="1.6"/>
    <text x="800" y="581" text-anchor="middle" font-size="12.5" font-weight="600">Params</text>
    <text x="800" y="598" text-anchor="middle" font-size="9.5" opacity="0.75">model · keys</text>
  </g>
  <g stroke="#d79b00" stroke-width="2" fill="none">
    <path d="M710,562 V350"/>
    <path d="M650,470 H710"/>
    <path d="M650,545 H710"/>
    <path d="M650,562 H710" stroke-dasharray="5 4"/>
    <path d="M710,350 H740"/>
    <path d="M800,660 V773 H650" marker-end="url(#arr)"/>
  </g>
  <g fill="#d79b00" font-size="10.5">
    <text x="688" y="462" text-anchor="middle">policy</text>
    <text x="688" y="537" text-anchor="middle">register</text>
    <text x="672" y="581" text-anchor="middle">hooks · no check</text>
    <text x="712" y="765" text-anchor="middle">sandbox policy</text>
  </g>
  <path d="M650,490 H730 V730 H620 V740" fill="none" stroke="currentColor" stroke-width="1.6" stroke-dasharray="5 4" marker-end="url(#arr)"/>
  <text x="720" y="615" transform="rotate(-90 720 615)" text-anchor="middle" fill="currentColor" font-size="10.5" opacity="0.8">escalate = swap profile</text>
</svg>

### The Six Layers a Request Traverses

**L1, the UI layer**, carries all interaction between the human and the agent. Users submit tasks through a terminal, an IDE plugin, or a desktop application; approval requests appear as popups or command-line confirmations, and results render here as well. One core can serve multiple frontends: Codex, for example, runs the same core behind both the terminal CLI and the desktop app, with identical approval logic; the only difference is whether the approval dialog is drawn by the terminal or by an application window.

**L2, the orchestration layer**, is the agent's main loop. It maintains the message history and, each turn, assembles the system prompt, tool definitions, conversation record, and tool results into one request to the model, while also handling context compaction and spawning sub-agents. All inputs, whether system prompts, tool definitions, or external content, converge into a single context at this layer.

**L3, the model layer**, does the reasoning, as a remote API or local weights. Each inference call is stateless; the context that survives across turns lives in L2, not on the model side. The diagram draws it with a dashed border because it is the only component the harness does not control. The harness is the code wrapping the model, responsible for assembling requests, executing tools, and managing state; the industry also calls it the framework, and the series uses harness throughout.

**L4, the permission-check layer**, sits between the model and the tools: every tool call the model makes must pass through it, and its verdict is one of allow, ask, or deny. The verdict follows permission rules and approval policies delivered from the config plane, not the model's own judgment.

**L5, the tools layer**, is the agent's only point of action. The tool registry lives here, registering every interface the model can call. What an agent can actually do is decided by which tools this layer registers: registering an MCP server adds an entire external data path to the agent.

**L6, the memory and storage layer**, holds persistent state: project memory, global memory, session records, and credentials. This state survives across sessions; what one session writes is still there in the next. Credentials are stored only at this layer and are used during execution in L5.

### Tool Effects and the Shell Tool

Tools are the agent's only way of acting on the environment, and by effect they fall into four classes.

1) Read tools acquire information about the environment and are the agent's channel for perceiving the outside world.

2) Write tools modify environment state, covering every persistent operation from editing files to committing code.

3) Exec tools run code or processes and carry the most directly destructive potential in an agent's behavior.

4) Communication tools handle network I/O and determine whether the agent can exchange data with the outside.

The four classes are not independent: the attack exits of data exfiltration, C2 channels, and lateral movement are all assembled from communication combined with read or exec.

The shell tool is the convergence point of the four effect classes and the hardest object for permission checking to cover. A single shell command can read files, modify configuration, execute scripts, and communicate outward all at once, and its parameter space is the entire shell language. Permission checking can only perform lexical analysis on it, and lexical analysis does not line up with semantics: the same command has a hundred spellings, and what the parser sees and what the shell actually executes can be two different things. A large share of permission-bypass vulnerabilities originates here, and so does the industry's special treatment of the shell tool: command allowlists, prefix parsing, and mandatory sandboxing are all measures aimed at this one tool.

### Two Components Off the Request Path

Beyond the six layers sit two more components, not on the request path yet deciding how that path behaves.

The config plane is the agent's control plane. Its content falls into four classes: component registration decides which tools exist; permission policies decide how the check evaluates; event hooks define which events trigger which commands; runtime parameters specify the model endpoint and how credentials are obtained. Configuration taking effect is control: whatever tools are registered, the agent can do; whatever rules are written, those actions run without confirmation.

Configuration has one further property: whether a config file is trustworthy depends on the path it was written through, not on its content, and the less trustworthy the write path, the less trustworthy the file. The same config file means something completely different when it ships as a built-in default and when it arrives from a freshly cloned repository. The trust gradient runs in roughly five tiers, from built-in, enterprise-managed, user-directory, and project-directory to marketplace auto-install; the farther along, the less trustworthy, and what agents load most often is precisely the latter tiers. The trust-confirmation mechanisms already in products, VS Code's workspace trust, JetBrains' trusted projects, Claude Code's directory-trust confirmation, cover only the project-directory tier.

The sandbox is the enforcement boundary at execution time. It does not judge whether an action is good; it only bounds what execution can touch: how far the writable range reaches, whether the network is available, whether credentials are visible inside the boundary. The sandbox is implemented by mandatory mechanisms the operating system provides, not by the harness itself: Seatbelt on macOS, bubblewrap or Landlock plus seccomp on Linux, restricted tokens on Windows, and containers; the harness configures and invokes it. The sandbox meets L5 at the execution step: a command the model initiates passes through the sandbox before it reaches external systems, which is what the all exec arrow from L5 to the sandbox in the overview diagram says; the writable range of the write path is likewise defined by sandbox policy.

### Codex Desktop as the Worked Example

Codex Desktop is ChatGPT.app on macOS, carrying the ChatGPT name while its bundle identifier (com.openai.codex) reads Codex. The application consists of a closed-source part and an open-source part: the Electron shell is closed, and its contents sit inside the application bundle, viewable by anyone who installs the app; the embedded core is open, readable in the openai/codex repository. Layers L2 through L6 all live in the core; only L1 belongs to the shell. What follows dissects it layer by layer from public documentation [8], the public repository, and the application bundle contents; the structure and data paths:

<svg viewBox="0 0 900 960" width="620" style="display:block;max-width:100%;height:auto;margin:1.2rem auto" role="img" aria-label="Codex desktop architecture">
  <!-- 对称布局:主链居中,左栏 Environment / 右栏 Config 等高框外互为镜像;左带两条虚回线,跳弧表示跨线不相连 -->
  <defs>
    <marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor"/></marker>
  </defs>
  <rect x="200" y="110" width="500" height="760" rx="24" fill="rgba(127,127,127,0.05)" stroke="currentColor" stroke-opacity="0.6" stroke-width="1.8"/>
  <text x="700" y="98" text-anchor="end" fill="currentColor" font-size="14" font-weight="700" opacity="0.85">Agent — ChatGPT.app</text>
  <rect x="380" y="30" width="140" height="56" rx="14" fill="rgba(127,127,127,0.10)" stroke="currentColor" stroke-opacity="0.7" stroke-width="1.8"/>
  <text x="450" y="64" text-anchor="middle" fill="currentColor" font-size="17" font-weight="600">User</text>
  <line x1="450" y1="86" x2="450" y2="150" stroke="currentColor" stroke-width="2" marker-start="url(#arr)" marker-end="url(#arr)"/>
  <text x="462" y="124" fill="currentColor" font-size="11.5" opacity="0.8">task / render</text>
  <g fill="currentColor">
    <rect x="250" y="150" width="400" height="64" rx="12" fill="rgba(127,127,127,0.09)" stroke="currentColor" stroke-opacity="0.55" stroke-width="1.6"/>
    <text x="450" y="177" text-anchor="middle" font-size="16.5" font-weight="600">L1 UI</text>
    <text x="450" y="199" text-anchor="middle" font-size="12" opacity="0.75">Electron shell — ChatGPT.app</text>
    <rect x="250" y="246" width="400" height="64" rx="12" fill="rgba(127,127,127,0.09)" stroke="currentColor" stroke-opacity="0.55" stroke-width="1.6"/>
    <text x="450" y="273" text-anchor="middle" font-size="16.5" font-weight="600">L2 Orchestration</text>
    <text x="450" y="295" text-anchor="middle" font-size="12" opacity="0.75">codex-rs core · session loop</text>
    <rect x="250" y="342" width="400" height="64" rx="12" fill="rgba(127,127,127,0.09)" stroke="currentColor" stroke-opacity="0.55" stroke-width="1.6" stroke-dasharray="6 4"/>
    <text x="450" y="369" text-anchor="middle" font-size="16.5" font-weight="600">L3 Model</text>
    <text x="450" y="391" text-anchor="middle" font-size="12" opacity="0.75">remote API · provider configurable</text>
    <rect x="250" y="438" width="400" height="64" rx="12" fill="rgba(247,223,168,0.35)" stroke="#c9a53f" stroke-opacity="0.9" stroke-width="1.6"/>
    <text x="450" y="465" text-anchor="middle" font-size="16.5" font-weight="600">L4 Permission Check</text>
    <text x="450" y="487" text-anchor="middle" font-size="12" opacity="0.8">hooks → Guardian → user · approval_policy 4 levels</text>
    <rect x="250" y="534" width="400" height="64" rx="12" fill="rgba(127,127,127,0.09)" stroke="currentColor" stroke-opacity="0.55" stroke-width="1.6"/>
    <text x="450" y="561" text-anchor="middle" font-size="16.5" font-weight="600">L5 Tools</text>
    <text x="450" y="583" text-anchor="middle" font-size="11" opacity="0.75">shell · apply_patch · web_search · MCP · code-mode</text>
    <rect x="250" y="650" width="220" height="64" rx="12" fill="rgba(88,178,128,0.14)" stroke="#58b280" stroke-width="1.6"/>
    <text x="360" y="677" text-anchor="middle" font-size="15" font-weight="600">L6 Memory + Storage</text>
    <text x="360" y="699" text-anchor="middle" font-size="11.5" opacity="0.75">rollout · sqlite · memories · auth</text>
    <rect x="500" y="740" width="150" height="66" rx="12" fill="rgba(150,115,220,0.18)" stroke="#9673a6" stroke-width="1.8" stroke-dasharray="6 4"/>
    <text x="575" y="767" text-anchor="middle" font-size="15.5" font-weight="600">Sandbox</text>
    <text x="575" y="789" text-anchor="middle" font-size="11" opacity="0.8">file · process · network boundaries</text>
  </g>
  <g stroke="currentColor" stroke-width="2">
    <line x1="450" y1="214" x2="450" y2="246" marker-end="url(#arr)"/>
  <text x="468" y="234" fill="currentColor" stroke="none" font-size="11.5">app-server (stdio)</text>
    <line x1="450" y1="310" x2="450" y2="342" marker-end="url(#arr)"/>
    <line x1="450" y1="406" x2="450" y2="438" marker-end="url(#arr)"/>
    <line x1="450" y1="502" x2="450" y2="534" marker-end="url(#arr)"/>
    <line x1="360" y1="598" x2="360" y2="650" marker-start="url(#arr)" marker-end="url(#arr)"/>
    <line x1="565" y1="598" x2="565" y2="740" marker-end="url(#arr)"/>
    <line x1="575" y1="806" x2="575" y2="908" marker-end="url(#arr)"/>
  </g>
  <text x="372" y="630" fill="currentColor" font-size="11" opacity="0.8">read / write</text>
  <text x="577" y="671" fill="currentColor" font-size="11" opacity="0.8">all exec</text>
  <text x="575" y="928" text-anchor="middle" fill="currentColor" font-size="12" opacity="0.8">exec: workspace + /tmp write · network off by default</text>
  <path d="M250,470 H222 V182 H250" fill="none" stroke="currentColor" stroke-width="1.6" stroke-dasharray="5 4" marker-start="url(#arr)" marker-end="url(#arr)"/>
  <text x="212" y="326" transform="rotate(-90 212 326)" text-anchor="middle" fill="currentColor" font-size="11" opacity="0.8">ask / approve</text>
  <path d="M360,714 V726 H238 V574 A8 8 0 0 0 238,558 V478 A8 8 0 0 0 238,462 V278 H250" fill="none" stroke="currentColor" stroke-width="1.6" stroke-dasharray="5 4" marker-end="url(#arr)"/>
  <text x="299" y="742" text-anchor="middle" fill="currentColor" font-size="11" opacity="0.8">memory recall</text>
  <rect x="40" y="290" width="120" height="370" rx="16" fill="rgba(100,150,220,0.08)" stroke="#6c8ebf" stroke-opacity="0.7" stroke-width="1.6"/>
  <g fill="currentColor" text-anchor="middle">
    <text x="100" y="330" font-size="11" font-weight="700">EXTERNAL</text>
    <text x="100" y="346" font-size="11" font-weight="700">ENVIRONMENT</text>
  </g>
  <g fill="currentColor">
    <rect x="52" y="375" width="96" height="56" rx="12" fill="rgba(100,150,220,0.16)" stroke="#6c8ebf" stroke-width="1.6"/>
    <text x="100" y="399" text-anchor="middle" font-size="13.5" font-weight="600">Content</text>
    <text x="100" y="419" text-anchor="middle" font-size="9.5" opacity="0.75">files · web pages</text>
    <rect x="52" y="451" width="96" height="56" rx="12" fill="rgba(100,150,220,0.16)" stroke="#6c8ebf" stroke-width="1.6"/>
    <text x="100" y="475" text-anchor="middle" font-size="13.5" font-weight="600">Service</text>
    <text x="100" y="495" text-anchor="middle" font-size="9.5" opacity="0.75">MCP servers</text>
    <rect x="52" y="527" width="96" height="56" rx="12" fill="rgba(100,150,220,0.16)" stroke="#6c8ebf" stroke-width="1.6"/>
    <text x="100" y="551" text-anchor="middle" font-size="13.5" font-weight="600">File</text>
    <text x="100" y="571" text-anchor="middle" font-size="9.5" opacity="0.75">AGENTS.md · skills</text>
  </g>
  <g stroke="#6c8ebf" stroke-width="1.6" fill="none">
    <path d="M148,403 H155 V555 H148"/>
  </g>
  <path d="M155,479 H210 V566 H250" fill="none" stroke="#6c8ebf" stroke-width="2.5" marker-end="url(#arr)"/>
  <text x="182" y="494" text-anchor="middle" fill="#6c8ebf" font-size="10.5">channels</text>
  <rect x="740" y="290" width="120" height="370" rx="16" fill="rgba(255,230,204,0.10)" stroke="#d79b00" stroke-opacity="0.8" stroke-width="1.6"/>
  <text x="800" y="330" text-anchor="middle" fill="currentColor" font-size="11" font-weight="700">CONFIG</text>
  <g fill="currentColor">
    <rect x="752" y="362" width="96" height="50" rx="12" fill="rgba(255,230,204,0.25)" stroke="#d79b00" stroke-width="1.6"/>
    <text x="800" y="383" text-anchor="middle" font-size="12.5" font-weight="600">Hooks</text>
    <text x="800" y="400" text-anchor="middle" font-size="9.5" opacity="0.75">trigger commands</text>
    <rect x="752" y="428" width="96" height="50" rx="12" fill="rgba(255,230,204,0.25)" stroke="#d79b00" stroke-width="1.6"/>
    <text x="800" y="449" text-anchor="middle" font-size="12.5" font-weight="600">Policies</text>
    <text x="800" y="466" text-anchor="middle" font-size="9.5" opacity="0.75">allow · deny</text>
    <rect x="752" y="494" width="96" height="50" rx="12" fill="rgba(255,230,204,0.25)" stroke="#d79b00" stroke-width="1.6"/>
    <text x="800" y="515" text-anchor="middle" font-size="12.5" font-weight="600">Components</text>
    <text x="800" y="532" text-anchor="middle" font-size="9.5" opacity="0.75">MCP · plugins</text>
    <rect x="752" y="560" width="96" height="50" rx="12" fill="rgba(255,230,204,0.25)" stroke="#d79b00" stroke-width="1.6"/>
    <text x="800" y="581" text-anchor="middle" font-size="12.5" font-weight="600">Params</text>
    <text x="800" y="598" text-anchor="middle" font-size="9.5" opacity="0.75">model · keys</text>
  </g>
  <g stroke="#d79b00" stroke-width="2" fill="none">
    <path d="M710,562 V350"/>
    <path d="M650,470 H710"/>
    <path d="M650,545 H710"/>
    <path d="M650,562 H710" stroke-dasharray="5 4"/>
    <path d="M710,350 H740"/>
    <path d="M800,660 V773 H650" marker-end="url(#arr)"/>
  </g>
  <g fill="#d79b00" font-size="10.5">
    <text x="688" y="462" text-anchor="middle">policy</text>
    <text x="688" y="537" text-anchor="middle">register</text>
    <text x="672" y="581" text-anchor="middle">hooks · no check</text>
    <text x="712" y="765" text-anchor="middle">sandbox policy</text>
  </g>
  <path d="M650,490 H730 V730 H620 V740" fill="none" stroke="currentColor" stroke-width="1.6" stroke-dasharray="5 4" marker-end="url(#arr)"/>
  <text x="720" y="615" transform="rotate(-90 720 615)" text-anchor="middle" fill="currentColor" font-size="10.5" opacity="0.8">escalate = swap profile</text>
</svg>

The complete task flow (desktop):

1. The application opens; the shell starts and launches the embedded core as a child process. The core reads configuration: ~/.codex/config.toml is the user-level file, holding approval_policy, sandbox_mode, mcp_servers, and the model provider; enterprises can push configuration through managed_config.toml or macOS MDM (the enterprise device-management channel), with priority over user files and command-line arguments. This corresponds to the enterprise-managed tier of the trust gradient above.
2. The user types a task in the window; the shell hands it to the core, and the session main loop takes over (mostly in codex-rs's core crate). Each turn assembles the system prompt, AGENTS.md, tool definitions, and conversation history into one request.
3. AGENTS.md enters the context at this step: the global ~/.codex/AGENTS.md is read first, then the walk proceeds from the repository root down to the current directory, taking at most one file per directory and concatenating them; skills (SKILL.md prompt packs with attached executable scripts) load at this step as well. Any instruction carried inside the project directory enters the model's context this way.
4. The request goes to the remote model service, which returns tool calls.
5. The check. A command must clear three checkpoints: the PermissionRequest stage of hooks runs first, Guardian (a built-in model-based review that scores commands) sits in the middle, and the approval_policy closes, deciding between auto-approval and a prompt. approval_policy has four tiers, untrusted, on-failure, on-request, and never, and version-controlled directories default to the Auto profile (workspace-write plus on-request): writes outside the workspace and network-requiring commands both ask the user, while non-version-controlled directories default to read-only. How the approval is presented varies with the frontend: a command-line confirmation in the terminal, a dialog in the application window on the desktop, while whether to approve is still decided by the core logic.
6. Execution. Commands go into the sandbox before running: Seatbelt on macOS (via sandbox-exec with a generated policy), Landlock plus seccomp on Linux, restricted tokens on Windows, with two further backends, a firewall and the Microsoft eXecution Container (Microsoft's open-source sandbox execution framework). The writable range of workspace-write is the workspace plus the temporary directory. A command's network access is a separate boundary, allowlisted per domain through a built-in proxy; it substitutes for the file boundary in neither direction, and defaults to locked down as well.
7. Tool results are folded back into the context for the next turn. All state lands in ~/.codex: session records (rollout files) and the sqlite state database, with login credentials and persistent memory in the same directory, shared with the CLI.

What the desktop app adds over the CLI lies almost entirely in L1: graphical interface, login, the built-in browser view, system notifications, auto-update. This layer's code is not in the open-source repository, but Electron applications package their UI code inside app.asar.

Back to the overview diagram, cell by cell:

| Structural position | What it is in Codex Desktop |
|---|---|
| L1 UI | Electron shell: a Chromium renderer draws the interface while the main process manages windows, login, the built-in browser view, and auto-update; the shell hands tasks to the embedded core |
| L2 Orchestration | the session main loop inside the embedded core (codex-rs's core crate); AGENTS.md enters the context during request assembly |
| L3 Model | remote model service (OpenAI by default, provider configurable) |
| L4 Permission check | the hooks → Guardian → approval_policy stack; the approval_policy tiers decide auto-approval or a prompt; the approval dialog is a window in the application |
| L5 Tools | shell (persistent session and one-shot commands), apply_patch, web_search, MCP servers, code-mode (V8) |
| L6 Memory and storage | rollout session records, sqlite state database, memories, login credentials (~/.codex) |
| Config plane | ~/.codex/config.toml; enterprise managed_config / MDM take priority |
| Sandbox | read-only / workspace-write / danger-full-access profiles; Seatbelt on macOS, Landlock/seccomp on Linux, restricted tokens on Windows; the network boundary is independent, allowlisted per domain through a built-in proxy |

Claude Code has the same shape: settings.json corresponds to the config plane, the allow/deny rules under permissions are L4's decision input, and hooks are the config plane's event hooks [9]. The CVE-2025-59536 mentioned at the opening failed exactly in the hooks field.

## Two Structural Facts

With the structure taken apart, two conclusions follow, both arising from how the structure itself works rather than from implementation bugs, and every attack surface derived later starts from these two.

**Structural fact 1: all external content converges, at assembly time, into one flat token stream, and provenance is lost at that step.**

When L2 assembles a request, the system prompt, tool definitions, conversation history, tool results, and read-in files are all concatenated into one sequence with no structural source markers. The model cannot distinguish which segment is the system prompt written by the product's developers and which is a comment written by an attacker in an issue. A product can insert text like "the following is tool output," but that is a text-level convention the model has learned to follow, not a structural guarantee.

Simon Willison's phrasing of the same fact: "LLMs are unable to reliably distinguish the importance of instructions based on where they came from. Everything eventually gets glued together into a sequence of tokens and fed to the model." [7]

Codex's AGENTS.md is a direct example: an instruction file inside the project, whose content enters the context verbatim. Clone a repository, and whatever instructions hide inside it are delivered to the model, with no way to tell who wrote them.

**Structural fact 2: the permission checkpoint covers only the model-to-action segment; content ingestion and configuration loading never pass through it.**

Against the overview diagram: L4 sits between L3 and L5 and governs only the tool calls the model initiates. Content enters the context through L5's read tools or channels further upstream, and configuration loading reaches the config plane directly through the file channel; neither path crosses L4.

This one is the key to understanding configuration-class vulnerabilities, and CVE-2025-59536 turns on exactly this: the hooks configuration executed before the trust dialog appeared; before the user had any chance to say "I trust this directory," the configured command had already finished. The problem is that this path lies entirely outside the check's jurisdiction, not that the check's rules were wrongly written.

## Permission Checking and the Sandbox: Two Independent Dimensions, Not Either-Or

One common misconception needs correcting here: treating permission checking and the sandbox as two parallel, interchangeable switches for skipping confirmation, as in "either a dialog asks me, or the action goes into the sandbox; pick one." This reading does not hold, and it is the source of a number of product defects. Checking and sandboxing are two independent dimensions:

| | Permission check | Sandbox |
|---|---|---|
| Question answered | Is this action allowed at all | What the action can touch when it happens |
| Nature of the mechanism | a per-action check at the moment of decision | a boundary sustained for the whole of execution |
| Strengths | flexible, fine-grained, able to express intent | deterministic, independent of judgment quality, kernel-level |
| Weaknesses | lexical parsing errors, approval fatigue, rules sourced from writable configuration | coarse granularity, incomplete coverage |

The weaknesses of one are the strengths of the other, and vice versa. The correct relation is stacking, not either-or: the sandbox is the backstop, and the check governs only the actions that must leave the boundary. An auto-approved authorization should rest on boundary coverage, not on the check: a pass from the check means only "no question this time," and this execution must at least stay inside the sandbox; a pass with execution outside the sandbox's reach equals no constraint at all.

There is a worse shape: the sandbox that should be the backstop becomes the reason for skipping the check, as in "the sandbox will catch it, don't ask." The sandbox then not only fails to backstop but vouches for the check. This shape is left for the sandbox article.

## Closing Notes

None of the attack surfaces this series develops takes the model as its object of attack; all of them land on the code wrapping the model: configuration, permission checking, the sandbox, and the framework itself. This pattern recurs throughout the series, and it is also the premise that many "defend AI with AI" proposals never spell out.

The correct shape of the authorization mechanism is left unopened here, to be taken up in the final article, once the attack surfaces and attack paths have been walked and the whole series is collected.

The next article derives the attack surfaces from the two structural facts: where each surface sits, how an attacker writes into it, and why the existing checkpoints fail to stop it.

## References

[1] Check Point Research — RCE and API Token Exfiltration Through Claude Code Project Files (CVE-2025-59536): https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/

[2] NVD — CVE-2025-61260 (OpenAI Codex CLI ≤ 0.23.0): https://nvd.nist.gov/vuln/detail/CVE-2025-61260

[3] BleepingComputer — Researchers escape OpenAI Codex sandbox to run commands on host (Heapjack / Overpatch): https://www.bleepingcomputer.com/news/security/researchers-escape-openai-codex-sandbox-to-run-commands-on-host/

[4] Cato AI Labs — DuneSlide: Two Critical RCE Vulnerabilities (CVE-2026-50548 / 50549): https://www.catonetworks.com/blog/duneslide-two-critical-rce-vulnerabilities/

[5] NVD — CVE-2026-12537 (Google Gemini CLI): https://nvd.nist.gov/vuln/detail/CVE-2026-12537

[6] Embrace The Red — GitHub Copilot: Remote Code Execution via Prompt Injection (CVE-2025-53773): https://embracethered.com/blog/posts/2025/github-copilot-remote-code-execution-via-prompt-injection/

[7] Simon Willison — The lethal trifecta for AI agents: https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/

[8] OpenAI Codex documentation (config, sandbox, approval policy, AGENTS.md): https://developers.openai.com/codex/

[9] Claude Code documentation (settings, permissions, hooks): https://code.claude.com/docs/

[10] GitHub — openai/codex source repository (codex-rs Rust project): https://github.com/openai/codex
