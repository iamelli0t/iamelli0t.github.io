---
title: "AI Agent 安全系列：1. AI Agent 结构拆解"
date: 2026-10-10
tags: [ai-agent, attack-surface, architecture]
author: "iamelli0t"
ShowToc: true
TocOpen: true
url: /zh/ai-agent-security/01/
---

2025 年以来，主流 coding agent 的漏洞通报进入高发期，Claude Code、Codex、Cursor、Gemini CLI、GitHub Copilot 相继出现可由恶意仓库远程触发的严重漏洞。Claude Code 的 CVE-2025-59536，恶意仓库携带的 hooks 配置先于信任对话框执行[1]；Codex CLI 的 CVE-2025-61260，项目本地的 MCP 配置被自动加载，克隆一个仓库就交出执行权与 GitHub token[2]；Cursor 的 DuneSlide（CVE-2026-50548/49），沙箱写入白名单按模型填写的参数构建，注入内容可以让白名单指向沙箱执行器本身[4]。

Gemini CLI 的 CVE-2026-12537，工作区信任判断与工具白名单被绕过，最终落到容器启动器的命令注入[5]；GitHub Copilot 的 CVE-2025-53773，恶意仓库把 autoApprove 写进设置，agent 直接进入全自动模式[6]。2026 年 9 月，Codex 再披露 Heapjack 与 Overpatch 两个无 CVE 编号的沙箱逃逸漏洞，共同根因是沙箱的强制机制与被它限制的代码处在同一信任域[3]。

这些漏洞的直接根因各不相同，覆盖执行时序、配置自动加载、沙箱构建方式、信任判断与白名单解析，但失效位置集中在少数几个部件上：配置加载、权限判定、沙箱边界与框架自身代码。失效位置如此集中并非偶然，它与 agent 的内部结构直接相关。要回答“为什么是这几个位置”，需要先把 agent 拆开，弄清它由哪些部件组成、哪些输入能够进入、中间有几道关卡。

这是 AI Agent 安全系列的第一篇。系列的分析路径是：从内部结构推导攻击面，再从每个攻击面推导攻击路径，每一步用公开的 CVE 与 writeup 印证。

## 与传统软件的本质差别：输入参与决策

传统软件同样要处理不可信输入：浏览器解析网页，邮件客户端解析邮件，攻击者控制的内容每天都在进入系统。但传统软件的数据与程序是分离的，输入是数据，不参与决定程序下一步做什么。浏览器拿到一段 HTML，按照写定的渲染逻辑绘制页面；攻击者若想利用，必须先找到解析器或内存管理的缺陷，把数据变成控制流，这是漏洞挖掘的传统路径，门槛不低。

agent 改变了这个前提，网页内容、issue 评论、依赖包里的注释、MCP server 返回的结果，进入 agent 之后都直接参与决定下一步调用哪个工具、传递什么参数，模型把读进的一段文字转成一次工具调用，输入由此从数据变成了决策依据本身。

两种模型的差别如下图：

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

输入参与决策是第一条事实，权限是第二条。coding agent 通常持有开发者本人的完整权限，从读写文件、执行命令到使用其凭证，这种权限是产品前提而非实现上的省事：agent 要执行业务，就必须持有相应权限。两条事实合在一起，构成 agent 安全的核心问题：不可信内容能够影响决策，决策的执行又携带完整权限，中间的防线是什么、能否有效拦截。输入与执行之间的这些防线，正是 Agent 安全研究的对象。

业界对这类风险早有概括，即 Lethal Trifecta（致命三要素）[7]：一个 agent 同时具备接触不可信内容、读取敏感数据、对外通信三种能力时，攻击者就能够诱导 agent 把敏感数据读出来、发送出去。

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

Trifecta 的三个条件与前文两条事实完全对应：不可信内容影响决策对应第一条，完整权限覆盖后两条（敏感数据可读、数据具备外发通道）。它回答的是攻击链能否成立；至于从哪里攻破、防线为什么拦不住，它没有回答，而这两问是后续各篇的主题，最后一篇会回到这里。

## AI Agent 的结构剖析

从整体结构看，一个 agent 运行时，从用户按下回车到命令真正执行，请求依次经过六层；六层之外另有配置面与沙箱两个部件，配置面不在请求通路上，但工具注册、权限规则与运行参数都由它下发，六层的运行方式由它决定；外部环境经内容、服务与文件三条通道接入。总体结构与数据通路如下图：

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

### 请求经过的六层

**L1 界面层**承载人与 agent 的全部交互。用户通过终端、IDE 插件或桌面应用提交任务，审批请求以弹窗或命令行确认框的形式呈现，执行结果也在这一层展示。同一个核心可以搭配不同的界面形态：以 Codex 为例，同一套核心同时支撑终端命令行和桌面应用，审批逻辑完全一致，差异只在于审批框由命令行还是应用窗口呈现。

**L2 编排层**是整个 agent 的主循环，负责维护消息历史，并在每一轮把系统提示、工具定义、对话记录与工具返回结果组装成一个请求发送给模型，同时承担上下文压缩与子 agent 的派生。所有输入，无论来自系统提示、工具定义还是外部内容，最终都在这一层汇成同一个上下文。

**L3 模型层**承担推理，形态为远端 API 或本地权重，每一轮推理都是无状态的，跨轮存活的上下文保存在 L2 而非模型侧。图中将其画为虚线框，因为它是整个结构里唯一不受 harness 控制的部件。harness 指包裹模型的这层代码，负责组装请求、执行工具与管理状态，业内也称为框架，全篇统一用 harness 这个词。

**L4 权限判定层**位于模型与工具之间：模型每一次调用工具都必须经过它，判定结果为允许、询问、拒绝三选一。判定的依据是配置面下发的权限规则与审批策略，而非模型自身的判断。

**L5 工具层**是 agent 唯一的动作出口，工具注册表位于这一层，模型能够调用的所有接口都在这里注册。agent 实际能做什么，取决于这一层注册了哪些工具：注册一个 MCP server，就等于为 agent 增加了一整条外部数据通路。

**L6 记忆与存储层**保存持久状态，包括项目记忆、全局记忆、会话记录与凭证。这些状态跨会话存活，本次会话写入的内容在下一次会话中依然存在。凭证只在这一层存放，实际使用发生在 L5 执行时。

### 工具效果分类与 shell 工具

工具是 agent 作用于环境的唯一途径，按效果分为四类。

1）读取类获取环境信息，是 agent 认知外部世界的通道。

2）写入类修改环境状态，覆盖从编辑文件到提交代码的全部持久化操作。

3）执行类运行代码或进程，是 agent 行为中破坏力最直接的一类。

4）通信类负责网络收发，决定 agent 能否与外部交换数据。

四类效果并不彼此独立，数据外带、C2 通道、横向移动这些攻击出口，全部由通信配合读取或执行组合完成。

shell 工具是四类效果的交汇点，也是权限判定最难覆盖的对象。一条 shell 命令可以同时完成读取文件、修改配置、执行脚本与对外通信，其参数空间是整个 shell 语言；权限判定面对它只能做词法解析，而词法解析与语义天然对不上：同一段命令可以有一百种写法，解析器看到的与 shell 实际执行的可以是两回事。大量判定绕过漏洞源于此处，行业对 shell 工具的单独对待也源于此处，命令白名单、前缀解析、强制沙箱等措施全部针对这一个工具而设。

### 不在请求链上的两个部件

六层之外还有两个部件，它们不在请求链上，却决定着这条链的行为。

配置面是 agent 的控制面，内容分为四类：组件注册决定注册了哪些工具，权限策略规定权限规则如何判定，事件钩子定义什么事件触发什么命令，运行参数指定模型端点与凭证的获取方式。配置生效即控制：注册了什么工具，agent 就能做什么；写入了什么权限规则，什么动作就免于确认。

配置还有一个关键性质：判断一份配置可信不可信，看的是它经过什么途径写进来，与内容本身无关，写入途径越不可信，这份配置就越不可信。同一份配置，来自产品内置默认值与来自刚克隆的仓库，信任级别完全不同。信任梯度大致为五档，从内置、企业下发、用户目录、项目目录到市场自动安装，越靠后越不可信，而 agent 最常加载的正是后面几种。产品里已有的信任确认机制，VS Code 的工作区信任、JetBrains 的可信项目、Claude Code 的目录信任确认，覆盖的都只是项目目录这一档。

沙箱是执行层面的约束边界。它不判断动作的好坏，只限制执行时能够触达的范围：可写范围多大、网络是否可用、凭证在边界内是否可见。沙箱由操作系统提供的强制机制实现，不由 harness 自己实现，包括 macOS 的 Seatbelt、Linux 的 bubblewrap 或 Landlock 加 seccomp、Windows 的受限令牌（restricted token），以及容器；harness 负责对它进行配置和调用。沙箱与 L5 的衔接在执行这一步：模型发起的命令在落到外部系统前先经过沙箱，总图上 L5 指向沙箱的 all exec 说的就是这个；写入路径的可写范围同样由沙箱策略界定。

### 以 Codex 桌面版为例

Codex 桌面版在 macOS 上是 ChatGPT.app，应用挂着 ChatGPT 的名字，包标识（com.openai.codex）写的却是 Codex。这个应用由闭源与开源两部分组成：Electron 壳闭源，内容都在应用包目录里，装了应用就能查看；内嵌的核心开源，代码在 openai/codex 仓库中可以直接阅读。六层中的 L2 到 L6 都落在核心上，只有 L1 属于壳。以下依据公开文档[8]、公开仓库与应用包内容逐层拆解，结构与数据通路如下图：

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
    <text x="450" y="487" text-anchor="middle" font-size="12" opacity="0.8">hooks → Guardian → user · approval_policy 四档</text>
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

任务的完整流程（桌面版）如下：

1. 打开应用，壳启动并拉起内嵌的核心子进程。核心读配置：~/.codex/config.toml 是用户级配置，approval_policy、sandbox_mode、mcp_servers、模型 provider 都写在这里；企业可以用 managed_config.toml 或 macOS 的 MDM（企业设备管理下发通道）推配置，优先级高于用户文件与命令行参数。这对应前文信任梯度中的“企业下发”一档。
2. 在窗口里输入任务，壳把任务递给核心，由会话主循环接管（主体在 codex-rs 的 core crate）。每一轮把系统提示、AGENTS.md、工具定义、对话历史拼成一个请求。
3. AGENTS.md 在这一步进上下文：先读全局的 ~/.codex/AGENTS.md，再从仓库根向下走到当前目录，每层目录最多取一个文件，拼接在一起；skills（SKILL.md 提示包，附带可执行脚本）也在这一步加载，项目目录里携带的任何指令都由此进入模型上下文。
4. 请求发往远端模型服务，模型返回工具调用。
5. 判定。命令要过三道关卡：hooks 的 PermissionRequest 环节先行，Guardian（内置的模型自动审查，用模型给命令评分）居中，approval_policy 收尾，由它决定自动放行还是弹出审批。approval_policy 分 untrusted、on-failure、on-request、never 四档，版本控制目录默认取 Auto 档（workspace-write 加 on-request）：工作区外的写入与需要联网的命令都问用户，非版本控制目录则默认只读。审批的呈现随界面而变：终端里是命令行确认框，桌面版是应用窗口里的对话框，批不批仍由核心逻辑决定。
6. 执行。命令先放进沙箱再运行：macOS 用 Seatbelt（经 sandbox-exec 带上生成的策略），Linux 用 Landlock 加 seccomp，Windows 用受限令牌，另有防火墙与微软执行容器（Microsoft eXecution Container，微软开源的沙箱执行框架）两类后端。workspace-write 的可写范围是工作区加临时目录。命令的网络访问另成一条边界，经内置代理按域名放行，与文件边界互不替代，默认同样收紧。
7. 工具结果拼回上下文，进入下一轮。整个过程的状态都落在 ~/.codex：会话记录（rollout 文件）与 sqlite 状态库，登录凭证与持久记忆也在这个目录下，与 CLI 共享。

桌面版相对 CLI 多出的部分基本都在 L1：图形界面、登录、内置浏览器视图、系统通知、自动更新。这一层的代码不在开源仓库中，但 Electron 应用将界面代码打包在 app.asar 里。

回到总图，逐格对上：

| 结构位置 | Codex 桌面版里的东西 |
|---|---|
| L1 界面 | Electron 壳：Chromium 渲染进程画界面，主进程管窗口、登录、内置浏览器视图、自动更新；壳把任务递给内嵌核心 |
| L2 编排 | 内嵌核心（codex-rs 的 core crate）里的会话主循环；AGENTS.md 在组装请求时进上下文 |
| L3 模型 | 远端模型服务（默认 OpenAI，provider 可配） |
| L4 判定 | 判定栈 hooks → Guardian → approval_policy；approval_policy 四档决定自动放行或弹出审批，审批框是应用窗口里的对话框 |
| L5 工具 | shell（持久会话与一次性命令）、apply_patch、web_search、MCP server、code-mode（V8） |
| L6 记忆与存储 | rollout 会话记录、sqlite 状态库、memories、登录凭证（~/.codex） |
| 配置面 | ~/.codex/config.toml，企业 managed_config / MDM 优先级更高 |
| 沙箱 | read-only / workspace-write / danger-full-access 三档；macOS Seatbelt、Linux Landlock/seccomp、Windows 受限令牌；网络边界独立，经内置代理按域名放行 |

Claude Code 与此同构：settings.json 对应配置面，permissions 中的 allow/deny 规则是 L4 的判定输入，hooks 是配置面里的事件钩子[9]。开篇提到的 CVE-2025-59536，问题正出在 hooks 字段。

## 两条结构性事实

结构拆解完成，得到两条结论：这两条都源于结构本身的工作方式，不是实现上的 bug，后续推导的攻击面全部从这两条出发。

**结构性事实 1：所有外部内容在组装时汇成同一条平坦的 token 流，来源信息在这一步丢失。**

L2 组装请求时，系统提示、工具定义、对话历史、工具返回、读入的文件全部拼成一条序列，序列里没有结构化的来源标记。模型收到时无法区分哪段是产品开发者写的系统提示，哪段是攻击者在 issue 里写的评论。产品可以在文本中加入“以下是工具返回的内容”这类说明，但那是文本层面的约定，靠模型学习得来，不是结构保证。

Simon Willison 对同一事实的表述："LLMs are unable to reliably distinguish the importance of instructions based on where they came from. Everything eventually gets glued together into a sequence of tokens and fed to the model."[7]

Codex 的 AGENTS.md 是一个直接例子：项目里的指令文件，内容直接进入上下文。克隆一个仓库，里面藏着什么指令，模型就收到什么指令，且无从分辨这些指令来自谁。

**结构性事实 2：判定检查点位于“模型 → 动作”这一段，内容进入与配置加载都不经过它。**

对照总图：L4 位于 L3 与 L5 之间，只管辖模型发起的工具调用。内容进入上下文走的是 L5 的读取工具或更靠前的通道，配置加载走文件通道直达配置面，两条路径都不经过 L4。

这一条是理解配置类漏洞的关键，CVE-2025-59536 的核心也在这里：hooks 配置在信任对话框弹出之前执行，用户还没来得及表达“我信任这个目录”，配置里的命令已经跑完。问题出在这条路径根本不在判定的管辖范围内，判定的规则本身没有写错。

## 判定与沙箱：两个独立的维度，而非二选一

这里需要纠正一个常见误解：把权限判定与沙箱当成两个并列、可以互相替代的免确认开关，即“要么弹窗问我，要么关进沙箱，二选一”，这个理解不成立，也正是不少产品缺陷的来源。判定与沙箱是两个独立的维度：

| | 判定 | 沙箱 |
|---|---|---|
| 回答什么问题 | 这个动作允不允许发生 | 动作发生时能碰到什么 |
| 机制性质 | 逐动作、决策那一刻的一次检查 | 执行全程持续的边界 |
| 强项 | 灵活、细粒度、能表达意图 | 确定、不依赖判断质量、内核级 |
| 弱项 | 词法解析出错、审批疲劳、规则本身来自可写配置 | 粒度粗、覆盖不全 |

判定的弱项恰是沙箱的强项，反之亦然。二者的正确关系是叠加，而不是二选一：沙箱兜底，判定只管辖要越出边界的动作。一道免确认的授权应当由边界覆盖来支撑，而不是由判定来支撑：判定放行只是“这次不问了”，这次执行至少要被沙箱关住；判定放行而执行落在沙箱约束之外，等于没有任何约束。

还有更糟的形态：本该兜底的沙箱反过来成为免确认的理由，即“反正有沙箱，别问了”。此时沙箱非但没有兜底，还为判定背书。这一形态留到沙箱一篇展开。

## 小结

后续展开的攻击面，没有一个以模型为攻击对象，全部落在包裹模型的代码上：配置、判定、沙箱与框架本身。这一模式会在系列中反复出现，也是许多“用 AI 防 AI”方案没有说清的前提。

授权机制的正确形态在这里先不展开，留到最后一篇绕完攻击面与攻击路径之后回收全文时给出。

下一篇从两条结构性事实出发推导攻击面：每个攻击面在哪里、攻击者如何写入、现有关卡为什么拦不住。

## References

[1] Check Point Research — RCE and API Token Exfiltration Through Claude Code Project Files (CVE-2025-59536)：https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/

[2] NVD — CVE-2025-61260 (OpenAI Codex CLI ≤ 0.23.0)：https://nvd.nist.gov/vuln/detail/CVE-2025-61260

[3] BleepingComputer — Researchers escape OpenAI Codex sandbox to run commands on host (Heapjack / Overpatch)：https://www.bleepingcomputer.com/news/security/researchers-escape-openai-codex-sandbox-to-run-commands-on-host/

[4] Cato AI Labs — DuneSlide: Two Critical RCE Vulnerabilities (CVE-2026-50548 / 50549)：https://www.catonetworks.com/blog/duneslide-two-critical-rce-vulnerabilities/

[5] NVD — CVE-2026-12537 (Google Gemini CLI)：https://nvd.nist.gov/vuln/detail/CVE-2026-12537

[6] Embrace The Red — GitHub Copilot: Remote Code Execution via Prompt Injection (CVE-2025-53773)：https://embracethered.com/blog/posts/2025/github-copilot-remote-code-execution-via-prompt-injection/

[7] Simon Willison — The lethal trifecta for AI agents：https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/

[8] OpenAI Codex 文档（config、sandbox、approval policy、AGENTS.md）：https://developers.openai.com/codex/

[9] Claude Code 文档（settings、permissions、hooks）：https://code.claude.com/docs/

[10] GitHub — openai/codex 源码仓库（codex-rs Rust 工程）：https://github.com/openai/codex
