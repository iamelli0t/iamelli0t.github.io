---
title: "AI Agent 安全系列：2. AI Agent 攻击面推导"
date: 2026-10-12
tags: [ai-agent, attack-surface, threat-modeling]
author: "iamelli0t"
ShowToc: true
TocOpen: true
url: /zh/ai-agent-security/02/
---

2025 年 12 月，OWASP 发布 2026 版 Agentic Applications Top 10[1]，列出智能体应用的十类主要威胁，下面的推导以它为参照。

第 1 篇把 agent 运行时拆成六层与两个部件，并留下两条结构性事实：结构性事实 1 是所有外部内容在组装时汇成一条没有来源标记的平坦 token 流；结构性事实 2 是判定检查点只覆盖“模型 → 动作”这一段，内容进入与配置加载都不经过它。沿着这张结构图推导，得到的攻击面与威胁清单不同：它的意义在于可检验，任何一个新漏洞、新技术出现，都能定位它落在哪个攻击面上；定位不上，则暴露的是结构图的缺口，两种结果都推进认识。

推导按三个问题展开：agent 的行为由哪些状态决定，执行由哪些关卡拦截；这些状态与关卡推出哪几个攻击面，各落在架构图的什么位置；一个攻击面要变成一次实际攻击，中间还差什么。

## OWASP 2026 版 Agentic Applications Top 10

![OWASP Agentic Top 10 at a glance](/images/ai-agent-02-surfaces/owasp-glance.png)

图源：OWASP Top 10 for Agentic Applications（2026）[1]。十类如下：

1. **目标劫持（ASI01）**：利用模型无法可靠区分指令与内容的固有弱点，操纵 agent 的目标、任务选择与决策路径，影响覆盖后续多步行为而非单次回答；
2. **工具滥用与利用（ASI02）**：agent 在授权范围内以不安全或非预期的方式使用合法工具，如删除数据、过度调用付费接口、外传信息；涉及提权归 ASI03，形成代码执行的归 ASI05；
3. **身份与权限滥用（ASI03）**：操纵委托链、角色继承与 agent 上下文实现提权；根源是身份体系以人为中心，agent 没有独立受治理的身份，最小权限无法真正执行；
4. **智能体供应链（ASI04）**：模型、工具、插件、数据集、MCP 与 A2A 接口、注册表、更新通道等第三方组件被投毒或篡改；与传统软件供应链的差别在组件多为运行时动态装配；
5. **意外代码执行（ASI05）**：注入、工具滥用或不安全序列化把文本变成可执行行为，后果是宿主或容器接管、驻留与沙箱逃逸；代码常由 agent 实时生成，绕过基于静态规则的安全管控；
6. **记忆与上下文投毒（ASI06）**：对话历史、长期记忆、检索库被写入恶意或误导数据，污染此后的推理、规划与工具选择，跨会话传播；这一类投毒针对存储的上下文，当次输入的注入归 ASI01；
7. **不安全的智能体间通信（ASI07）**：多智能体系统的消息交换缺乏认证、完整性与语义校验，可被拦截、伪造与篡改，威胁横跨传输、路由、发现与语义各层；
8. **级联失败（ASI08）**：单一缺陷沿智能体网络传播放大成系统性故障；它描述扩散本身而非起点，起点按性质归 ASI04、ASI06 或 ASI07；
9. **人机信任利用（ASI09）**：利用拟人化信任、权威偏差与自动化偏差，让人不加验证地批准 agent 的输出与建议，审批链上的人成为被利用的一环；
10. **失控智能体（ASI10）**：恶意或被攻陷的 agent 偏离预期功能与授权范围，行为漂移且伪装合规；清单关注漂移开始后的行为完整性丧失，不是初始入侵。

这份清单完成了自己的任务：给做 agent 安全的人当参考，收录影响最大的十类威胁，公开攻击的主要形态都在其中。它的组织方式是威胁类型，不是 agent 内部结构，所以回答不了这样的问题：每一类威胁落在运行时的哪个位置、哪几类威胁共享同一个根因、为什么公开漏洞集中在其中几类而其余几乎为零；回答这些问题，需要的是从结构出发的推导。

## 推导方法：从架构图到攻击面

推导从第 1 篇的架构图出发：

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
    <text x="450" y="391" text-anchor="middle" font-size="12" opacity="0.75">reasoning · outside harness control</text>
    <rect x="250" y="438" width="400" height="64" rx="12" fill="rgba(247,223,168,0.35)" stroke="#c9a53f" stroke-opacity="0.9" stroke-width="1.6"/>
    <text x="450" y="465" text-anchor="middle" font-size="16.5" font-weight="600">L4 Permission Check</text>
    <text x="450" y="487" text-anchor="middle" font-size="12" opacity="0.8">allow / ask / deny</text>
    <rect x="250" y="534" width="400" height="64" rx="12" fill="rgba(127,127,127,0.09)" stroke="currentColor" stroke-opacity="0.55" stroke-width="1.6"/>
    <text x="450" y="561" text-anchor="middle" font-size="16.5" font-weight="600">L5 Tools</text>
    <text x="450" y="583" text-anchor="middle" font-size="12" opacity="0.75">read / write / exec / network</text>
    <rect x="250" y="650" width="220" height="64" rx="12" fill="rgba(88,178,128,0.14)" stroke="#58b280" stroke-width="1.6"/>
    <text x="360" y="677" text-anchor="middle" font-size="15" font-weight="600">L6 Persistent State</text>
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

一个 agent 运行时里，行为由五类状态决定，每一类都对应架构图上的一个确定位置：

| 状态 | 在架构图上的位置 | 被写中意味着 |
|---|---|---|
| 上下文内容 | L2 每一轮组装出的请求，模型据此决策 | 模型按攻击者的指令决策 |
| 判定规则 | L4 判定的输入，由配置面下发 | 攻击者把自己要执行的动作写成免确认 |
| 组件构成 | L5 注册的工具与 MCP server | agent 多出一条攻击者定义的数据通路 |
| 持久状态 | L6 的记忆、会话记录与凭证 | 影响延伸到之后的每一次会话 |
| 呈现信息 | L1 展示给用户、供审批的内容 | 用户看到的是攻击者构造的画面 |

五类状态有一条共同性质：只要不可信输入能写中其中一类，agent 的行为就被控制了。

执行由四道关卡拦截：

| 关卡 | 机制形态 | 失效方式 |
|---|---|---|
| 判定与审查 | L4 的逐动作检查，有确定性规则与模型自动审查两种形态 | 规则被词法绕过、被改写、被整段跳过；模型审查有信息盲区 |
| 沙箱 | 执行全程持续的边界 | 覆盖有缺口、边界可逃逸 |
| 框架与运行时自身代码 | 承载各层的实现：序列化、解析、进程间通信 | 自身实现缺陷可被直接利用，不经模型与判定 |
| 人 | 最后一道审批 | 审批疲劳下机械放行、被伪造的呈现欺骗 |

攻击面由两部分组成。第一部分是可写入的位置：上表中的每一类状态都有自己的到达路径，不可信输入沿这些路径写入。第二部分是可绕过的关卡：每道关卡都有自己的失效方式，判定可被绕过、沙箱可被击穿、框架代码可被直接利用，失效一旦成立，没有下一道防线再拦。

两部分要组合起来才构成实际攻击，单独任何一半都不成立。只写不绕，写进来的东西没有人替它执行；只绕不写，关卡放行的仍是正常动作，行为没有被控制。实际攻击几乎总是两步的组合：先写中某个状态改变行为，再从某个关卡的缺口过去。

三个公开案例各占一种组合：

1. 经典注入：内容写中上下文，同时判定对白名单内的动作免确认，被劫持的决策不经检查直接执行；
2. 配置即执行：组件构成被写中，事件钩子触发执行，全程不经模型与判定（结构性事实 2）；
3. Cursor 的 DuneSlide：注入操纵模型填写的参数，沙箱按被操纵的参数构建写入白名单，最终覆写沙箱执行器本身[2]。

推导的范围先划一条边界：攻击面只覆盖攻击者经不可信输入触达的失效。三类常见的失效因此排除在外。

- 幻觉与超出授权的自作主张，出在 agent 自身，背后没有攻击者。
- 资源耗尽，它可以是攻击的结果，但不是一条独立的路径。
- 用户本人直接注入的指令，用户是授权主体，自己给的指令不构成攻击。

有一种情况容易误判：用户把第三方内容转贴进对话，这些内容的来源不是用户，仍然按不可信内容处理。

## 七个攻击面

推导方法里的两张表各推出一部分攻击面，五类状态推出上下文、配置、持久状态、呈现四个可写入的攻击面。判定规则与组件构成都由配置文件承载，在这里合并成一个配置攻击面；四道关卡里，判定、沙箱、框架自身代码推出三个可绕过的攻击面。第四道关卡是人，攻击人的方式是写呈现与骗审批，这两种方式都落在人机接口攻击面上，人因此不单独构成攻击面。四个可写入的攻击面加三个可绕过的攻击面，就是七个攻击面。标到 Agent 结构图上，S1 至 S7 即正文的攻击面 1 至攻击面 7：

<svg viewBox="0 0 900 860" width="620" style="display:block;max-width:100%;height:auto;margin:1.2rem auto" role="img" aria-label="Seven attack surfaces mapped onto the agent architecture">
  <defs>
    <marker id="arr2" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor"/></marker>
  </defs>
  <rect x="200" y="110" width="500" height="680" rx="24" fill="rgba(127,127,127,0.05)" stroke="currentColor" stroke-opacity="0.6" stroke-width="1.8"/>
  <text x="700" y="98" text-anchor="end" fill="currentColor" font-size="14" font-weight="700" opacity="0.85">Agent</text>
  <rect x="380" y="28" width="140" height="48" rx="14" fill="rgba(127,127,127,0.10)" stroke="currentColor" stroke-opacity="0.7" stroke-width="1.8"/>
  <text x="450" y="58" text-anchor="middle" fill="currentColor" font-size="16" font-weight="600">User</text>
  <line x1="450" y1="76" x2="450" y2="150" stroke="currentColor" stroke-width="2" marker-end="url(#arr2)"/>
  <g fill="currentColor">
    <rect x="250" y="150" width="400" height="56" rx="12" fill="rgba(127,127,127,0.09)" stroke="currentColor" stroke-opacity="0.55" stroke-width="1.6"/>
    <text x="450" y="184" text-anchor="middle" font-size="15.5" font-weight="600">L1 UI</text>
    <rect x="250" y="238" width="400" height="56" rx="12" fill="rgba(127,127,127,0.09)" stroke="currentColor" stroke-opacity="0.55" stroke-width="1.6"/>
    <text x="450" y="272" text-anchor="middle" font-size="15.5" font-weight="600">L2 Orchestration</text>
    <rect x="250" y="326" width="400" height="56" rx="12" fill="rgba(127,127,127,0.09)" stroke="currentColor" stroke-opacity="0.55" stroke-width="1.6" stroke-dasharray="6 4"/>
    <text x="450" y="360" text-anchor="middle" font-size="15.5" font-weight="600">L3 Model</text>
    <rect x="250" y="414" width="400" height="56" rx="12" fill="rgba(247,223,168,0.35)" stroke="#c9a53f" stroke-opacity="0.9" stroke-width="1.6"/>
    <text x="450" y="448" text-anchor="middle" font-size="15.5" font-weight="600">L4 Permission Check</text>
    <rect x="250" y="502" width="400" height="56" rx="12" fill="rgba(127,127,127,0.09)" stroke="currentColor" stroke-opacity="0.55" stroke-width="1.6"/>
    <text x="450" y="536" text-anchor="middle" font-size="15.5" font-weight="600">L5 Tools</text>
    <rect x="250" y="612" width="220" height="56" rx="12" fill="rgba(88,178,128,0.14)" stroke="#58b280" stroke-width="1.6"/>
    <text x="360" y="646" text-anchor="middle" font-size="14" font-weight="600">L6 Persistent State</text>
    <rect x="500" y="705" width="150" height="60" rx="12" fill="rgba(150,115,220,0.18)" stroke="#9673a6" stroke-width="1.8" stroke-dasharray="6 4"/>
    <text x="575" y="741" text-anchor="middle" font-size="14.5" font-weight="600">Sandbox</text>
  </g>
  <g stroke="currentColor" stroke-width="2">
    <line x1="450" y1="206" x2="450" y2="238" marker-end="url(#arr2)"/>
    <line x1="450" y1="294" x2="450" y2="326" marker-end="url(#arr2)"/>
    <line x1="450" y1="382" x2="450" y2="414" marker-end="url(#arr2)"/>
    <line x1="450" y1="470" x2="450" y2="502" marker-end="url(#arr2)"/>
    <line x1="360" y1="558" x2="360" y2="612" marker-end="url(#arr2)"/>
    <line x1="565" y1="558" x2="565" y2="705" marker-end="url(#arr2)"/>
  </g>
  <text x="372" y="592" fill="currentColor" font-size="11" opacity="0.85">read / write</text>
  <text x="577" y="600" fill="currentColor" font-size="11" opacity="0.85">all exec</text>
  <rect x="40" y="250" width="120" height="310" rx="16" fill="rgba(100,150,220,0.08)" stroke="#6c8ebf" stroke-opacity="0.7" stroke-width="1.6"/>
  <g fill="currentColor" text-anchor="middle">
    <text x="100" y="286" font-size="10.5" font-weight="700">EXTERNAL</text>
    <text x="100" y="301" font-size="10.5" font-weight="700">ENVIRONMENT</text>
  </g>
  <g fill="currentColor">
    <rect x="52" y="316" width="96" height="50" rx="12" fill="rgba(100,150,220,0.16)" stroke="#6c8ebf" stroke-width="1.6"/>
    <text x="100" y="346" text-anchor="middle" font-size="13" font-weight="600">Content</text>
    <rect x="52" y="384" width="96" height="50" rx="12" fill="rgba(100,150,220,0.16)" stroke="#6c8ebf" stroke-width="1.6"/>
    <text x="100" y="414" text-anchor="middle" font-size="13" font-weight="600">Service</text>
    <rect x="52" y="452" width="96" height="50" rx="12" fill="rgba(100,150,220,0.16)" stroke="#6c8ebf" stroke-width="1.6"/>
    <text x="100" y="482" text-anchor="middle" font-size="13" font-weight="600">File</text>
  </g>
  <path d="M160,409 H185 V266 H244" fill="none" stroke="#6c8ebf" stroke-width="2.5" marker-end="url(#arr2)"/>
  <text x="196" y="352" fill="#6c8ebf" font-size="10.5" font-weight="600">channels</text>
  <rect x="740" y="250" width="120" height="310" rx="16" fill="rgba(255,230,204,0.10)" stroke="#d79b00" stroke-opacity="0.8" stroke-width="1.6"/>
  <text x="800" y="286" text-anchor="middle" fill="currentColor" font-size="11" font-weight="700">CONFIG</text>
  <g fill="currentColor">
    <rect x="752" y="316" width="96" height="44" rx="12" fill="rgba(255,230,204,0.25)" stroke="#d79b00" stroke-width="1.6"/>
    <text x="800" y="343" text-anchor="middle" font-size="12" font-weight="600">Hooks</text>
    <rect x="752" y="378" width="96" height="44" rx="12" fill="rgba(255,230,204,0.25)" stroke="#d79b00" stroke-width="1.6"/>
    <text x="800" y="405" text-anchor="middle" font-size="12" font-weight="600">Policies</text>
    <rect x="752" y="440" width="96" height="44" rx="12" fill="rgba(255,230,204,0.25)" stroke="#d79b00" stroke-width="1.6"/>
    <text x="800" y="467" text-anchor="middle" font-size="12" font-weight="600">Components</text>
    <rect x="752" y="502" width="96" height="44" rx="12" fill="rgba(255,230,204,0.25)" stroke="#d79b00" stroke-width="1.6"/>
    <text x="800" y="529" text-anchor="middle" font-size="12" font-weight="600">Params</text>
  </g>
  <g stroke="#d79b00" stroke-width="2" fill="none">
    <path d="M740,442 H656" marker-end="url(#arr2)"/>
    <path d="M740,530 H656" marker-end="url(#arr2)"/>
    <path d="M800,560 V735 H656" marker-end="url(#arr2)"/>
  </g>
  <g fill="#d43c3c">
    <rect x="662" y="165" width="44" height="26" rx="8" fill="#d43c3c" fill-opacity="0.85"/>
    <rect x="428" y="297" width="44" height="26" rx="8" fill="#d43c3c" fill-opacity="0.85"/>
    <rect x="200" y="429" width="44" height="26" rx="8" fill="#d43c3c" fill-opacity="0.85"/>
    <rect x="448" y="722" width="44" height="26" rx="8" fill="#d43c3c" fill-opacity="0.85"/>
    <rect x="482" y="627" width="44" height="26" rx="8" fill="#d43c3c" fill-opacity="0.85"/>
    <rect x="778" y="237" width="44" height="26" rx="8" fill="#d43c3c" fill-opacity="0.85"/>
    <rect x="178" y="700" width="44" height="26" rx="8" fill="#d43c3c" fill-opacity="0.85"/>
  </g>
  <g fill="#ffffff" text-anchor="middle" font-size="12.5" font-weight="700">
    <text x="684" y="183">S6</text>
    <text x="450" y="315">S1</text>
    <text x="222" y="447">S3</text>
    <text x="470" y="740">S4</text>
    <text x="504" y="645">S5</text>
    <text x="800" y="255">S2</text>
    <text x="200" y="718">S7</text>
  </g>
  <g fill="currentColor" font-size="10.5" opacity="0.8">
    <text x="712" y="183">UI &amp; approval</text>
    <text x="420" y="315" text-anchor="end">context assembly</text>
    <text x="194" y="447" text-anchor="end">permission check</text>
    <text x="440" y="740" text-anchor="end">sandbox</text>
    <text x="504" y="672" text-anchor="middle">persistent state</text>
    <text x="170" y="718" text-anchor="end">framework &amp; runtime</text>
  </g>
  <text x="450" y="826" text-anchor="middle" fill="currentColor" font-size="11" opacity="0.8">S1–S7: the seven attack surfaces derived in this article</text>
</svg>

**攻击面 1：上下文注入（S1，L2→L3，可写入）。** 任务输入、工具定义与返回、读入的文件与网页、跨会话存续的记忆，这些内容在 L2 组装时汇成同一条无来源标记的 token 流（结构性事实 1），写入这个攻击面的直接对象是模型的决策。注入载体覆盖最普通的日常内容：网页、issue 评论、工具描述、仓库里的注释，攻击者不需要任何特殊入口。注入本身是投递而非漏洞：模型被劫持后能走多远，由攻击面 3 与攻击面 4 决定，这一关系决定了注入类攻击的完整形态总是一条链。

**攻击面 2：配置（S2，CFG，可写入）。** 配置文件承载判定规则、组件注册、事件钩子与运行参数四类内容，写入配置等于不经模型、不经判定地更改机器。到达路径落在第 1 篇所述信任梯度的低端：项目目录里的配置随仓库克隆一并进入，市场自动安装由 agent 自己完成，两者都是攻击者可以安排的写入方式。从公开 CVE 的数量看，这是目前产出最多的攻击面。

**攻击面 3：判定绕过（S3，L4，可绕过）。** 判定机制自身有四类失效方式。

- 词法绕过：命令文本到效果分类的映射对不上语义，判定器读到的与实际执行的是两回事。
- 规则被改写：经攻击面 2 的通道写入白名单，或诱导用户批准范围过宽的规则。
- 路径被跳过：事件钩子的执行不经过判定。
- 审查盲区：模型审查看不到密文与执行语义中携带的恶意意图。

**攻击面 4：沙箱（S4，执行边界，可绕过）。** 沙箱的失效分四类。

- 覆盖缺口：profile 通常只约束写与执行，读操作不设限，凭证处于可读状态。
- 越界执行：用户批准越界动作后，这一次执行退出沙箱、在宿主机上直接运行，整条边界随之失效。
- 边界逃逸：沙箱内的代码突破边界本身，重新拿到宿主机的完整权限。
- 构建依赖模型参数：沙箱按模型填写的参数构建白名单，参数被注入操纵时边界随之失守，DuneSlide 已经把这条路径完整走了一遍[2]。

**攻击面 5：持久状态（S5，L6，可写入）。** 记忆与会话记录被写入之后，本次会话的出口成为后续会话的入口，单会话攻击由此变成持续存在，驻留与远控都落在攻击面 5 上。凭证的暴露面由读路径与通信出口两部分构成，两者同时可达，变现才成立。从公开记录看，这是事件与研究落差最大的一个攻击面。

**攻击面 6：人机接口（S6，L1，可写入）。** 四道关卡里最后一道是人，攻击人靠控制人看到的内容，而内容全部经 L1 呈现，这个攻击面因此落在 L1。呈现是可写入的目标，从数据到屏幕的显示过程独立于模型决策：AutoGPT 的 CVE-2023-37275 中，恶意网页携带的 ANSI 转义序列不经过模型，直接被终端渲染成伪造的命令输出，被欺骗的是查看屏幕的人[3]。审批环节同样可以被欺骗，具体形式包括审批疲劳下的机械放行、伪装成正常流程的同意请求，以及不显示真实执行内容的界面。

**攻击面 7：框架与运行时（S7，harness 自身代码，可绕过）。** 这个攻击面指向 harness 自身代码的实现缺陷，范围包括 L2 与 L5 的序列化、checkpoint、解析器、本地服务，以及 V8、Electron 一类原生运行时的自身漏洞，失效形态有状态投毒、解析混淆与可信文件被覆写。由于攻击对象就是包裹模型的代码本身，这类缺陷不需要经过模型与判定，Langflow 的未认证远程代码执行（CVE-2025-3248）是典型：浏览器一次访问就触发。

七个攻击面合起来看，排布有一条清晰的逻辑：攻击面 1 与攻击面 2 改变行为，前者操纵模型决策，后者更改机器；攻击面 3 与攻击面 4 绕过关卡，对应判定与沙箱；攻击面 5 让攻击跨会话持续存在；攻击面 6 与攻击面 7 针对最后的兜底环节，即人与代码。没有一个攻击面以模型为攻击对象。第 1 篇末尾还只是观察，推导完成之后成了结论：所有关卡都落在 harness 上，模型不在关卡序列里，模型被攻破只提高攻击面 1 的写入成功率，不构成独立的攻击面。

| # | 攻击面 | 架构位置 | 性质 | 公开案例（节选） |
|---|---|---|---|---|
| 1 | 上下文注入 | L2→L3 | 可写入 | EchoLeak（CVE-2025-32711）|
| 2 | 配置 | CFG | 可写入 | Claude Code 59536 / 21852、Codex 61260、Copilot 53773 |
| 3 | 判定绕过 | L4 | 可绕过 | Browser Use 47241 |
| 4 | 沙箱 | 执行边界 | 可绕过 | DuneSlide、ChatMate（CVE-2026-32193） |
| 5 | 持久状态 | L6 | 可写入 | 记忆投毒事件 15 起以上 |
| 6 | 人机接口 | L1 | 可写入 | AutoGPT 37275 |
| 7 | 框架与运行时 | harness 自身代码 | 可绕过 | Langflow 3248、LangGrinch 68664 |

## 从攻击面到攻击路径

攻击面给出的是可以写入的位置，位置要变成实际危害，还差一条从入口走到出口的路线，这条路线就是攻击路径。完整的攻击路径分为五段，每一段的取值都在固定的选项集合之内：

| 路径段 | 选项集合 |
|---|---|
| 通道（怎么进来） | 内容 / 服务 / 文件 / 内部（跨会话记忆、子 agent 消息） |
| 写入（落在哪个攻击面） | 攻击面 1 上下文 / 攻击面 2 配置 / 攻击面 5 状态 / 攻击面 6 呈现 |
| 绕过（哪道关卡放行） | 攻击面 3 判定 / 攻击面 4 沙箱 / 攻击面 7 框架代码 / 人 |
| 效果 | 读 / 写 / 执行 / 通信 |
| 出口 | 变现 / 驻留 / 扩张 |

<svg viewBox="0 0 1080 420" width="680" style="display:block;max-width:100%;height:auto;margin:1.2rem auto" role="img" aria-label="The five-segment path formula with the cross-session feedback loop">
  <defs>
    <marker id="arrp" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor"/></marker>
    <marker id="arrr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="#d43c3c"/></marker>
  </defs>
  <g fill="currentColor" font-size="12" font-weight="700">
    <text x="115" y="76" text-anchor="middle">1</text>
    <text x="320" y="76" text-anchor="middle">2</text>
    <text x="525" y="76" text-anchor="middle">3</text>
    <text x="730" y="76" text-anchor="middle">4</text>
    <text x="935" y="76" text-anchor="middle">5</text>
  </g>
  <g fill="currentColor">
    <rect x="30" y="100" width="170" height="150" rx="14" fill="rgba(127,127,127,0.08)" stroke="currentColor" stroke-opacity="0.7" stroke-width="1.8"/>
    <text x="115" y="128" text-anchor="middle" font-size="15" font-weight="700">CHANNEL</text>
    <rect x="235" y="100" width="170" height="150" rx="14" fill="rgba(127,127,127,0.08)" stroke="currentColor" stroke-opacity="0.7" stroke-width="1.8"/>
    <text x="320" y="128" text-anchor="middle" font-size="15" font-weight="700">WRITE</text>
    <rect x="440" y="100" width="170" height="150" rx="14" fill="rgba(127,127,127,0.08)" stroke="currentColor" stroke-opacity="0.7" stroke-width="1.8"/>
    <text x="525" y="128" text-anchor="middle" font-size="15" font-weight="700">BYPASS</text>
    <rect x="645" y="100" width="170" height="150" rx="14" fill="rgba(127,127,127,0.08)" stroke="currentColor" stroke-opacity="0.7" stroke-width="1.8"/>
    <text x="730" y="128" text-anchor="middle" font-size="15" font-weight="700">EFFECT</text>
    <rect x="850" y="100" width="170" height="150" rx="14" fill="rgba(127,127,127,0.08)" stroke="currentColor" stroke-opacity="0.7" stroke-width="1.8"/>
    <text x="935" y="128" text-anchor="middle" font-size="15" font-weight="700">EXIT</text>
  </g>
  <g fill="currentColor" text-anchor="middle" font-size="11.5" opacity="0.85">
    <text x="115" y="162">content</text>
    <text x="115" y="186">service · file</text>
    <text x="115" y="210">memory · sub-agent</text>
    <text x="320" y="162">S1 context</text>
    <text x="320" y="186">S2 config · S5 state</text>
    <text x="320" y="210">S6 UI</text>
    <text x="525" y="158">S3 permission check</text>
    <text x="525" y="180">S4 sandbox</text>
    <text x="525" y="202">S7 framework</text>
    <text x="525" y="224">human approval</text>
    <text x="730" y="162">read · write</text>
    <text x="730" y="186">exec · network</text>
    <text x="935" y="162">monetize</text>
    <text x="935" y="186">persist · spread</text>
  </g>
  <g stroke="currentColor" stroke-width="2" fill="none">
    <path d="M200,175 H229" marker-end="url(#arrp)"/>
    <path d="M405,175 H434" marker-end="url(#arrp)"/>
    <path d="M610,175 H639" marker-end="url(#arrp)"/>
    <path d="M815,175 H844" marker-end="url(#arrp)"/>
  </g>
  <path d="M935,250 V330 H115 V254" fill="none" stroke="#d43c3c" stroke-width="2" stroke-dasharray="6 4" marker-end="url(#arrr)"/>
  <text x="525" y="322" text-anchor="middle" fill="#d43c3c" font-size="11.5" font-weight="600">persist: written state becomes the next session's channel</text>
  <text x="540" y="395" text-anchor="middle" fill="currentColor" font-size="11" opacity="0.8">one complete path = one option per segment; real attacks compose multiple typical paths</text>
</svg>

一次完整的攻击路径，就是把五个段各填一个值。用配置即执行这条链走一遍：通道是文件，恶意配置随仓库克隆进入；写入落在攻击面 2 配置；绕过利用的是事件钩子不经判定的缺口；效果是执行；出口是驻留，写下的钩子在之后的每次会话里继续生效。

七条典型路径的来源就在这张表里。写入段的选项是四个可写入的攻击面；绕过段的选项是四道关卡，判定、沙箱、框架代码对应攻击面 3、4、7，第四道关卡是人，人不是攻击面，骗过人的写入落在攻击面 6。

生成办法是让这七个攻击面轮流当答案，不做选项的穷举组合（那会有几百种无意义的组合）：轮到哪一个，它就填进写入段或绕过段，通道、效果、出口三段填它最典型的取值，五段连起来就是一条路径。攻击面 1 当答案是：恶意内容从网页、issue 评论这类入口进来，写进上下文，劫持模型决策后专挑免确认的动作执行，连起来就是上下文注入链。七个攻击面各当一次答案，得到七条典型路径，表格每行只写固定填入的攻击面与标志性后果：

| 典型路径 | 攻击面 | 路径形态 |
|---|---|---|
| 上下文注入链 | 攻击面 1 | 把恶意内容写进上下文，劫持模型决策后专挑免确认动作执行 |
| 配置即执行链 | 攻击面 2 | 把规则与钩子写进配置，触发执行不经模型与判定 |
| 判定绕过链 | 攻击面 3 | 构造特制输入让判定误判，读取敏感文件或执行命令 |
| 边界击穿链 | 攻击面 4 | 操纵沙箱构建参数或利用解析间隙，覆写执行器或逃出边界 |
| 状态投毒链 | 攻击面 5 | 把恶意数据写进记忆与会话记录，成为后续会话的入口 |
| 人机欺骗链 | 攻击面 6 | 把伪造的呈现写上屏幕，骗得批准后凭证随执行出去 |
| 框架接管链 | 攻击面 7 | 直接利用框架自身代码缺陷，不经模型与判定 |

七条链并不各自独立，判定绕过链就是一个例子：要让判定面对特制输入，得先把内容送进来，写入一段填的是上下文注入的成果。真实攻击更常见的是几条链串在一起，Cursor 的 CurXecute 零点击链就是四个环节的复合链：注入完成投递，被劫持的模型自动执行白名单内的动作，随后抓取环境中的凭证，最后以反弹 shell 驻留。四个环节单独拿出来，每一个都有各自的公开分析；真正构成威胁的，是把它们串起来的完整链。因此典型路径是可供复用的标准件，而不是封闭的分类：单条典型路径描述一种走法，真实攻击按需组合。

出口一段还有一层含义。驻留类出口写下的记忆、钩子、配置与计划任务会成为下一次会话的输入，图中红色虚线画的正是这条回路：本会话的出口接到下一次会话的通道，一次性攻击由此变成持续存在。会话之内另有小循环，工具结果拼回上下文供下一轮推理使用，注入攻击依靠它在多步里逐步放大。一个循环在会话之内，一个循环横跨会话，两者同时存在，是 agent 攻击难以防御的结构性原因。

第 3 至第 9 篇按上表的顺序逐条展开这七条路径，每条配公开案例。

## 小结

至此，七个攻击面推导完成。推导同时给出贯穿全系列的结论：攻击面全部落在 harness 上，没有一个以模型为攻击对象，模型被写入只是攻击面 1 的成功率问题，不是独立的攻击目标。从攻击面到攻击路径，中间是五段结构（通道、写入、绕过、效果、出口），一条路径就是把五个段各填一个值，七个攻击面各生成一条典型路径，真实攻击是几条链的组合；这套结构是后面每篇分析路径共用的基础。

下一篇进入第一个攻击面：上下文注入。各种内容怎么汇成一条流、写进来能控制什么、为什么输入侧的每一个过滤方案都堵不住它。

## References

[2] Cato AI Labs — DuneSlide: Two Critical RCE Vulnerabilities (CVE-2026-50548 / 50549)：https://www.catonetworks.com/blog/duneslide-two-critical-rce-vulnerabilities/

[3] NVD — CVE-2023-37275 (AutoGPT)：https://nvd.nist.gov/vuln/detail/CVE-2023-37275

[1] OWASP — Top 10 for Agentic Applications (2026)：https://genai.owasp.org/
