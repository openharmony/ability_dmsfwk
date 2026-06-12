# DMS模块仓库指引

## 作用域声明

```yaml
适用范围:
  仓库: ability_dmsfwk
  子系统: 分布式任务调度子系统
  模块: DMS (Distributed Mission Scheduler Framework)
  目标智能体: 通用编码智能体 (Claude Code, Codex, Copilot, Cursor等)
```

---

## 约束声明

> **重要**: [03_continue_rules.md](reference/03_continue_rules.md) 和 [04_01_06_sink_bundle_matching.md](reference/04_01_06_sink_bundle_matching.md) 为接续业务整体约束，优先级最高。

---

## 代码结构

```
ability_dmsfwk/                 # 分布式任务调度框架
├── services/                      # 服务实现
│   ├── dtbschedmgr/               # 接续业务（核心）
│   │   ├── src/                   # 源代码
│   │   ├── include/               # 头文件
│   │   └── test/unittest/         # 单元测试
│   ├── dtbcollabmgr/              # 新协同业务（核心）
│   │   ├── src/                   # 源代码
│   │   ├── include/               # 头文件
│   │   └── test/unittest/         # 单元测试
│   └── dtbabilitymgr/             # [已废弃] 分布式能力管理服务
│       ├── src/                   # 源代码（仅维护，不再扩展）
│       └── test/unittest/         # 单元测试
├── frameworks/                    # 框架层
│   └── native/distributed_extension/  # 分布式扩展框架
├── interfaces/                    # 接口定义
│   ├── innerkits/                 # 内部Kit接口
│   └── taihe/                     # Taihe接口
├── common/                        # 公共代码
├── reference/                     # 知识库文档
└── docs/                          # 其他文档
```

### 常用修改路径映射

| 任务类型 | 主要路径 | 关键文件 |
| --- | --- | --- |
| 接续业务 | services/dtbschedmgr/src/ | distributed_sched_continuation.cpp, dsched_continue_*.cpp |
| 协同业务 | services/dtbcollabmgr/src/ | ability_connection_manager.cpp, av_trans_*.cpp |
| IPC通信 | services/dtbschedmgr/src/ | distributed_sched_stub.cpp, distributed_sched_proxy.cpp |
| Bundle管理 | services/dtbschedmgr/src/ | bundle_manager_internal.cpp |
| 权限校验 | services/dtbschedmgr/src/ | distributed_sched_permission.cpp |

---

## 知识索引

| 场景 | 先读                                                     |
| --- |--------------------------------------------------------|
| 基础概念/术语定义/模块别名/账号概念/设备角色/SRC端/SINK端 | reference/01_terminology.md **[重要概念]**                 |
| 依赖关系/外部接口/AMS/软总线/BMS/设备管理/权限管理/KV存储 | reference/02_dependencies.md                           |
| 接续规则/接续约束/三元组/bundleName/continueType/abilityName/匹配规则/前置条件/可接续判定 | reference/03_continue_rules.md **[优先级最高]**             |
| 接续流程/广播阶段/接续阶段/MMI事件/广播触发/事件监听/事件冻结 | reference/04_continue_flow.md                          |
| 包名匹配/SINK端匹配/AppIdentifierList/continueBundleName/普通场景/引导安装/推荐安装开关 | reference/04_01_06_sink_bundle_matching.md **[优先级最高]** |
| IPC通信/Stub/Proxy/服务端/客户端/角色映射/分布式调度 | reference/05_ipc_architecture.md                       |
| 事件监听/获焦/失焦/前台/后台/进程死亡/生命周期/DmsContinueConditionMgr | reference/06_event_listener.md                         |
| Bundle交互/BMS接口/Bundle查询/Ability匹配/跨应用接续/权限验证/接续类型ID | reference/07_bundle_interaction.md                     |

---

## 编辑前置条件

在修改代码前，智能体**必须**:
1. 声明任务类型（接续业务/IPC通信/事件监听/Bundle管理/权限校验等）
2. 列出已阅读的知识库章节
3. 说明发现的约束条件
4. 确认修改是否涉及高风险边界

---

## 约束与边界

### 禁止事项

- **不要**修改分布式接续的公开API签名（需兼容性评审）
- **不要**绕过 [03_continue_rules.md](reference/03_continue_rules.md) 和 [04_01_06_sink_bundle_matching.md](reference/04_01_06_sink_bundle_matching.md) 定义的接续规则
- **不要**修改IPC协议格式或消息ID（需协议兼容性评审）
- **不要**删除或绕过权限校验逻辑（需安全评审）
- **不要**在 dtbabilitymgr 目录新增功能（已废弃，仅维护）

### 需确认后修改

以下修改需在实施前向用户确认:
- 修改 IPC 协议格式或新增消息ID
- 修改权限校验逻辑或新增权限要求
- 修改跨设备通信行为
- 修改接续规则判定逻辑
- 新增或删除公开API接口

### 高风险文件

| 文件路径 | 风险类型 | 说明 |
| --- | --- | --- |
| services/dtbschedmgr/src/distributed_sched_stub.cpp | IPC协议 | 处理远端请求，修改影响跨设备通信 |
| services/dtbschedmgr/src/distributed_sched_proxy.cpp | IPC协议 | 发送远端请求，修改影响跨设备通信 |
| services/dtbschedmgr/src/distributed_sched_permission.cpp | 权限校验 | 权限逻辑修改需安全评审 |
| services/dtbschedmgr/src/distributed_sched_continuation.cpp | 接续核心 | 接续流程核心，修改需遵循 [03_continue_rules.md](reference/03_continue_rules.md) 约束 |
| services/dtbschedmgr/src/mission/notification/dms_continue_recommend_info.cpp | 接续推荐 | 接续推荐相关，修改需遵循接续规则 |

---

## 验证要求

### 构建命令

```bash
# 从 OpenHarmony 源码根目录执行（非本项目子目录）
./build.sh --product-name <product> --build-target dmsfwk --ccache

# 示例：
# ./build.sh --product-name rk3568 --build-target dmsfwk --ccache
```

### 测试用例编译命令

```bash
# 从 OpenHarmony 源码根目录执行（非本项目子目录）
./build.sh --product-name <product> --build-target dmsfwk_test --ccache

# 示例：
# ./build.sh --product-name rk3568 --build-target dmsfwk_test --ccache
```

### 单元测试目录

| 业务 | 单测目录 |
| --- | --- |
| 接续业务 | services/dtbschedmgr/test/unittest/continue/, distributed_sched_continuation_test.cpp |
| 协同业务 | services/dtbschedmgr/test/unittest/collab/, services/dtbcollabmgr/test/unittest/ |

### 完成定义

任务完成需满足:
1. 构建通过（无编译错误）
2. 所有单元测试通过。**重要**:单独修改接续或者协同功能，也需要全部单元测试都通过
3. 双设备组网后xts验证通过

### 无法验证时的处理

若无法执行构建或测试:
1. 明确说明验证未执行的原因
2. 手动审查修改的代码逻辑
3. 列出潜在风险点供人工确认
4. 失败或为执行测试用例人工复测

---

## 常见失败模式

| 模式 | 描述 | 防止方法 |
| --- | --- | --- |
| 绕过接续规则 | 未遵循 [03_continue_rules.md](reference/03_continue_rules.md) 和 [04_01_06_sink_bundle_matching.md](reference/04_01_06_sink_bundle_matching.md) 的接续约束 | 修改接续代码前必读这两个文件 |
| IPC协议不兼容 | 修改消息格式导致跨版本不兼容 | IPC修改需协议评审 |
| 权限校验遗漏 | 新增功能未添加必要权限校验 | 参考 distributed_sched_permission.cpp |
| 知识库未读取 | 未读取相关章节即修改代码 | 遵循编辑前置条件 |
| 修改废弃模块 | 在 dtbabilitymgr 新增功能 | 该目录已废弃，新功能应放入 dtbcollabmgr 或 dtbschedmgr |
