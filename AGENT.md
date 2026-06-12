# DMS模块智能体指令

## 作用域声明

```yaml
适用范围:
  仓库: ability_dmsfwk_my
  子系统: 分布式任务调度子系统
  模块: DMS (Distributed Mission Scheduler Framework)
  目标智能体: 通用编码智能体 (Claude Code, Codex, Copilot, Cursor等)
```

---

## 约束声明

> **重要**: 章节3(接续规则说明)和章节4.1.6(SINK端包匹配规则)为接续业务整体约束，优先级最高。大模型读取知识库时应优先获取这两个章节内容。

---

## 代码结构

```
ability_dmsfwk_my/                 # 分布式任务调度框架
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
| 新协同业务 | services/dtbcollabmgr/src/ | ability_connection_manager.cpp, av_trans_*.cpp |
| IPC通信 | services/dtbschedmgr/src/ | distributed_sched_stub.cpp, distributed_sched_proxy.cpp |
| 事件监听 | services/dtbschedmgr/src/ | app_state_observer.cpp, common_event_listener.cpp |
| Bundle管理 | services/dtbschedmgr/src/ | bundle_manager_internal.cpp (隐含) |
| 权限校验 | services/dtbschedmgr/src/ | distributed_sched_permission.cpp |
| 分布式Intent | services/dtbschedmgr/src/distributedIntent/ | distributed_intent_service.cpp |
| 测试代码 | services/dtbschedmgr/test/unittest/ | *_test.cpp |
| [废弃] dtbabilitymgr | services/dtbabilitymgr/ | 仅维护，不再扩展新功能 |

---

## 目录索引

```yaml
知识库结构:
  章节1_基础概念与术语:
    文件: reference/01_terminology.md
    关键字: 基础概念/术语定义/模块别名/账号概念/设备角色/SRC端/SINK端
    内容:
      - 1.1 模块别名映射
      - 1.2 账号概念(系统账号OsAccount/分布式账号OhosAccount)
      - 1.3 设备角色(SRC端/源设备/SINK端/目标设备)

  章节2_模块依赖与外部接口:
    文件: reference/02_dependencies.md
    关键字: 依赖关系/外部接口/AMS/软总线/BMS/设备管理/权限管理/KV存储
    内容:
      - 2.1 AMS模块(Ability管理服务)
      - 2.2 账号模块(系统账号/分布式账号)
      - 2.3 软总线模块(SoftBus)
      - 2.4 设备管理模块(DM)
      - 2.5 Bundle管理模块(BMS)
      - 2.6 分布式数据模块(KV存储)
      - 2.7 AccessToken模块(权限管理)

  章节3_接续规则说明:
    文件: reference/03_continue_rules.md
    关键字: 接续规则/接续约束/三元组/bundleName/continueType/abilityName/匹配规则/前置条件/可接续判定
    说明: 接续业务整体约束，优先级最高
    内容:
      - 3.1 应用标识(三元组/默认值规则/辅助标识)
      - 3.2 接续规则(前置条件/规则矩阵/规则总结)
      - 3.3 规则判定表

  章节4_接续业务流程:
    主文件: reference/04_continue_flow.md
    关键字: 接续流程/广播阶段/接续阶段/MMI事件/广播触发/事件监听/事件冻结
    内容:
      - 4.1 阶段一_广播阶段(SRC发送/SINK接收)
      - 4.1.1 广播触发条件(任务状态变化/MMI事件)
      - 4.1.2 MMI事件监听流程(初始化/添加监听/移除监听)
      - 4.1.3 MMI事件处理链路(捕获/投递/处理/触发广播)
      - 4.1.4 MMI事件冻结机制(防止广播风暴)
      - 4.1.5 Bundle管理交互(广播压缩/应用匹配验证)
      - 4.1.6 SINK端包匹配(接续业务整体约束，详见reference/04_01_06_sink_bundle_matching.md)
      - 4.2 阶段二_接续阶段(SRC推送/SINK拉取)
      - 4.2.1 Bundle管理交互(权限校验/Bundle验证)
    子文件:
      - reference/04_01_06_sink_bundle_matching.md:
          关键字: 包名匹配/SINK端匹配/AppIdentifierList/continueBundleName/普通场景/引导安装/推荐安装开关/接续约束
          说明: 章节4.1.6 SINK端包匹配规则，接续业务整体约束
          内容:
            - 4.1.6.1 概述(场景分类/关键概念)
            - 4.1.6.2 普通场景包名匹配规则
            - 4.1.6.3 引导安装场景包名匹配规则
            - 推荐安装开关校验规则

  章节5_IPC通信架构:
    文件: reference/05_ipc_architecture.md
    关键字: IPC通信/Stub/Proxy/服务端/客户端/角色映射/分布式调度
    内容:
      - 5.1 核心原则(Stub服务端/Proxy客户端)
      - 5.2 服务端列表(DistributedSchedStub等)
      - 5.3 客户端列表(DistributedSchedProxy等)
      - 5.4 场景角色对照(本端/远端角色映射)

  章节6_事件监听机制:
    文件: reference/06_event_listener.md
    关键字: 事件监听/获焦/失焦/前台/后台/进程死亡/生命周期/DmsContinueConditionMgr
    内容:
      - 6.1 任务级别事件监听(获焦/失焦/后台/前台)
      - 6.2 应用级别事件监听(前台切换/进程死亡)
      - 6.3 事件处理管理器(DmsContinueConditionMgr)
      - 6.4 协作场景生命周期监听

  章节7_Bundle管理交互:
    文件: reference/07_bundle_interaction.md
    关键字: Bundle交互/BMS接口/Bundle查询/Ability匹配/跨应用接续/权限验证/接续类型ID
    内容:
      - 7.1 概述(BundleManagerInternal与BMS交互)
      - 7.2 功能分类(Bundle查询/Ability匹配/跨应用接续/权限验证)
      - 7.3 接续流程中的使用(广播阶段/接续阶段)
      - 7.4 免安装相关
      - 7.5 调用位置索引
```

---

## 查询指引

```yaml
场景关键字映射:
  接续业务判断:
    必读: 章节3 + 章节4.1.6
    关键字: 接续规则/接续约束/三元组/包名匹配/可接续判定

  接续流程分析:
    推荐: 章节4 + 章节3 + 章节4.1.6
    关键字: 接续流程/广播阶段/接续阶段/MMI事件

  Bundle管理:
    推荐: 章节7 + 章节3
    关键字: Bundle交互/BMS接口/跨应用接续

  IPC通信:
    推荐: 章节5
    关键字: IPC通信/Stub/Proxy

  事件监听:
    推荐: 章节6
    关键字: 事件监听/获焦/失焦/生命周期

  基础概念:
    推荐: 章节1 + 章节2
    关键字: 基础概念/术语/依赖关系
```

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
- **不要**绕过章节3和章节4.1.6定义的接续规则
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
| services/dtbschedmgr/src/distributed_sched_continuation.cpp | 接续核心 | 接续流程核心，修改需遵循章节3约束 |

---

## 验证要求

### 构建命令

```bash
# 从 OpenHarmony 源码根目录执行（非本项目子目录）
./build.sh --product-name <product> --build-target dmsfwk --ccache

# 示例：
# ./build.sh --product-name rk3568 --build-target dmsfwk --ccache
```

### 测试命令

```bash
# TODO: 补充实际测试命令
# 单元测试位置: services/dtbschedmgr/test/unittest/
```

### 完成定义

任务完成需满足:
1. 构建通过（无编译错误）
2. 相关单元测试通过
3. 说明修改的影响范围和涉及的模块
4. 确认是否涉及高风险边界

### 无法验证时的处理

若无法执行构建或测试:
1. 明确说明验证未执行的原因
2. 手动审查修改的代码逻辑
3. 列出潜在风险点供人工确认

---

## 常见失败模式

| 模式 | 描述 | 防止方法 |
| --- | --- | --- |
| 绕过接续规则 | 未遵循章节3/4.1.6的接续约束 | 修改接续代码前必读章节3和4.1.6 |
| IPC协议不兼容 | 修改消息格式导致跨版本不兼容 | IPC修改需协议评审 |
| 权限校验遗漏 | 新增功能未添加必要权限校验 | 参考 distributed_sched_permission.cpp |
| 知识库未读取 | 未读取相关章节即修改代码 | 遵循编辑前置条件 |
| 修改废弃模块 | 在 dtbabilitymgr 新增功能 | 该目录已废弃，新功能应放入 dtbcollabmgr |