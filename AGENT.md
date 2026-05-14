# DMS模块知识库

## 目录索引

```yaml
知识库结构:
  章节1_基础概念与术语:
    文件: reference/01_terminology.md
    内容:
      - 1.1 模块别名映射
      - 1.2 账号概念(系统账号OsAccount/分布式账号OhosAccount)
      - 1.3 设备角色(SRC端/源设备/SINK端/目标设备)

  章节2_模块依赖与外部接口:
    文件: reference/02_dependencies.md
    内容:
      - 2.1 AMS模块(Ability管理服务)
      - 2.2 账号模块(系统账号/分布式账号)
      - 2.3 软总线模块(SoftBus)
      - 2.4 设备管理模块(DM)
      - 2.5 Bundle管理模块(BMS)
      - 2.6 分布式数据模块(KV存储)
      - 2.7 AccessToken模块(权限管理)

  章节3_接续业务流程:
    文件: reference/03_continue_flow.md
    内容:
      - 3.1 阶段一_广播阶段(SRC发送/SINK接收)
      - 3.1.1 广播触发条件(任务状态变化/MMI事件)
      - 3.1.2 MMI事件监听流程(初始化/添加监听/移除监听)
      - 3.1.3 MMI事件处理链路(捕获/投递/处理/触发广播)
      - 3.1.4 MMI事件冻结机制(防止广播风暴)
      - 3.1.5 Bundle管理交互(广播压缩/应用匹配验证)
      - 3.2 阶段二_接续阶段(SRC推送/SINK拉取)
      - 3.2.1 Bundle管理交互(权限校验/Bundle验证)

  章节4_IPC通信架构:
    文件: reference/04_ipc_architecture.md
    内容:
      - 4.1 核心原则(Stub服务端/Proxy客户端)
      - 4.2 服务端列表(DistributedSchedStub等)
      - 4.3 客户端列表(DistributedSchedProxy等)
      - 4.4 场景角色对照(本端/远端角色映射)

  章节5_事件监听机制:
    文件: reference/05_event_listener.md
    内容:
      - 5.1 任务级别事件监听(获焦/失焦/后台/前台)
      - 5.2 应用级别事件监听(前台切换/进程死亡)
      - 5.3 事件处理管理器(DmsContinueConditionMgr)
      - 5.4 协作场景生命周期监听

  章节6_Bundle管理交互:
    文件: reference/06_bundle_interaction.md
    内容:
      - 6.1 概述(BundleManagerInternal与BMS交互)
      - 6.2 功能分类(Bundle查询/Ability匹配/跨应用接续/权限验证)
      - 6.3 接续流程中的使用(广播阶段/接续阶段)
      - 6.4 免安装相关
      - 6.5 调用位置索引

  ```