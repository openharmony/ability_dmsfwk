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
      - 3.2 阶段二_接续阶段(SRC推送/SINK拉取)

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

  ```