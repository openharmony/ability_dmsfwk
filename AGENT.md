# DMS模块知识库

## 1. 基础概念与术语

### 1.1 模块别名映射

```yaml
模块别名:
  AMS模块: [Ability管理服务, AMS]
  账号模块: [系统账号, 分布式账号, OsAccount, OhosAccount, 账号子系统]
  窗口模块: [WM, 窗口管理, 窗口]
  软总线模块: [SoftBus, 软总线, 分布式软总线]
  设备管理模块: [DM, 设备管理器, 设备管理]
  Bundle管理模块: [BMS, 包管理]
  分布式数据模块: [KV存储, 分布式KV, 分布式数据]
  AccessToken模块: [权限管理, Token, AccessToken]
```

### 1.2 账号概念

#### 系统账号 (OsAccount)

```yaml
定义:
  名称: 系统账号
  别名: [用户, uid, 用户空间, 用户空间id, OsAccount]
  标识符:
    key: [localId, userId]
    type: int32
    示例: 100
  作用域: 本地设备
  用途: [数据隔离, 权限控制, 进程管理, 应用安装]
  特点: 不同设备的相同userId代表不同的用户空间
```

#### 分布式账号 (OhosAccount)

```yaml
定义:
  名称: 分布式账号
  别名: [华为账号, 账号, 用户账号, OhosAccount]
  标识符:
    key: [uid_, activeAccountId]
    type: string
    示例: 华为账号ID
  作用域: 跨设备(云端)
  用途: [跨设备认证, 组网, 分布式数据同步, 设备间信任关系]
  特点: 同一华为账号在不同设备上uid_相同
```

#### 账号绑定关系

```yaml
绑定关系:
  描述: 系统账号绑定分布式账号
  示例:
    设备A: 系统账号(userId=100) <-> 分布式账号(activeAccountId='华为ID_X')
    设备B: 系统账号(userId=100) <-> 分布式账号(activeAccountId='华为ID_X')
    注释: userId相同但代表不同用户空间，activeAccountId相同表示同一华为账号

同账号判断:
  方法: 比较activeAccountId
  相同: 允许跨设备操作(接续、协作)
  不同: 禁止或需要额外权限
```

#### AccountInfo结构体

```cpp
// 文件: distributed_sched_interface.h
struct AccountInfo {
    int32_t accountType;           // SAME_ACCOUNT_TYPE / DIFF_ACCOUNT_TYPE
    std::vector<std::string> groupIdList;
    std::string activeAccountId;   // 分布式账号ID(华为账号)
    int32_t userId;                // 系统账号ID(用户空间)
};
```

#### 变量使用场景

```yaml
userId使用:
  启动Ability: [userId, callerUid] -> StartAbility, StartRemoteAbility
  权限校验: [userId] -> CheckPermission, AccessToken校验
  Bundle查询: [userId] -> GetApplicationInfo, GetBundleInfo
  协作匹配: [userId, srcUserId, sinkUserId] -> DSchedCollab匹配SRC/SINK端
  用户切换: [accountId, userId] -> HandleUserSwitched
  Token生成: [userId] -> GetHapTokenID(userId, bundleName, 0)

activeAccountId使用:
  同账号校验: [activeAccountId, accountId] -> CheckSameAccount, CheckIsSameAccount
  跨设备认证: [activeAccountId] -> DeviceManager.CheckIsSameAccount
  Intent校验: [uid_] -> IntentPermissionChecker
  协作传输: [activeAccountId] -> DSchedCollabEvent序列化
  组网验证: [uid_] -> DistributedSchedMissionManager
  MDM豁免: [accountId] -> IsMDMControlWithExemption
```

#### 查询接口

```yaml
系统账号查询:
  命名空间: AccountSA::OsAccountManager
  代码路径: ability_os_account/interfaces/innerkits/osaccount/native/include/
  接口:
    QueryActiveOsAccountIds:
      返回: std::vector<int32_t>
      用途: 获取活跃用户ID列表
    QueryOsAccountById:
      参数: userId
      返回: OsAccountInfo
      用途: 查询指定用户信息
    IsOsAccountActived:
      参数: userId
      返回: bool
      用途: 检查用户是否激活
    CheckOsAccountConstraintEnabled:
      参数: [userId, constraint, isEnabled]
      用途: 检查账号约束(MDM控制)

分布式账号查询:
  命名空间: AccountSA::OhosAccountKits::GetInstance()
  代码路径: ability_os_account/interfaces/innerkits/ohosaccount/native/include/
  接口:
    GetOhosAccountInfo:
      返回: OhosAccountInfo
      用途: 获取当前分布式账号信息
      关键字段: uid_
```

### 1.3 设备角色

#### SRC端(源设备)

```yaml
SRC端:
  名称: SRC端
  别名: [source端, src, src端, 源端, 发送端, 源设备]
  角色: 发起接续
  广播阶段: 发送接续意图广播
  接续阶段: 推送应用数据(PUSH)
  状态流转: [SOURCE_START, ABILITY, SOURCE_WAIT_END, SOURCE_END]
```

#### SINK端(目标设备)

```yaml
SINK端:
  名称: SINK端
  别名: [sink端, 目标端, sink, 对端, 接收端, 目标设备]
  角色: 接收接续
  广播阶段: 接收广播、处理推荐
  接续阶段: 拉取数据、启动应用(PULL)
  状态流转: [SINK_START, DATA, SINK_WAIT_END, SINK_END]
```

#### 模块命名

```yaml
模块中文名:
  collab: 新协同
  continue: [应用迁移, 接续, 应用接续, 应用跨端迁移]
```

---

## 2. 模块依赖与外部接口

### 2.1 AMS模块

```yaml
AMS模块:
  别名: [Ability管理服务, AMS]
  命名空间: AAFwk
  代码路径: D:\Code\ability_ability_runtime
  关键接口:
    AbilityManagerClient::GetInstance():
      StartAbility: 启动Ability
      ConnectAbility: 连接ServiceExtension
      DisconnectAbility: 断开连接
      StartAbilityByCall: Call模式启动
      ReleaseCall: 释放Call连接
      ContinueAbility: 应用接续
```

### 2.2 账号模块

```yaml
账号模块:
  别名: [系统账号, 分布式账号, OsAccount, OhosAccount, 账号子系统]
  命名空间: AccountSA
  代码路径: D:\Code\account_os_account
  关键接口:
    OsAccountManager:
      QueryActiveOsAccountIds: 查询活跃用户
      QueryOsAccountById: 查询用户信息
      IsOsAccountActived: 检查激活状态
    OhosAccountKits::GetInstance():
      GetOhosAccountInfo: 获取华为账号信息
```

### 2.3 软总线模块

```yaml
软总线模块:
  别名: [SoftBus, 软总线, 分布式软总线]
  代码路径: D:\Code\communication_dsoftbus
  本模块封装: DSchedTransportSoftbusAdapter
  关键接口:
    GetInstance():
      InitChannel: 初始化传输通道
      ConnectDevice: 连接设备
      SendData: 发送数据
      DisconnectDevice: 断开连接
      RegisterListener: 注册监听器
```

### 2.4 设备管理模块

```yaml
设备管理模块:
  别名: [DM, 设备管理器, 设备管理]
  关键接口:
    GetInstance():
      InitDeviceManager: 初始化设备管理
      RegisterDevStateCallback: 注册设备状态回调
      CheckIsSameAccount: 同账号检查
      CheckSrcIsSameAccount: SRC端同账号检查
      CheckSinkIsSameAccount: SINK端同账号检查
  数据结构:
    DmAccessCaller:
      accountId: 分布式账号ID
      networkId: 设备网络ID
      userId: 系统账号ID
      tokenId: AccessToken
      pkgName: 包名
    DmAccessCallee:
      networkId: 设备网络ID
      accountId: 分布式账号ID
      userId: 系统账号ID
      peerId: 对端ID
```

### 2.5 Bundle管理模块

```yaml
Bundle管理模块:
  别名: [BMS, 包管理]
  命名空间: AppExecFwk
  关键接口:
    IBundleMgr:
      GetBundleInfo: 获取Bundle信息
      QueryAbilityInfo: 查询Ability信息
      GetApplicationInfo: 获取应用信息
    BundleManagerInternal:
      QueryAbilityInfo: 查询Ability信息
      GetLocalBundleInfo: 获取本地Bundle信息
      GetBundleManager: 获取BMS代理
```

### 2.6 分布式数据模块

```yaml
分布式数据模块:
  别名: [KV存储, 分布式KV, 分布式数据]
  命名空间: DistributedKv
  关键接口:
    DistributedKvDataManager:
      GetSingleKvStore: 获取KV存储
    SingleKvStore:
      Sync: 数据同步
      Put: 写入数据
      Get: 获取数据
```

### 2.7 AccessToken模块

```yaml
AccessToken模块:
  别名: [权限管理, Token, AccessToken]
  关键类型: AccessToken::AccessTokenID
  用途: [权限校验, Token管理]
```

---

## 3. 接续业务流程

### 3.1 阶段一：广播阶段

```yaml
广播阶段:
  描述: SRC端发送接续意图广播，SINK端接收广播并处理推荐

  SRC端入口:
    类: DMSContinueSendMgr
    方法: SendContinueBroadcast()
    文件: mission/notification/dms_continue_send_manager.h
    触发: OnMissionStatusChanged() -> 任务状态变化触发

  SINK端入口:
    类: DMSContinueRecvMgr
    方法: NotifyDataRecv()
    文件: mission/notification/dms_continue_recv_manager.h
    触发: 软总线接收广播数据
```

### 3.2 阶段二：接续阶段

```yaml
接续阶段:
  描述: SRC端推送数据，SINK端拉取数据并启动应用

  SRC端入口:
    类: DSchedContinueManager
    方法: ContinueMission()
    文件: continue/dsched_continue_manager.h
    调用链:
      - ContinueMission()
      - HandleContinueMission()
      - 创建DSchedContinue实例(SOURCE端)
      - Init()
      - SendContinueData()

  SINK端入口:
    类: DSchedContinue
    方法: ProcessContinueData()
    文件: continue/dsched_continue.h
    调用链:
      - DSchedContinueManager::OnDataRecv()
      - HandleDataRecv()
      - NotifyContinueDataRecv()
      - 获取/创建DSchedContinue实例(SINK端)
      - ProcessContinueData()
      - StartAbility()
```

---

## 4. IPC通信架构

### 4.1 核心原则

```yaml
IPC原则:
  服务端Stub: 继承IRemoteStub，实现OnRemoteRequest，被动响应远端请求
  客户端Proxy: 继承IRemoteProxy，调用SendRequest，主动发起远端请求
```

### 4.2 服务端列表

```yaml
服务端:
  DistributedSched:
    类: DistributedSchedStub
    文件: services/dtbschedmgr/include/distributed_sched_stub.h
    处理: [StartAbilityFromRemote, ConnectAbilityFromRemote, ContinueMission, NotifyContinuationResultFromRemote]

  AbilityConnectionWrapper:
    类: AbilityConnectionWrapperStub
    文件: services/dtbschedmgr/include/ability_connection_wrapper_stub.h
    处理: [OnAbilityConnectDone, OnAbilityDisconnectDone]

  BundleManagerCallback:
    类: DmsBundleManagerCallbackStub
    文件: services/dtbschedmgr/include/bundle/bundle_manager_callback_stub.h
    处理: [OnFreeInstallDone]

  DistributedIntentService:
    类: DistributedIntentServiceStub
    文件: services/dtbschedmgr/include/distributedIntent/distributed_intent_service_stub.h
    处理: [SendDistributedIntent]

  FreeInstallCallback:
    类: DmsFreeInstallCallbackStub
    文件: services/dtbschedmgr/include/dms_free_install_callback_stub.h
    处理: [OnFreeInstallResult]
```

### 4.3 客户端列表

```yaml
客户端:
  DistributedSched:
    类: DistributedSchedProxy
    文件: services/dtbschedmgr/include/distributed_sched_proxy.h
    发送: [StartRemoteAbility, ConnectRemoteAbility, ContinueMission, NotifyCompleteContinuation]

  AbilityConnectionWrapper:
    类: AbilityConnectionWrapperProxy
    文件: services/dtbschedmgr/include/ability_connection_wrapper_proxy.h
    发送: [OnAbilityConnectDone, OnAbilityDisconnectDone]

  FreeInstallCallback:
    类: DmsFreeInstallCallbackProxy
    文件: services/dtbschedmgr/include/dms_free_install_callback_proxy.h
    发送: [OnFreeInstallResult]
```

### 4.4 场景角色对照

```yaml
场景角色:
  本端启动远端Ability: {本端: 客户端(Proxy), 远端: 服务端(Stub)}
  远端启动本端Ability: {本端: 服务端(Stub), 远端: 客户端(Proxy)}
  本端发起接续: {本端: 客户端(Proxy), 远端: 服务端(Stub)}
  本端接收接续: {本端: 服务端(Stub), 远端: 客户端(Proxy)}
  连接回调通知: {本端: 双向, 远端: 双向}
  免安装回调: {本端: 双向, 远端: 双向}
```

---

## 5. 事件监听机制

### 5.1 任务级别事件监听

```yaml
任务级别监听:
  类: DistributedMissionFocusedListener
  文件: mission/distributed_mission_focused_listener.h
  事件:
    OnMissionFocused: 任务获得焦点
    OnMissionUnfocused: 任务失去焦点
    OnMissionMovedToBackground: 任务移到后台
    OnMissionMovedToFront: 任务移到前台
    OnMissionCreated: 任务创建
    OnMissionDestroyed: 任务销毁
    OnMissionClosed: 任务关闭
```

### 5.2 应用级别事件监听

```yaml
应用级别监听:
  类: AppStateObserver
  文件: app_state_observer.h
  事件:
    OnForegroundApplicationChanged: 应用前台/后台状态变化
    OnAbilityStateChanged: Ability状态变化
    OnExtensionStateChanged: Extension状态变化
    OnProcessCreated: 进程创建
    OnProcessDied: 进程死亡
```

### 5.3 事件处理管理器

```yaml
事件处理管理器:
  类: DmsContinueConditionMgr
  文件: mission/dms_continue_condition_manager.h
  方法:
    OnMissionFocused: 处理任务获焦事件
    OnMissionUnfocused: 处理任务失焦事件
    OnMissionDestory: 处理任务销毁事件
    OnMissionBackground: 处理任务退后台事件
    OnMissionActive: 处理任务激活事件
    OnMissionInactive: 处理任务失活事件
```

### 5.4 协作场景生命周期监听

```yaml
协作生命周期监听:
  类: AbilityLifecycleObserver
  文件: collab/ability_state_observer.h
  方法:
    OnForegroundApplicationChanged: 应用前台变化
```

---
