# 4. 接续业务流程

## 4.1 阶段一：广播阶段

```yaml
广播阶段:
  描述: SRC端发送接续意图广播，SINK端接收广播并处理推荐

  SRC端入口:
    类: DMSContinueSendMgr
    方法: SendContinueBroadcast()
    文件: mission/notification/dms_continue_send_manager.h
    触发: OnMissionStatusChanged() -> 可接续页面状态变化触发

  SINK端入口:
    类: DMSContinueRecvMgr
    方法: NotifyDataRecv()
    文件: mission/notification/dms_continue_recv_manager.h
    触发: 软总线接收广播数据
```

### 4.1.1 广播触发条件

```yaml
广播触发条件:
  可接续页面状态变化:
    说明: Mission在接续业务中指代应用的可接续页面(PageAbility)
    - 可接续页面获焦(Focused) → 发送APPEAR广播
    - 可接续页面失焦(Unfocused) → 发送DISAPPEAR广播
    - 可接续页面退后台(Background) → 发送DISAPPEAR广播
    - 可接续页面销毁(Destroyed) → 发送DISAPPEAR广播
    - 可接续页面激活(Active) → 发送APPEAR广播
    - 可接续页面失活(Inactive) → 发送DISAPPEAR广播

  MMI事件触发:
    说明: 用户输入事件触发接续广播发送
    触发条件: 可接续页面处于获焦/激活状态且MMI监听器已添加

    MMI事件类型:
      KeyEvent: 按键事件(键盘输入)
      PointerEvent: 指针事件(触摸/点击/滑动)
      AxisEvent: 轴事件(滚轮/旋钮等)

    广播类型: BROADCAST_TYPE_APPEAR

    核心作用: MMI事件表示用户正在使用设备,触发发送接续广播,让SINK端知道SRC端有活跃的可接续页面可用于接续
```

### 4.1.2 MMI事件监听流程

```yaml
MMI事件监听流程:
  初始化:
    入口: MultiUserManager::Init()
    文件: multi_user_manager.cpp
    操作: MMIAdapter::GetInstance().Init()

  添加监听器:
    入口: DMSContinueSendMgr::AddMMIListener()
    文件: mission/notification/dms_continue_send_manager.cpp
    触发时机:
      - 可接续页面获焦(SendStrategyFocused)
      - 可接续页面激活(SendStrategyActive)
      - 设备上线且屏幕解锁
    操作:
      - mmiMonitorId_ = MMIAdapter::GetInstance().AddMMIListener()
      - isMMIFreezed_ = false

  移除监听器:
    入口: DMSContinueSendMgr::RemoveMMIListener()
    文件: mission/notification/dms_continue_send_manager.cpp
    触发时机:
      - 可接续页面失焦(SendStrategyUnfocused)
      - 可接续页面销毁(SendStrategyDestoryed)
      - 可接续页面失活(SendStrategyInactive)
      - 用户切换
    操作: MMIAdapter::GetInstance().RemoveMMIListener(mmiMonitorId_)
```

### 4.1.3 MMI事件处理链路

```yaml
MMI事件处理链路:
  步骤1_事件捕获:
    类: MMIAdapter::MMIEventCallback
    文件: adapter/mmi_adapter.cpp
    方法:
      OnInputEvent(KeyEvent): 按键事件回调
      OnInputEvent(PointerEvent): 触摸事件回调
      OnInputEvent(AxisEvent): 轴事件回调
    操作: MMIAdapter::GetInstance().PostRawMMIEvent()

  步骤2_事件投递:
    类: MMIAdapter
    方法: PostRawMMIEvent()
    操作: eventHandler_->PostTask(HandleRawMMIEvent)

  步骤3_事件处理:
    类: MMIAdapter
    方法: HandleRawMMIEvent()
    操作:
      - 检查isMMIFreezed_(冻结状态)
      - 已冻结: 直接返回
      - 未冻结: 设置isMMIFreezed_=true,继续处理
      - 获取sendMgr = MultiUserManager::GetInstance().GetCurrentSendMgr()
      - sendMgr->OnMMIEvent()
      - PostUnfreezeMMIEvent()(5秒后解冻)

  步骤4_触发广播:
    类: DMSContinueSendMgr
    方法: OnMMIEvent()
    文件: mission/notification/dms_continue_send_manager.cpp
    操作:
      - missionId = DmsContinueConditionMgr::GetInstance().GetCurrentFocusedMission(accountId_)
      - 移除超时任务: RemoveTask(TIMEOUT_UNFOCUSED_TASK + missionId)
      - SendContinueBroadcast(missionId, MISSION_EVENT_MMI)
```

### 4.1.4 MMI事件冻结机制

```yaml
冻结机制:
  目的: 防止频繁MMI事件导致广播风暴

  关键变量:
    isMMIFreezed_: 冻结状态标志(bool)
    FREEZE_MMI_EVENT_INTERVAL: 5000ms冻结间隔

  冻结流程:
    MMI事件触发:
      - 设置isMMIFreezed_=true
      - 处理事件发送广播
      - PostUnfreezeMMIEvent()投递解冻任务

    解冻流程:
      - 5秒后执行HandleUnfreezeMMIEvent()
      - 设置isMMIFreezed_=false
      - 允许响应新的MMI事件

  效果: MMI事件触发后5秒内不再响应新的MMI事件,避免频繁发送接续广播
```

### 4.1.5 Bundle管理交互

```yaml
广播阶段_BMS交互:
  说明: 广播阶段与BMS的交互,用于广播数据压缩和应用匹配验证
  详细说明: 见 [07_Bundle管理交互](07_bundle_interaction.md) 章节7.3.1

  SRC端:
    SendContinueBroadcast():
      - GetBundleNameId(bundleName): 获取Bundle名称ID(广播压缩)
      - GetContinueTypeId(bundleName, abilityName): 获取接续类型ID(广播压缩)

  SINK端:
    NotifyDataRecv():
      - GetLocalBundleInfo(bundleName): 检查应用是否已安装
      - GetContinueBundle4Src(bundleName): 获取可接续Bundle列表(跨应用接续)
      - GetAppProvisionInfo4CurrentUser(bundleName): 验证应用签名
      - GetLocalAbilityInfo(bundleName, moduleName, abilityName): 验证Ability可接续
      - GetAbilityName(networkId, bundleName, continueType): 查找目标Ability
      - GetSrcAppIdentifierVec(appServiceCapabilities, bundleName): 应用标识匹配
```

### 4.1.6 SINK端包匹配

```yaml
SINK端包匹配:
  说明: SINK端接收广播后匹配本地可接续Bundle的详细规则
  详细说明: 见 [04_01_06_SINK端包匹配规则](04_01_06_sink_bundle_matching.md)

  匹配场景:
    - 同Bundle接续: 源端Bundle在本地已安装
    - 跨Bundle接续: 同开发者不同Bundle
    - AppIdentifier匹配: 应用标识精确匹配

  匹配优先级:
    优先级1: 同Bundle匹配(最高优先级)
    优先级2: AppIdentifier精确匹配
    优先级3: 开发者ID匹配
    优先级4: 匹配失败(推荐安装)
```

## 4.2 阶段二：接续阶段

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

### 4.2.1 Bundle管理交互

```yaml
接续阶段_BMS交互:
  说明: 接续阶段与BMS的交互,用于权限校验和Bundle验证
  详细说明: 见 [07_Bundle管理交互](07_bundle_interaction.md) 章节7.3.2

  SRC端:
    ContinueMission():
      - GetCallerAppIdFromBms(callingUid): 获取调用者AppId(权限验证)
      - GetBundleNameListFromBms(callingUid): 获取Bundle列表(多Bundle应用)
      - GetLocalBundleInfo(bundleName): 验证Bundle信息
      - GetAppProvisionInfo4CurrentUser(bundleName): 验证应用签名

  SINK端:
    ProcessContinueData():
      - GetLocalBundleInfoV9(bundleName): 获取Bundle详细信息
      - GetAbilityName(networkId, bundleName, continueType): 查找目标Ability
      - IsSameDeveloperId(bundleName, developerId): 验证开发者ID(跨应用接续)
```