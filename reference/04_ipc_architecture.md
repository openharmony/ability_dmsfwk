# 4. IPC通信架构

## 4.1 核心原则

```yaml
IPC原则:
  服务端Stub: 继承IRemoteStub，实现OnRemoteRequest，被动响应远端请求
  客户端Proxy: 继承IRemoteProxy，调用SendRequest，主动发起远端请求
```

## 4.2 服务端列表

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

## 4.3 客户端列表

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

## 4.4 场景角色对照

```yaml
场景角色:
  本端启动远端Ability: {本端: 客户端(Proxy), 远端: 服务端(Stub)}
  远端启动本端Ability: {本端: 服务端(Stub), 远端: 客户端(Proxy)}
  本端发起接续: {本端: 客户端(Proxy), 远端: 服务端(Stub)}
  本端接收接续: {本端: 服务端(Stub), 远端: 客户端(Proxy)}
  连接回调通知: {本端: 双向, 远端: 双向}
  免安装回调: {本端: 双向, 远端: 双向}
```