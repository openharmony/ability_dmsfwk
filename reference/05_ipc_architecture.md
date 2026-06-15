# 5. IPC通信架构

## 5.1 核心原则

```yaml
IPC原则:
  服务端Stub: 继承IRemoteStub，实现OnRemoteRequest，被动响应远端请求
  客户端Proxy: 继承IRemoteProxy，调用SendRequest，主动发起远端请求
```

## 5.2 服务端列表

```yaml
服务端Stub:
  DistributedSchedStub:
    处理: StartAbilityFromRemote, ConnectAbilityFromRemote, ContinueMission, NotifyContinuationResultFromRemote

  AbilityConnectionWrapperStub:
    处理: OnAbilityConnectDone, OnAbilityDisconnectDone

  DmsBundleManagerCallbackStub:
    处理: OnFreeInstallDone

  DistributedIntentServiceStub:
    处理: SendDistributedIntent

  DmsFreeInstallCallbackStub:
    处理: OnFreeInstallResult
```

## 5.3 客户端列表

```yaml
客户端Proxy:
  DistributedSchedProxy:
    发送: StartRemoteAbility, ConnectRemoteAbility, ContinueMission, NotifyCompleteContinuation

  AbilityConnectionWrapperProxy:
    发送: OnAbilityConnectDone, OnAbilityDisconnectDone

  DmsFreeInstallCallbackProxy:
    发送: OnFreeInstallResult
```

## 5.4 场景角色对照

```yaml
场景角色:
  本端启动远端Ability: {本端: 客户端Proxy, 远端: 服务端Stub}
  远端启动本端Ability: {本端: 服务端Stub, 远端: 客户端Proxy}
  本端发起接续: {本端: 客户端Proxy, 远端: 服务端Stub}
  本端接收接续: {本端: 服务端Stub, 远端: 客户端Proxy}
  连接回调通知: {本端: 双向, 远端: 双向}
  免安装回调: {本端: 双向, 远端: 双向}
```