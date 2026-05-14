# 5. 事件监听机制

## 5.1 任务级别事件监听

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

## 5.2 应用级别事件监听

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

## 5.3 事件处理管理器

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

## 5.4 协作场景生命周期监听

```yaml
协作生命周期监听:
  类: AbilityLifecycleObserver
  文件: collab/ability_state_observer.h
  方法:
    OnForegroundApplicationChanged: 应用前台变化
```