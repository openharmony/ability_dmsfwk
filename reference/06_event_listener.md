# 6. 事件监听机制

## 6.1 任务级别事件监听

```yaml
任务级别监听:
  事件:
    OnMissionFocused: 任务获得焦点
    OnMissionUnfocused: 任务失去焦点
    OnMissionMovedToBackground: 任务移到后台
    OnMissionMovedToFront: 任务移到前台
    OnMissionCreated: 任务创建
    OnMissionDestroyed: 任务销毁
    OnMissionClosed: 任务关闭
```

## 6.2 应用级别事件监听

```yaml
应用级别监听:
  事件:
    OnForegroundApplicationChanged: 应用前台/后台状态变化
    OnAbilityStateChanged: Ability状态变化
    OnExtensionStateChanged: Extension状态变化
    OnProcessCreated: 进程创建
    OnProcessDied: 进程死亡
```

## 6.3 事件处理管理器

```yaml
事件处理管理器:
  方法:
    OnMissionFocused: 处理任务获焦事件
    OnMissionUnfocused: 处理任务失焦事件
    OnMissionDestory: 处理任务销毁事件
    OnMissionBackground: 处理任务退后台事件
    OnMissionActive: 处理任务激活事件
    OnMissionInactive: 处理任务失活事件
```

## 6.4 协作场景生命周期监听

```yaml
协作生命周期监听:
  方法:
    OnForegroundApplicationChanged: 应用前台变化
```