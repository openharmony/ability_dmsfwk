# 3. 接续业务流程

## 3.1 阶段一：广播阶段

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

## 3.2 阶段二：接续阶段

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