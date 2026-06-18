# 4. 接续业务流程

## 4.1 阶段一：广播阶段

```yaml
广播阶段:
  描述: SRC端发送接续意图广播，SINK端接收广播并处理推荐

  SRC端:
    入口: SendContinueBroadcast() 发送接续广播
    出口: 广播数据发送至软总线

  SINK端:
    入口: NotifyDataRecv() 接收广播数据
    出口: 生成接续推荐列表或触发引导安装

  广播触发条件:
    - 可接续页面获焦/激活 → 发送APPEAR广播
    - 可接续页面失焦/失活/退后台/销毁 → 发送DISAPPEAR广播
    - MMI事件(用户输入)触发 → 发送APPEAR广播

  MMI事件冻结:
    说明: MMI事件触发后5秒冻结，防止广播风暴

  Bundle管理交互:
    说明: 广播数据压缩和应用匹配验证，详见知识索引中Bundle交互相关文档

  SINK端包匹配:
    说明: SINK端接收广播后匹配本地可接续Bundle的详细规则，详见知识索引中标注优先级最高的包匹配文档
    匹配场景: 同Bundle接续、跨Bundle接续、AppIdentifier匹配
```

## 4.2 阶段二：接续阶段

```yaml
接续阶段:
  描述: SRC端推送数据，SINK端拉取数据并启动应用

  SRC端:
    入口: ContinueMission() 发起接续请求
    出口: 接续数据发送至SINK端

  SINK端:
    入口: ProcessContinueData() 处理接续数据
    出口: 启动目标Ability

  Bundle管理交互:
    说明: 权限校验和Bundle验证，详见知识索引中Bundle交互相关文档
```