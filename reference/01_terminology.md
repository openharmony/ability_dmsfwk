# 1. 基础概念与术语

## 1.1 模块别名映射

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

## 1.2 账号概念

### 系统账号 (OsAccount)

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

### 分布式账号 (OhosAccount)

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

### 账号绑定关系

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

### AccountInfo结构体

```cpp
// 文件: distributed_sched_interface.h
struct AccountInfo {
    int32_t accountType;           // SAME_ACCOUNT_TYPE / DIFF_ACCOUNT_TYPE
    std::vector<std::string> groupIdList;
    std::string activeAccountId;   // 分布式账号ID(华为账号)
    int32_t userId;                // 系统账号ID(用户空间)
};
```

### 变量使用场景

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

### 查询接口

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

## 1.3 设备角色

### SRC端(源设备)

```yaml
SRC端:
  名称: SRC端
  别名: [source端, src, src端, 源端, 发送端, 源设备]
  角色: 发起接续
  广播阶段: 发送接续意图广播
  接续阶段: 推送应用数据(PUSH)
  状态流转: [SOURCE_START, ABILITY, SOURCE_WAIT_END, SOURCE_END]
```

### SINK端(目标设备)

```yaml
SINK端:
  名称: SINK端
  别名: [sink端, 目标端, sink, 对端, 接收端, 目标设备]
  角色: 接收接续
  广播阶段: 接收广播、处理推荐
  接续阶段: 拉取数据、启动应用(PULL)
  状态流转: [SINK_START, DATA, SINK_WAIT_END, SINK_END]
```

### 模块命名

```yaml
模块中文名:
  collab: 新协同
  continue: [应用迁移, 接续, 应用接续, 应用跨端迁移]
```