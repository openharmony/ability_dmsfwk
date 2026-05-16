# 2. 模块依赖与外部接口

## 2.1 AMS模块

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

## 2.2 账号模块

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

## 2.3 软总线模块

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

## 2.4 设备管理模块

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

## 2.5 Bundle管理模块

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

## 2.6 分布式数据模块

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

## 2.7 AccessToken模块

```yaml
AccessToken模块:
  别名: [权限管理, Token, AccessToken]
  关键类型: AccessToken::AccessTokenID
  用途: [权限校验, Token管理]
```