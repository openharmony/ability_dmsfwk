# 7. Bundle管理交互

## 7.1 概述

```yaml
Bundle管理交互:
  说明: DMS模块与BMS(Bundle Manager Service)的交互封装
  交互方式: 通过IBundleMgr代理与BMS通信
```

## 7.2 功能分类

### 7.2.1 Bundle信息查询

```yaml
Bundle信息查询:
  GetLocalBundleInfo:
    功能: 获取本地Bundle信息
    使用场景: SINK端检查应用是否已安装、验证Bundle版本

  GetLocalBundleInfoV9:
    功能: V9版本获取Bundle信息
    使用场景: 接续阶段获取详细Bundle元数据

  GetLocalAbilityInfo:
    功能: 获取本地Ability信息
    使用场景: SINK端验证Ability是否可接续
```

### 7.2.2 接续类型与Ability匹配

```yaml
接续类型与Ability匹配:
  GetContinueTypeId:
    功能: 获取接续类型ID
    使用场景: SRC端发送广播前获取接续类型ID（广播数据压缩）

  GetAbilityName:
    功能: 根据接续类型获取Ability名称
    使用场景: SINK端根据接续类型查找目标Ability

  GetBundleNameId:
    功能: 获取Bundle名称ID
    使用场景: SRC端发送广播前获取Bundle名称ID（广播数据压缩）

  GetBundleNameById:
    功能: 通过ID获取Bundle名称
    使用场景: SINK端解析广播数据还原BundleName
```

### 7.2.3 跨应用接续

```yaml
跨应用接续:
  GetContinueBundle4Src:
    功能: 获取源端Bundle对应的目标Bundle列表
    使用场景: SINK端获取源端Bundle对应的目标Bundle列表（跨Bundle接续）

  IsSameDeveloperId:
    功能: 验证源端与目标端是否为同一开发者
    使用场景: 跨应用接续权限校验
```

### 7.2.4 AppId与权限验证

```yaml
AppId与权限验证:
  GetCallerAppIdFromBms:
    功能: 获取调用者AppId
    使用场景: 接续发起时权限校验

  GetBundleNameListFromBms:
    功能: 获取调用者Bundle列表
    使用场景: 多Bundle应用支持

  GetAppProvisionInfo4CurrentUser:
    功能: 获取当前用户的AppProvisionInfo
    使用场景: 验证应用签名、开发者信息

  GetSrcAppIdentifierVec:
    功能: 获取源端应用标识列表
    使用场景: 应用匹配验证
```

## 7.3 接续流程中的使用

### 7.3.1 广播阶段

```yaml
广播阶段_BMS交互:
  SRC端:
    SendContinueBroadcast():
      - GetBundleNameId(): Bundle名称ID
      - GetContinueTypeId(): 接续类型ID
    目的: 广播数据压缩

  SINK端:
    NotifyDataRecv():
      - GetLocalBundleInfo(): 检查应用是否已安装
      - GetContinueBundle4Src(): 获取可接续Bundle列表
      - GetAppProvisionInfo4CurrentUser(): 验证应用签名
      - GetLocalAbilityInfo(): 验证Ability可接续
      - GetAbilityName(): 查找目标Ability
    目的: 应用匹配验证、Ability定位
```

### 7.3.2 接续阶段

```yaml
接续阶段_BMS交互:
  SRC端:
    ContinueMission():
      - GetCallerAppIdFromBms(): 获取调用者AppId
      - GetBundleNameListFromBms(): 获取Bundle列表
      - GetLocalBundleInfo(): 验证Bundle信息
      - GetAppProvisionInfo4CurrentUser(): 验证应用签名
    目的: 权限校验、应用信息验证

  SINK端:
    ProcessContinueData():
      - GetLocalBundleInfoV9(): 获取Bundle信息
      - GetAbilityName(): 查找目标Ability
      - IsSameDeveloperId(): 验证开发者ID
    目的: Bundle验证、Ability定位、跨应用接续校验
```

## 7.4 免安装相关

```yaml
免安装相关:
  CheckIfRemoteCanInstall:
    功能: 检查远端是否可安装应用
    使用场景: 免安装接续场景验证

  CheckRemoteBundleInfoForContinuation:
    功能: 检查远端Bundle信息是否可接续
    使用场景: 验证目标设备Bundle状态

  OnQueryInstallationFinished:
    功能: 免安装完成后接收通知
    使用场景: 免安装回调
```