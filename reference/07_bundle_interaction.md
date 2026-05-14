# 7. Bundle管理交互

## 7.1 概述

```yaml
Bundle管理交互:
  说明: DMS模块与BMS(Bundle Manager Service)的交互封装

  核心类: BundleManagerInternal
  文件: bundle/bundle_manager_internal.h

  交互方式: 通过IBundleMgr代理与BMS通信
  代理获取: GetBundleManager() -> sptr<IBundleMgr>
```

---

## 7.2 功能分类

### 7.2.1 Bundle信息查询

```yaml
Bundle信息查询:
  GetBundleManager:
    功能: 获取BMS代理对象
    返回: sptr<IBundleMgr>

  GetLocalBundleInfo:
    功能: 获取本地Bundle信息
    参数: bundleName
    返回: BundleInfo
    使用场景:
      - SINK端检查应用是否已安装
      - 验证Bundle版本信息
      - 获取Bundle的接续能力配置

  GetLocalBundleInfoV9:
    功能: V9版本获取Bundle信息
    参数: bundleName
    返回: BundleInfo
    使用场景:
      - 接续阶段获取详细Bundle元数据

  GetLocalAbilityInfo:
    功能: 获取本地Ability信息
    参数: bundleName, moduleName, abilityName
    返回: AbilityInfo
    使用场景:
      - SINK端验证Ability是否可接续
      - 获取Ability的接续配置

  GetApplicationInfoFromBms:
    功能: 从BMS获取应用信息
    参数: bundleName, flag, userId
    返回: ApplicationInfo
```

---

### 7.2.2 Ability信息查询

```yaml
Ability信息查询:
  QueryAbilityInfo:
    功能: 查询Ability信息
    参数: Want
    返回: AbilityInfo
    使用场景:
      - 验证目标Ability是否存在
      - 获取Ability启动参数

  QueryExtensionAbilityInfo:
    功能: 查询Extension信息
    参数: Want
    返回: ExtensionAbilityInfo
    使用场景:
      - Extension组件接续支持

  InitAbilityInfoFromExtension:
    功能: 从Extension初始化Ability信息
    参数: ExtensionAbilityInfo
    返回: AbilityInfo
    使用场景:
      - Extension转换为Ability接续
```

---

### 7.2.3 接续类型与Ability匹配

```yaml
接续类型与Ability匹配:
  GetContinueTypeId:
    功能: 获取接续类型ID
    参数: bundleName, abilityName
    返回: continueTypeId(uint8_t)
    使用场景:
      - SRC端发送广播前获取接续类型ID
      - 用于广播数据压缩(BundleNameId+ContinueTypeId代替完整名称)
    调用位置:
      - 广播阶段: dms_continue_send_manager.cpp:272

  GetAbilityName:
    功能: 根据接续类型获取Ability名称
    参数: networkId, bundleName, continueType
    返回: abilityName(string)
    使用场景:
      - SINK端根据接续类型查找目标Ability
      - 支持跨Ability接续(不同Ability名称)
    用位置:
      - 广播阶段: dms_continue_recv_manager.cpp:669
      - 接续阶段: dsched_continue.cpp:622, 629

  GetContinueType:
    功能: 获取应用的接续类型配置
    参数: networkId, bundleName, continueTypeId
    返回: continueType(string)
    调用位置:
      - dms_continue_recv_manager.cpp:894
```

---

### 7.2.4 Bundle名称ID映射

```yaml
Bundle名称ID映射:
  GetBundleNameId:
    功能: 获取Bundle名称ID
    参数: bundleName
    返回: bundleNameId(uint16_t)
    使用场景:
      - SRC端发送广播前获取Bundle名称ID
      - 用于广播数据压缩(用ID代替完整BundleName)
    调用位置:
      - 广播阶段: dms_continue_send_manager.cpp:266
      - 接续阶段: dsched_continue_manager.cpp:284

  GetBundleNameById:
    功能: 通过ID获取Bundle名称
    参数: networkId, bundleNameId
    返回: bundleName(string)
    使用场景:
      - SINK端解析广播数据还原BundleName
```

---

### 7.2.5 跨应用接续

```yaml
跨应用接续:
  GetContinueBundle4Src:
    功能: 获取源端Bundle对应的目标Bundle列表
    参数: srcBundleName
    返回: bundleNameList(vector<string>)
    使用场景:
      - SINK端获取源端Bundle对应的目标Bundle列表
      - 支持跨Bundle接续(同开发者不同应用)
    调用位置:
      - 广播阶段: dms_continue_recv_manager.cpp:276, 332, 392

  IsSameDeveloperId:
    功能: 验证源端与目标端是否为同一开发者
    参数: bundleNameInCurrentSide, developerId4OtherSide
    返回: bool
    使用场景:
      - 验证源端与目标端是否为同一开发者
      - 跨应用接续权限校验
    调用位置:
      - 接续阶段: dsched_continue.cpp:951
```

---

### 7.2.6 AppId与权限验证

```yaml
AppId与权限验证:
  GetCallerAppIdFromBms:
    功能: 获取调用者AppId
    参数: callingUid 或 bundleName
    返回: appId(string)
    使用场景:
      - 接续发起时获取调用者AppId
      - 权限校验
    调用位置:
      - 接续阶段: dsched_continue.cpp:800

  GetBundleNameListFromBms:
    功能: 获取调用者Bundle列表
    参数: callingUid
    返回: bundleNameList(vector<string>)
    使用场景:
      - 获取调用者所属的Bundle列表
      - 多Bundle应用支持
    调用位置:
      - 接续阶段: dsched_continue.cpp:804

  IsSameAppId:
    功能: 检查是否相同AppId
    参数: callerAppId, targetBundleName
    返回: bool
    使用场景:
      - 验证调用者与目标应用是否相同

  GetAppProvisionInfo4CurrentUser:
    功能: 获取当前用户的AppProvisionInfo
    参数: bundleName
    返回: AppProvisionInfo
    使用场景:
      - 获取应用的AppProvisionInfo
      - 验证应用签名、开发者信息
    调用位置:
      - 广播阶段: dms_continue_recv_manager.cpp:292, 346, 403
      - 接续阶段: dsched_continue.cpp:912, 933

  GetSrcAppIdentifierVec:
    功能: 获取源端应用标识列表
    参数: appServiceCapabilities, bundleName
    返回: srcAppIdentifierVec(vector<string>)
    使用场景:
      - 获取源端应用标识列表
      - 应用匹配验证
    调用位置:
      - 广播阶段: dms_continue_recommend_manager.cpp:234
```

---

## 7.3 接续流程中的使用

### 7.3.1 广播阶段使用

```yaml
广播阶段_BMS交互:
  SRC端:
    SendContinueBroadcast():
      - GetBundleNameId(bundleName): 获取Bundle名称ID
      - GetContinueTypeId(bundleName, abilityName): 获取接续类型ID
      目的: 广播数据压缩

  SINK端:
    NotifyDataRecv():
      - GetLocalBundleInfo(bundleName): 检查应用是否已安装
      - GetContinueBundle4Src(bundleName): 获取可接续Bundle列表
      - GetAppProvisionInfo4CurrentUser(bundleName): 验证应用签名
      - GetLocalAbilityInfo(bundleName, moduleName, abilityName): 验证Ability可接续
      - GetAbilityName(networkId, bundleName, continueType): 查找目标Ability
      目的: 应用匹配验证、Ability定位
```

---

### 7.3.2 接续阶段使用

```yaml
接续阶段_BMS交互:
  SRC端:
    ContinueMission():
      - GetCallerAppIdFromBms(callingUid): 获取调用者AppId(权限验证)
      - GetBundleNameListFromBms(callingUid): 获取Bundle列表
      - GetLocalBundleInfo(bundleName): 验证Bundle信息
      - GetAppProvisionInfo4CurrentUser(bundleName): 验证应用签名
      目的: 权限校验、应用信息验证

  SINK端:
    ProcessContinueData():
      - GetLocalBundleInfoV9(bundleName): 获取Bundle信息
      - GetAbilityName(networkId, bundleName, continueType): 查找目标Ability
      - IsSameDeveloperId(bundleName, developerId): 验证开发者ID
      目的: Bundle验证、Ability定位、跨应用接续校验
```

---

## 7.4 免安装相关

```yaml
免安装相关:
  CheckIfRemoteCanInstall:
    功能: 检查远端是否可安装应用
    参数: Want, missionId
    返回: bool
    使用场景:
      - 免安装接续场景验证

  CheckRemoteBundleInfoForContinuation:
    功能: 检查远端Bundle信息是否可接续
    参数: dstDeviceId, bundleName
    返回: DistributedBundleInfo
    使用场景:
      - 验证目标设备Bundle状态

免安装回调:
  DmsBundleManagerCallbackStub:
    功能: IPC服务端Stub
    文件: bundle/bundle_manager_callback_stub.h
    接口: OnQueryInstallationFinished(resultCode, missionId, versionCode)
    使用场景:
      - 免安装完成后接收通知
```

---

## 7.5 调用位置索引

```yaml
调用位置索引:
  广播阶段:
    - dms_continue_send_manager.cpp:266 (GetBundleNameId)
    - dms_continue_send_manager.cpp:272 (GetContinueTypeId)
    - dms_continue_recv_manager.cpp:271 (GetLocalBundleInfo)
    - dms_continue_recv_manager.cpp:276 (GetContinueBundle4Src)
    - dms_continue_recv_manager.cpp:292,346,403 (GetAppProvisionInfo4CurrentUser)
    - dms_continue_recv_manager.cpp:669 (GetAbilityName)
    - dms_continue_recommend_manager.cpp:167 (GetLocalAbilityInfo)
    - dms_continue_recommend_manager.cpp:234 (GetSrcAppIdentifierVec)

  接续阶段:
    - dsched_continue.cpp:603 (GetLocalBundleInfo)
    - dsched_continue.cpp:622,629 (GetAbilityName)
    - dsched_continue.cpp:670,753 (GetLocalBundleInfoV9)
    - dsched_continue.cpp:800 (GetCallerAppIdFromBms)
    - dsched_continue.cpp:804 (GetBundleNameListFromBms)
    - dsched_continue.cpp:912,933 (GetAppProvisionInfo4CurrentUser)
    - dsched_continue.cpp:951 (IsSameDeveloperId)
    - dsched_continue_manager.cpp:284 (GetBundleNameId)
```