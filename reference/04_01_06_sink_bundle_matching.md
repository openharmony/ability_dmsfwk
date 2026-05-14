# SINK端包匹配规则

## 1. 概述

```yaml
SINK端包匹配:
  说明: SINK端接收广播后,根据源端Bundle信息匹配本地可接续的目标Bundle
  所属章节: 章节4.1.6 广播阶段

  核心类: DMSContinueRecvMgr
  文件: mission/notification/dms_continue_recv_manager.cpp

  入口方法:
    ValidateAndPrepareBundleInfo(): 验证并准备Bundle信息
    GetFinalBundleName(): 获取最终匹配的Bundle名称
    GetFinalBundleNameOrAppIdentifierList(): 使用AppIdentifier匹配

  触发时机:
    - SINK端接收到APPEAR广播
    - 需要确定本地可接续的目标Bundle

  匹配目的:
    - 支持同Bundle接续
    - 支持同开发者跨Bundle接续
    - 支持AppIdentifier精确匹配
```

---

## 2. 匹配场景分类

```yaml
匹配场景:
  场景1_同Bundle接续:
    说明: 源端Bundle名与目标端相同
    条件: 源端bundleName在本地已安装
    结果: finalBundleName = bundleName
    示例: 源端com.example.app → 目标端com.example.app

  场景2_同开发者跨Bundle接续:
    说明: 开发者ID相同但Bundle名不同(同一开发者的不同应用)
    条件:
      - 源端bundleName在本地未安装
      - 存在同开发者ID的其他Bundle
    验证: developerId匹配
    结果: finalBundleName = 匹配的BundleName
    示例: 源端com.example.app1 → 目标端com.example.app2(同开发者)

  场景3_AppIdentifier匹配:
    说明: 使用应用标识进行精确匹配
    条件: appIdentifierVec不为空
    验证: appIdentifier匹配
    结果: finalBundleName = 通过appIdentifier映射的BundleName
    示例: 通过应用签名标识精确匹配
```

---

## 3. 匹配流程

```yaml
匹配流程:
  步骤1_接收广播数据:
    DealOnBroadcastBusiness():
      - GetDistributedBundleInfo(): 获取源端Bundle信息
      - ValidateAndPrepareBundleInfo(): 验证并准备Bundle信息

  步骤2_查找接续类型:
    FindContinueType():
      - 从distributedBundleInfo.dmsAbilityInfos中查找
      - 根据continueTypeId定位continueType
      - 返回对应的abilityInfo

  步骤3_Bundle匹配:
    ValidateAndPrepareBundleInfo():
      - FindContinueType(): 查找接续类型
      - GetFinalBundleNameOrAppIdentifierList(): 匹配目标Bundle
      - GetFinalBundleName(): 获取最终Bundle名称

  调用链路图:
    DealOnBroadcastBusiness()
      └─> ValidateAndPrepareBundleInfo()
            ├─> FindContinueType()
            ├─> GetFinalBundleNameOrAppIdentifierList()
            │     ├─> HandleEmptyAppIdentifierVec()
            │     │     └─> GetFinalBundleNameInternal()
            │     └─> HandleNonEmptyAppIdentifierVec()
            │           └─> AppIdentifier精确匹配
            └─> GetFinalBundleName()
                  └─> GetFinalBundleNameInternal()
```

---

## 4. GetFinalBundleName匹配规则

```yaml
GetFinalBundleName:
  文件: dms_continue_recv_manager.cpp:322

  匹配逻辑:
    条件1_源端appIdentifierVec为空:
      操作: 调用GetFinalBundleNameInternal()
      说明: 使用developerId匹配
      流程: 同Bundle检查 → 开发者ID匹配

    条件2_源端appIdentifierVec不为空:
      操作: 使用AppIdentifier匹配流程
      说明: 使用appIdentifier精确匹配
      流程: 构建映射表 → 精确匹配

  返回:
    成功: finalBundleName, localBundleInfo
    失败: false

  伪代码:
    bool GetFinalBundleName(BundleValidationContext& context) {
        if (distributedBundleInfo.appIdentifierVec.empty()) {
            return GetFinalBundleNameInternal(context);
        } else {
            // 使用AppIdentifier匹配
            return GetFinalBundleNameOrAppIdentifierList(context);
        }
    }
```

---

## 5. GetFinalBundleNameInternal匹配规则

```yaml
GetFinalBundleNameInternal:
  文件: dms_continue_recv_manager.cpp:266

  匹配步骤:
    步骤1_同Bundle检查:
      操作: GetLocalBundleInfo(bundleName)
      条件: 源端bundleName在本地已安装
      结果: finalBundleName = bundleName, 返回true
      说明: 最高优先级匹配

    步骤2_获取候选列表:
      操作: GetContinueBundle4Src(bundleName, bundleNameList)
      说明: 获取源端对应的可接续Bundle列表(跨应用接续)
      条件: 若获取失败,记录日志

    步骤3_补充源Bundle:
      操作: 再次检查源bundleName是否已安装
      条件: 若已安装,加入bundleNameList

    步骤4_候选列表验证:
      条件: bundleNameList.size() == 0
      结果: 返回false(无可接续Bundle)

    步骤5_开发者ID匹配:
      遍历: bundleNameList中的每个bundleNameItem
      验证:
        - GetAppProvisionInfo4CurrentUser(bundleNameItem)
        - appProvisionInfo.developerId == distributedBundleInfo.developerId
        - GetLocalBundleInfo(bundleNameItem)成功
      匹配成功: finalBundleName = bundleNameItem, 返回true

    步骤6_匹配失败:
      结果: 返回false

  关键验证:
    - developerId: 开发者ID匹配
    - AppProvisionInfo: 应用签名信息

  伪代码:
    bool GetFinalBundleNameInternal(BundleValidationContext& context) {
        // 步骤1: 同Bundle检查
        if (GetLocalBundleInfo(bundleName, localBundleInfo)) {
            context.finalBundleName = bundleName;
            context.localBundleInfo = localBundleInfo;
            return true;
        }

        // 步骤2: 获取候选列表
        std::vector<std::string> bundleNameList;
        GetContinueBundle4Src(bundleName, bundleNameList);

        // 步骤3: 补充源Bundle
        if (GetLocalBundleInfo(bundleName, localBundleInfo)) {
            bundleNameList.push_back(bundleName);
        }

        // 步骤4: 候选列表验证
        if (bundleNameList.empty()) {
            return false;
        }

        // 步骤5: 开发者ID匹配
        for (const auto& bundleNameItem : bundleNameList) {
            AppProvisionInfo appProvisionInfo;
            if (GetAppProvisionInfo4CurrentUser(bundleNameItem, appProvisionInfo)) {
                if (appProvisionInfo.developerId == distributedBundleInfo.developerId) {
                    if (GetLocalBundleInfo(bundleNameItem, localBundleInfo)) {
                        context.finalBundleName = bundleNameItem;
                        context.localBundleInfo = localBundleInfo;
                        return true;
                    }
                }
            }
        }

        // 步骤6: 匹配失败
        return false;
    }
```

---

## 6. AppIdentifier匹配规则

```yaml
GetFinalBundleNameOrAppIdentifierList:
  文件: dms_continue_recv_manager.cpp:438

  入口判断:
    条件: distributedBundleInfo.appIdentifierVec.size() == 0
      分支: HandleEmptyAppIdentifierVec()
      说明: appIdentifier为空,使用developerId匹配

    条件: appIdentifierVec不为空
      分支: HandleNonEmptyAppIdentifierVec()
      说明: 使用appIdentifier精确匹配

HandleEmptyAppIdentifierVec:
  功能: 处理appIdentifier为空的情况
  操作: 调用GetFinalBundleNameInternal()
  说明: 回退到developerId匹配

HandleNonEmptyAppIdentifierVec:
  功能: 处理appIdentifier不为空的情况

  步骤1_获取已安装Bundle列表:
    操作:
      - GetContinueBundle4Src(bundleName, installedBundles)
      - GetLocalBundleInfo(bundleName)
    说明: 获取本地已安装的可接续Bundle列表

  步骤2_构建appIdentifier映射:
    遍历: installedBundles中的每个installedBundle
    操作:
      - GetAppProvisionInfo4CurrentUser(installedBundle)
      - 检查appProvisionInfo.appIdentifier是否非空
    存储: sinkAppIdentifierToBundleMap[appIdentifier] = installedBundle

  步骤3_源端appIdentifier匹配:
    遍历: distributedBundleInfo.appIdentifierVec
    查找: sinkAppIdentifierToBundleMap.find(srcAppIdentifier)
    匹配成功:
      - finalBundleName = matchedBundle
      - 返回true

  步骤4_匹配失败:
    结果: 返回false

  伪代码:
    bool HandleNonEmptyAppIdentifierVec(BundleValidationContext& context) {
        // 步骤1: 获取已安装Bundle列表
        std::vector<std::string> installedBundles;
        GetContinueBundle4Src(bundleName, installedBundles);

        LocalBundleInfo localBundleInfo;
        if (GetLocalBundleInfo(bundleName, localBundleInfo)) {
            installedBundles.push_back(bundleName);
        }

        // 步骤2: 构建appIdentifier映射
        std::map<std::string, std::string> sinkAppIdentifierToBundleMap;
        for (const auto& installedBundle : installedBundles) {
            AppProvisionInfo appProvisionInfo;
            if (GetAppProvisionInfo4CurrentUser(installedBundle, appProvisionInfo)) {
                if (!appProvisionInfo.appIdentifier.empty()) {
                    sinkAppIdentifierToBundleMap[appProvisionInfo.appIdentifier] = installedBundle;
                }
            }
        }

        // 步骤3: 源端appIdentifier匹配
        for (const auto& srcAppIdentifier : distributedBundleInfo.appIdentifierVec) {
            auto it = sinkAppIdentifierToBundleMap.find(srcAppIdentifier);
            if (it != sinkAppIdentifierToBundleMap.end()) {
                context.finalBundleName = it->second;
                if (GetLocalBundleInfo(it->second, context.localBundleInfo)) {
                    return true;
                }
            }
        }

        // 步骤4: 匹配失败
        return false;
    }
```

---

## 7. 数据结构

```yaml
关键数据结构:
  DmsBundleInfo:
    bundleName: 源端Bundle名称
    developerId: 开发者ID
    appIdentifier: 应用标识
    appIdentifierVec: 应用标识列表(多应用场景)
    dmsAbilityInfos: Ability接续信息列表

  BundleValidationContext:
    finalBundleName: 最终匹配的Bundle名称
    localBundleInfo: 本地Bundle信息
    continueType: 接续类型
    abilityInfo: Ability信息
    appIdentifiers: 应用标识列表

  AppProvisionInfo:
    appIdentifier: 应用标识(关键匹配字段)
    developerId: 开发者ID

  LocalBundleInfo:
    bundleName: Bundle名称
    abilityInfos: Ability信息列表
    // 其他Bundle信息

  DistributedBundleInfo:
    bundleName: 源端Bundle名称
    developerId: 开发者ID
    appIdentifierVec: 应用标识向量
    dmsAbilityInfos: DMS Ability信息列表
```

---

## 8. 匹配优先级

```yaml
匹配优先级:
  优先级1_同Bundle:
    条件: bundleName本地已安装
    优先级: 最高
    说明: 直接使用同名Bundle
    示例: com.example.app → com.example.app

  优先级2_AppIdentifier匹配:
    条件: appIdentifierVec不为空且有匹配
    优先级: 高
    说明: 使用应用标识精确匹配
    示例: 通过应用签名精确匹配

  优先级3_开发者ID匹配:
    条件: 同开发者其他Bundle已安装
    优先级: 中
    说明: 使用developerId匹配
    示例: com.example.app1 → com.example.app2

  优先级4_匹配失败:
    条件: 无可接续Bundle
    结果: 显示推荐安装
    说明: 无法匹配,提示用户安装对应应用

优先级判断流程:
  if (bundleName本地已安装) {
      return 同Bundle匹配;
  } else if (appIdentifierVec不为空) {
      return AppIdentifier匹配;
  } else {
      return 开发者ID匹配;
  }
```

---

## 9. 关键依赖

```yaml
BMS接口依赖:
  GetLocalBundleInfo(bundleName):
    功能: 获取本地Bundle信息
    说明: 检查Bundle是否已安装
    返回: Bundle信息或失败

  GetContinueBundle4Src(bundleName):
    功能: 获取源端对应的可接续Bundle列表
    说明: 用于跨应用接续场景
    返回: Bundle名称列表

  GetAppProvisionInfo4CurrentUser(bundleName):
    功能: 获取当前用户的应用签名信息
    说明: 用于验证developerId和appIdentifier
    返回: AppProvisionInfo

  GetLocalAbilityInfo(bundleName, moduleName, abilityName):
    功能: 获取本地Ability信息
    说明: 验证Ability是否可接续
    返回: Ability信息

  GetAbilityName(networkId, bundleName, continueType):
    功能: 根据接续类型查找目标Ability
    说明: 在指定设备上查找Ability
    返回: Ability名称
```

---

## 10. 错误处理

```yaml
错误场景:
  场景1_无可接续Bundle:
    条件: 所有匹配规则均未命中
    处理: 返回false
    影响: SINK端无法接续,显示推荐安装

  场景2_Bundle未安装:
    条件: GetLocalBundleInfo失败
    处理: 继续尝试其他匹配规则
    说明: 不直接返回失败,尝试跨应用接续

  场景3_开发者ID不匹配:
    条件: developerId验证失败
    处理: 继续遍历其他候选Bundle
    说明: 可能存在多个候选Bundle

  场景4_AppIdentifier匹配失败:
    条件: appIdentifierVec中无匹配项
    处理: 返回false
    说明: 精确匹配失败

  场景5_签名信息获取失败:
    条件: GetAppProvisionInfo失败
    处理: 跳过该Bundle,继续遍历
    说明: 不影响其他Bundle匹配
```

---

## 11. 调用位置索引

```yaml
调用位置:
  主入口:
    - dms_continue_recv_manager.cpp:486 (ValidateAndPrepareBundleInfo)

  匹配核心:
    - dms_continue_recv_manager.cpp:266 (GetFinalBundleNameInternal)
    - dms_continue_recv_manager.cpp:322 (GetFinalBundleName)
    - dms_continue_recv_manager.cpp:438 (GetFinalBundleNameOrAppIdentifierList)

  分支处理:
    - dms_continue_recv_manager.cpp:369 (HandleEmptyAppIdentifierVec)
    - dms_continue_recv_manager.cpp:385 (HandleNonEmptyAppIdentifierVec)

  辅助方法:
    - dms_continue_recv_manager.cpp:304 (FindContinueType)
```

---

## 12. 使用示例

```yaml
示例1_同Bundle接续:
  源端:
    bundleName: com.example.app
    developerId: dev_12345
    appIdentifierVec: []

  SINK端状态:
    已安装: com.example.app

  匹配结果:
    finalBundleName: com.example.app
    匹配方式: 同Bundle匹配

示例2_跨Bundle接续:
  源端:
    bundleName: com.example.app.pro
    developerId: dev_12345
    appIdentifierVec: []

  SINK端状态:
    已安装:
      - com.example.app.free
      - developerId: dev_12345

  匹配结果:
    finalBundleName: com.example.app.free
    匹配方式: 开发者ID匹配

示例3_AppIdentifier匹配:
  源端:
    bundleName: com.example.app
    developerId: dev_12345
    appIdentifierVec: ["app_id_123", "app_id_456"]

  SINK端状态:
    已安装:
      - com.example.app.cn
        appIdentifier: app_id_123
      - com.example.app.global
        appIdentifier: app_id_789

  匹配结果:
    finalBundleName: com.example.app.cn
    匹配方式: AppIdentifier精确匹配
```

---

## 13. 性能优化

```yaml
优化策略:
  策略1_优先快速路径:
    说明: 同Bundle检查是O(1)操作
    位置: GetFinalBundleNameInternal步骤1
    效果: 大部分场景直接命中

  策略2_映射表缓存:
    说明: AppIdentifier映射表一次性构建
    位置: HandleNonEmptyAppIdentifierVec
    效果: 避免重复查询BMS

  策略3_提前终止:
    说明: 找到匹配后立即返回
    位置: 所有匹配循环
    效果: 减少不必要的遍历

  策略4_批量查询:
    说明: GetContinueBundle4Src一次性获取候选列表
    位置: GetFinalBundleNameInternal步骤2
    效果: 减少BMS调用次数
```

---

## 14. 安全考虑

```yaml
安全验证:
  验证1_开发者ID校验:
    目的: 防止不同开发者的应用互相接续
    实现: appProvisionInfo.developerId == distributedBundleInfo.developerId
    重要性: 高

  验证2_AppIdentifier校验:
    目的: 精确验证应用身份
    实现: appIdentifier精确匹配
    重要性: 高
    说明: 比developerId更精确

  验证3_Bundle安装验证:
    目的: 确保目标Bundle已安装
    实现: GetLocalBundleInfo成功
    重要性: 中

  验证4_签名信息验证:
    目的: 验证应用签名的合法性
    实现: GetAppProvisionInfo4CurrentUser
    重要性: 高
```

---

## 15. 相关文档

- [广播阶段流程](04_continue_flow.md#416-sink端包匹配)
- [Bundle管理交互](07_bundle_interaction.md)
- [Sink端流程](../docs/knowledge_base/05_协作模块/Sink端流程.md)