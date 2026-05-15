# 3. 接续规则说明

> **约束声明**: 本章节为接续业务整体约束，优先级最高。大模型读取知识库时应优先获取本章节内容。

## 3.1 应用标识

```yaml
三元组(bundleName, continueType, abilityName):
  说明: 接续核心标识，用于确定目标应用和Ability
  来源: module.json5配置文件

默认值规则:
  条件: 未配置continueType
  结果: continueType = abilityName

辅助标识:
  appId: 应用市场签发唯一ID
  developerId: 开发者ID(来源: AppProvisionInfo)
  moduleName: 模块名称(来源: module.json5)
  appIdentifier: 应用标识(来源: AppProvisionInfo)
```

---

## 3.2 接续规则

```yaml
前置条件(必须满足其一):
  条件1: bundleName相同 + appId相同
  条件2: developerId相同 + bundleName不同
  说明: 不满足前置条件则不可接续

接续规则矩阵:
  同module场景:
    同continueType + 同abilityName → 可接续
    同continueType + 异abilityName → 可接续
    异continueType + 同abilityName → 可接续
    异continueType + 异abilityName → 不可接续

  异module场景:
    同continueType + 同abilityName → 可接续
    同continueType + 异abilityName → 可接续
    异continueType + 同abilityName → 不可接续
    异continueType + 异abilityName → 不可接续

规则总结:
  可接续: 同continueType(任意abilityName) 或 异continueType+同abilityName+同module
  不可接续: 异continueType+异abilityName 或 异module+异continueType
```

---

## 3.3 规则判定表

```
前置条件: (同包名+同appId) 或 (同developerId+异包名)

| module | continueType | abilityName | 结果       |
|--------|--------------|-------------|------------|
| 同     | 同           | 同          | 可接续     |
| 同     | 同           | 异          | 可接续     |
| 同     | 异           | 同          | 可接续     |
| 同     | 异           | 异          | 不可接续   |
| 异     | 同           | 同          | 可接续     |
| 异     | 同           | 异          | 可接续     |
| 异     | 异           | 同          | 不可接续   |
| 异     | 异           | 异          | 不可接续   |
```