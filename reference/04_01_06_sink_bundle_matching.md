# 4.1.6 SINK端包匹配规则

> **约束声明**: 本章节为接续业务整体约束，优先级最高。大模型读取知识库时应优先获取本章节内容。

## 4.1.6.1 概述

```yaml
场景分类:
  普通场景: 默认匹配流程
  引导安装场景: 编译宏SUPPORT_CONTINUATION_RECOMMEND_INSTALLATION隔离

关键概念:
  AppIdentifierList: 应用市场配置的可接续应用appid列表
    作用: 只有列表中的app可作为sink端应用
    优先级: 按列表顺序决定sink端应用选择优先级

  continueBundleName: module.json5配置的包名列表
    作用: 表示自身可作为列表中应用的sink端应用
```

---

## 4.1.6.2 普通场景包名匹配规则

```yaml
场景1_源端AppIdentifierList为空:
  分支1.1_有同包名应用:
    结果: 选择同包名应用作为sink端

  分支1.2_没有同包名应用:
    步骤1: GetContinueBundle4Src(bundleName)查询sink端候选应用列表
    步骤2: 遍历列表,找第一个developerId相同的应用
    结果: 选择该应用作为sink端

场景2_源端AppIdentifierList不为空:
  步骤1: GetContinueBundle4Src(bundleName)查询sink端候选应用列表
  步骤2: 将同包名应用添加到列表末尾
  步骤3: sink端已安装应用中,选择AppIdentifierList中最靠前的应用
  结果: 该应用作为最终的sink端
```

---

## 4.1.6.3 引导安装场景包名匹配规则

```yaml
关键变量:
  finalAppIdentifierVec: 通知桌面的应用列表(值为源端AppIdentifierList或空)
  推荐安装开关: 控制是否通知桌面显示接续图标

场景1_源端AppIdentifierList为空:
  结果: finalAppIdentifierVec = 空

  分支1.1_sink端应用获取成功:
    规则: 与普通场景相同(详见4.1.6.2)
    校验: 需校验推荐安装开关

  分支1.2_sink端应用获取失败:
    规则: 使用普通场景规则失败
    校验: 不需校验推荐安装开关

场景2_源端AppIdentifierList不为空:
  步骤1: GetContinueBundle4Src(bundleName)查询sink端候选应用列表
  步骤2: 若sink端安装了同包名应用,则追加到列表
  步骤3: sink端应用列表中,选择AppIdentifierList最靠前的应用作为最终sink端

  分支2.1_最终sink端是AppIdentifierList第一个:
    结果: finalAppIdentifierVec = 空
    校验: 不需校验推荐安装开关

  分支1.5_推荐安装开关关闭+sink端存在+不是AppIdentifierList第一个:
    结果: finalAppIdentifierVec = 空
    校验: 需校验推荐安装开关

  分支1.6_其他场景:
    结果: finalAppIdentifierVec = 源端AppIdentifierList
    校验: 需校验推荐安装开关
```

### 推荐安装开关校验规则

```yaml
校验触发条件:
  场景: 需校验推荐安装开关的场景

开关关闭处理:
  结果: 不通知桌面任何信息(不弹接续图标、不可接续)

不可接续处理:
  条件: IsBundleContinuable返回false
  结果: 不通知桌面任何信息(不弹接续图标、不可接续)
```

---

## 相关文档

- [接续业务流程](04_continue_flow.md) - 章节4 接续完整流程
- [接续规则说明](03_continue_rules.md) - 章节3 接续规则
- [Bundle管理交互](07_bundle_interaction.md) - 章节7 BMS接口交互