/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// [Start dataObject_onContinue]
// [Start dataObject_onCreate_onNewWant]
import { UIAbility, AbilityConstant, Want } from '@kit.AbilityKit';
import { distributedDataObject } from '@kit.ArkData';
// [StartExclude dataObject_onCreate_onNewWant]
import { BusinessError } from '@kit.BasicServicesKit';
// [EndExclude dataObject_onCreate_onNewWant]
import { hilog } from '@kit.PerformanceAnalysisKit';
// [StartExclude dataObject_onContinue]
// [StartExclude dataObject_onCreate_onNewWant]
import { window } from '@kit.ArkUI';
// [EndExclude dataObject_onContinue]
// [EndExclude dataObject_onCreate_onNewWant]

const TAG: string = '[MigrationAbility]';
const DOMAIN_NUMBER: number = 0xFF00;

// [StartExclude dataObject_onContinue]
// 示例数据对象定义与上同
// [EndExclude dataObject_onContinue]
// [StartExclude dataObject_onCreate_onNewWant]
// 业务数据定义
class ParentObject {
  mother: string
  father: string

  constructor(mother: string, father: string) {
    this.mother = mother
    this.father = father
  }
}

// 支持字符、数字、布尔值、对象的传递
class SourceObject {
  name: string | undefined
  age: number | undefined
  isVis: boolean | undefined
  parent: ParentObject | undefined

  constructor(name: string | undefined, age: number | undefined, isVis: boolean | undefined, parent: ParentObject | undefined) {
    this.name = name
    this.age = age
    this.isVis = isVis
    this.parent = parent
  }
}
// [EndExclude dataObject_onCreate_onNewWant]

export default class MigrationAbility extends UIAbility {
  d_object?: distributedDataObject.DataObject;
  // [StartExclude dataObject_onContinue]
  // [StartExclude dataObject_onCreate_onNewWant]
  contentStorage?: LocalStorage;
  // [EndExclude dataObject_onContinue]
  // [EndExclude dataObject_onCreate_onNewWant]

  // [StartExclude dataObject_onContinue]
  onCreate(want: Want, launchParam: AbilityConstant.LaunchParam): void {
    if (launchParam.launchReason === AbilityConstant.LaunchReason.CONTINUATION) {
      // [StartExclude dataObject_onCreate_onNewWant]
      console.info(`EntryAbility onCreate ${AbilityConstant.LaunchReason.CONTINUATION}`)
      this.context.restoreWindowStage(this.contentStorage);
      // [EndExclude dataObject_onCreate_onNewWant]
      // 调用封装好的分布式数据对象处理函数
      this.handleDistributedData(want);
    }
  }

  onNewWant(want: Want, launchParam: AbilityConstant.LaunchParam): void {
    if (launchParam.launchReason === AbilityConstant.LaunchReason.CONTINUATION) {
      if (want.parameters !== undefined) {
        // [StartExclude dataObject_onCreate_onNewWant]
        console.info(`EntryAbility onNewWant ${AbilityConstant.LaunchReason.CONTINUATION}`)
        this.context.restoreWindowStage(this.contentStorage);
        // [EndExclude dataObject_onCreate_onNewWant]
        // 调用封装好的分布式数据对象处理函数
        this.handleDistributedData(want);
      }
    }
  }

  handleDistributedData(want: Want) {
    // 创建空的分布式数据对象
    let remoteSource: SourceObject = new SourceObject(undefined, undefined, undefined, undefined);
    this.d_object = distributedDataObject.create(this.context, remoteSource);

    // 读取分布式数据对象组网id
    let dataSessionId = '';
    if (want.parameters !== undefined) {
      dataSessionId = want.parameters.dataSessionId as string;
    }
    // 添加数据变更监听
    this.d_object.on('status', (sessionId: string, networkId: string, status: 'online' | 'offline' | 'restored') => {
      hilog.info(DOMAIN_NUMBER, TAG, 'status changed ' + sessionId + ' ' + status + ' ' + networkId);
      if (status === 'restored') {
        if (this.d_object) {
          // 收到迁移恢复的状态时，可以从分布式数据对象中读取数据
          hilog.info(DOMAIN_NUMBER, TAG, 'restored name:' + this.d_object['name']);
          hilog.info(DOMAIN_NUMBER, TAG, 'restored parents:' + JSON.stringify(this.d_object['parent']));
          // [StartExclude dataObject_onCreate_onNewWant]
          let sourceObj: SourceObject = new SourceObject(this.d_object['name'], this.d_object['age'], this.d_object['isVis'], this.d_object['parent']);
          AppStorage.setOrCreate<SourceObject>('sourceObj', sourceObj);
          // [EndExclude dataObject_onCreate_onNewWant]
        }
      }
    });
    // 激活分布式数据对象
    this.d_object.setSessionId(dataSessionId);
  }
  // [EndExclude dataObject_onContinue]

  // [StartExclude dataObject_onCreate_onNewWant]
  async onContinue(wantParam: Record<string, Object>): Promise<AbilityConstant.OnContinueResult> {
    // ...
    let parentSource: ParentObject = new ParentObject('jack mom', 'jack Dad');
    let source: SourceObject = new SourceObject('jack', 18, false, parentSource);

    // 创建分布式数据对象
    this.d_object = distributedDataObject.create(this.context, source);

    // 生成数据对象组网id，激活分布式数据对象
    let dataSessionId: string = distributedDataObject.genSessionId();
    this.d_object.setSessionId(dataSessionId);

    // 将组网id存在want中传递到对端
    wantParam['dataSessionId'] = dataSessionId;

    // 数据对象持久化，确保迁移后即使应用退出，对端依然能够恢复数据对象
    // 从wantParam.targetDevice中获取到对端设备的networkId作为入参
    await this.d_object.save(wantParam.targetDevice as string).then((result:
      distributedDataObject.SaveSuccessResponse) => {
      hilog.info(DOMAIN_NUMBER, TAG, `Succeeded in saving. SessionId: ${result.sessionId},
        version:${result.version}, deviceId:${result.deviceId}`);
    }).catch((err: BusinessError) => {
      hilog.error(DOMAIN_NUMBER, TAG, 'Failed to save. Error: ', JSON.stringify(err) ?? '');
    });
    // [StartExclude dataObject_onContinue]
    return AbilityConstant.OnContinueResult.AGREE;
    // [EndExclude dataObject_onContinue]
  }
  // [EndExclude dataObject_onCreate_onNewWant]

  // [StartExclude dataObject_onContinue]
  // [StartExclude dataObject_onCreate_onNewWant]
  onDestroy(): void {
    console.info('testTag', '%{public}s', 'Ability onDestroy');
  }

  onWindowStageCreate(windowStage: window.WindowStage): void {
    // Main window is created, set main page for this ability
    console.info('testTag', '%{public}s', 'Ability onWindowStageCreate');

    windowStage.loadContent('continue/DataObj', (err) => {
      if (err.code) {
        console.error('testTag', 'Failed to load the content. Cause: %{public}s', JSON.stringify(err));
        return;
      }
      console.info('testTag', 'Succeeded in loading the content.');
    });
  }

  onWindowStageRestore(windowStage: window.WindowStage) {
    // 若不需要自动迁移页面栈信息，则需要在此处设置应用迁移后进入的页面
    windowStage.loadContent('continue/DataObj', (err, data) => {
      if (err.code) {
        console.info('Failed to load the content. Cause: %{public}s', JSON.stringify(err) ?? '');
        return;
      }
      console.info('Succeeded in loading the content. Data: %{public}s', JSON.stringify(data) ?? '');
    });
  }

  onWindowStageDestroy(): void {
    // Main window is destroyed, release UI related resources
    console.info('testTag', '%{public}s', 'Ability onWindowStageDestroy');
  }

  onForeground(): void {
    // Ability has brought to foreground
    console.info('testTag', '%{public}s', 'Ability onForeground');
  }

  onBackground(): void {
    // Ability has back to background
    console.info('testTag', '%{public}s', 'Ability onBackground');
  }
  // [EndExclude dataObject_onContinue]
  // [EndExclude dataObject_onCreate_onNewWant]
}
// [End dataObject_onContinue]
// [End dataObject_onCreate_onNewWant]