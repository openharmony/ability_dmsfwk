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

// [Start dataObject_asset_source]
// [Start dataObject_asset_sink]
// 导入模块
import { UIAbility, AbilityConstant, Want } from '@kit.AbilityKit';
import { distributedDataObject, commonType } from '@kit.ArkData';
import { fileIo, fileUri } from '@kit.CoreFileKit';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { BusinessError } from '@ohos.base';
// [StartExclude dataObject_asset_source]
import { window } from '@kit.ArkUI';
// [EndExclude dataObject_asset_source]

const TAG: string = '[MigrationAbility]';
const DOMAIN_NUMBER: number = 0xFF00;

// [StartExclude dataObject_asset_sink]
// 数据对象定义
class ParentObject {
  mother: string
  father: string

  constructor(mother: string, father: string) {
    this.mother = mother
    this.father = father
  }
}

class SourceObject {
  name: string | undefined
  age: number | undefined
  isVis: boolean | undefined
  parent: ParentObject | undefined
  attachment: commonType.Asset | undefined  // 新增资产属性

  constructor(name: string | undefined, age: number | undefined, isVis: boolean | undefined,
    parent: ParentObject | undefined, attachment: commonType.Asset | undefined) {
    this.name = name
    this.age = age
    this.isVis = isVis
    this.parent = parent
    this.attachment = attachment;
  }
}
// [EndExclude dataObject_asset_sink]

export default class MigrationAbility_asset extends UIAbility {
  d_object?: distributedDataObject.DataObject;
  // [StartExclude dataObject_asset_source]
  // [StartExclude dataObject_asset_sink]
  contentStorage?: LocalStorage;
  // [EndExclude dataObject_asset_sink]

  handleDistributedData(want: Want) {
    // ...
    // 创建一个各属性为空的资产对象
    let attachment: commonType.Asset = {
      name: '',
      uri: '',
      path: '',
      createTime: '',
      modifyTime: '',
      size: '',
    }

    // [StartExclude dataObject_asset_sink]
    // 读取分布式数据对象组网id
    let dataSessionId = '';
    if (want.parameters !== undefined) {
      dataSessionId = want.parameters.dataSessionId as string;
    }
    // [EndExclude dataObject_asset_sink]

    // 使用该空资产对象创建分布式数据对象，其余基础属性可以直接使用undefined
    let source: SourceObject = new SourceObject(undefined, undefined, undefined, undefined, attachment);
    this.d_object = distributedDataObject.create(this.context, source);

    this.d_object.on('status', (sessionId: string, networkId: string, status: 'online' | 'offline' | 'restored') => {
      if (status === 'restored') {
        // 收到监听的restored回调，表示分布式资产对象同步完成
        if (this.d_object) {
          hilog.info(DOMAIN_NUMBER, TAG, 'restored attachment:' + JSON.stringify(this.d_object['attachment']));
          // [StartExclude dataObject_asset_sink]
          let sourceObjAsset: SourceObject =
            new SourceObject(this.d_object['name'], this.d_object['age'], this.d_object['isVis'],
              this.d_object['parent'], this.d_object['attachment']);
          AppStorage.setOrCreate<SourceObject>('sourceObjAsset', sourceObjAsset);
          // [EndExclude dataObject_asset_sink]
        }
      }
    });

    // [StartExclude dataObject_asset_sink]
    // 激活分布式数据对象
    this.d_object.setSessionId(dataSessionId);
    // [EndExclude dataObject_asset_sink]
  }
  // [EndExclude dataObject_asset_source]

  // [StartExclude dataObject_asset_sink]
  async onContinue(wantParam: Record<string, Object>): Promise<AbilityConstant.OnContinueResult> {
    // ...

    // 1. 将资产写入分布式文件目录下
    let distributedDir: string = this.context.distributedFilesDir;  // 获取分布式文件目录路径
    let fileName: string = '/test.txt';                        // 文件名
    let filePath: string = distributedDir + fileName;          // 文件路径

    try {
      // 在分布式目录下创建文件
      let file = fileIo.openSync(filePath, fileIo.OpenMode.READ_WRITE | fileIo.OpenMode.CREATE);
      hilog.info(DOMAIN_NUMBER, TAG, 'Create file success.');
      // 向文件中写入内容（若资产为图片，可将图片转换为buffer后写入）
      fileIo.writeSync(file.fd, '[Sample] Insert file content here.');
      // 关闭文件
      fileIo.closeSync(file.fd);
    } catch (error) {
      let err: BusinessError = error as BusinessError;
      hilog.error(DOMAIN_NUMBER, TAG, `Failed to openSync / writeSync / closeSync. Code: ${err.code}, message: ${err.message}`);
    }

    // 2. 使用分布式文件目录下的文件创建资产对象
    let distributedUri: string = fileUri.getUriFromPath(filePath); // 获取分布式文件Uri

    // 获取文件参数
    let ctime: string = '';
    let mtime: string = '';
    let size: string = '';
    await fileIo.stat(filePath).then((stat: fileIo.Stat) => {
      ctime = stat.ctime.toString();  // 创建时间
      mtime = stat.mtime.toString();  // 修改时间
      size = stat.size.toString();    // 文件大小
    })

    // 创建资产对象
    let attachment: commonType.Asset = {
      name: fileName,
      uri: distributedUri,
      path: filePath,
      createTime: ctime,
      modifyTime: mtime,
      size: size,
    }

    // 3. 将资产对象作为分布式数据对象的根属性，创建分布式数据对象
    let parentSource: ParentObject = new ParentObject('jack mom', 'jack Dad');
    let source: SourceObject = new SourceObject('jack', 18, false, parentSource, attachment);
    this.d_object = distributedDataObject.create(this.context, source);

    // 生成组网id，激活分布式数据对象，save持久化保存
    // [StartExclude dataObject_asset_source]
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
    return AbilityConstant.OnContinueResult.AGREE;
    // [EndExclude dataObject_asset_source]
  }

  // [StartExclude dataObject_asset_source]
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
  // [EndExclude dataObject_asset_source]
  // [EndExclude dataObject_asset_sink]
}
// [End dataObject_asset_source]
// [End dataObject_asset_sink]
