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

// [Start dataObject_multi_asset]
// 导入模块
import { distributedDataObject, commonType } from '@kit.ArkData';
import { UIAbility, AbilityConstant, Want } from '@kit.AbilityKit';
// [StartExclude dataObject_multi_asset]
import { fileIo, fileUri } from '@kit.CoreFileKit';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { BusinessError } from '@ohos.base';
import { window } from '@kit.ArkUI';

const TAG: string = '[MigrationAbility]';
const DOMAIN_NUMBER: number = 0xFF00;
// [EndExclude dataObject_multi_asset]

// 数据对象定义
class SourceObject {
  name: string | undefined
  assets: Object | undefined  // 分布式数据对象的中添加一个Object属性

  constructor(name: string | undefined, assets: Object | undefined) {
    this.name = name
    this.assets = assets;
  }
}

export default class MigrationAbility_multi_asset extends UIAbility {
  d_object?: distributedDataObject.DataObject;
  // [StartExclude dataObject_multi_asset]
  contentStorage?: LocalStorage;
  // [EndExclude dataObject_multi_asset]

  // 该函数用于将资产数组转为Record
  GetAssetsWrapper(assets: commonType.Assets): Record<string, commonType.Asset> {
    let wrapper: Record<string, commonType.Asset> = {}
    let num: number = assets.length;
    for (let i: number = 0; i < num; i++) {
      wrapper[`asset${i}`] = assets[i];
    }
    return wrapper;
  }

  async onContinue(wantParam: Record<string, Object>): Promise<AbilityConstant.OnContinueResult> {
    // [StartExclude dataObject_multi_asset]
    // 1. 将资产写入分布式文件目录下
    let distributedDir: string = this.context.distributedFilesDir;  // 获取分布式文件目录路径
    let fileName: string = '/test.txt';                        // 文件名
    let filePath: string = distributedDir + fileName;          // 文件路径

    let fileName2: string = '/test2.txt';                        // 文件名
    let filePath2: string = distributedDir + fileName2;          // 文件路径

    try {
      // 在分布式目录下创建文件
      let file = fileIo.openSync(filePath, fileIo.OpenMode.READ_WRITE | fileIo.OpenMode.CREATE);
      hilog.info(DOMAIN_NUMBER, TAG, 'Create file success.');
      // 向文件中写入内容（若资产为图片，可将图片转换为buffer后写入）
      fileIo.writeSync(file.fd, '[Sample] Insert file content here.');
      // 关闭文件
      fileIo.closeSync(file.fd);

      // 在分布式目录下创建文件2
      let file2 = fileIo.openSync(filePath2, fileIo.OpenMode.READ_WRITE | fileIo.OpenMode.CREATE);
      hilog.info(DOMAIN_NUMBER, TAG, 'Create file success.');
      // 向文件2中写入内容（若资产为图片，可将图片转换为buffer后写入）
      fileIo.writeSync(file2.fd, '[Sample] Insert file2 content here.');
      // 关闭文件2
      fileIo.closeSync(file2.fd);
    } catch (error) {
      let err: BusinessError = error as BusinessError;
      hilog.error(DOMAIN_NUMBER, TAG, `Failed to openSync / writeSync / closeSync 2. Code: ${err.code}, message: ${err.message}`);
    }

    // 2. 使用分布式文件目录下的文件创建资产对象
    let distributedUri: string = fileUri.getUriFromPath(filePath); // 获取分布式文件Uri
    let distributedUri2: string = fileUri.getUriFromPath(filePath2);

    // 获取文件参数
    let ctime: string = '';
    let mtime: string = '';
    let size: string = '';
    await fileIo.stat(filePath).then((stat: fileIo.Stat) => {
      ctime = stat.ctime.toString();  // 创建时间
      mtime = stat.mtime.toString();  // 修改时间
      size = stat.size.toString();    // 文件大小
    })
    let ctime2: string = '';
    let mtime2: string = '';
    let size2: string = '';
    await fileIo.stat(filePath2).then((stat: fileIo.Stat) => {
      ctime2 = stat.ctime.toString();  // 创建时间
      mtime2 = stat.mtime.toString();  // 修改时间
      size2 = stat.size.toString();    // 文件大小
    })
    // [EndExclude dataObject_multi_asset]

    // 创建多个资产对象
    let attachment1: commonType.Asset = {
      // [StartExclude dataObject_multi_asset]
      name: fileName,
      uri: distributedUri,
      path: filePath,
      createTime: ctime,
      modifyTime: mtime,
      size: size,
      // [EndExclude dataObject_multi_asset]
    }

    let attachment2: commonType.Asset = {
      // [StartExclude dataObject_multi_asset]
      name: fileName2,
      uri: distributedUri2,
      path: filePath2,
      createTime: ctime2,
      modifyTime: mtime2,
      size: size2,
      // [EndExclude dataObject_multi_asset]
    }

    // 将资产对象插入资产数组
    let assets: commonType.Assets = [];
    assets.push(attachment1);
    assets.push(attachment2);

    // 将资产数组转为Record Object，并用于创建分布式数据对象
    let assetsWrapper: Object = this.GetAssetsWrapper(assets);
    let source: SourceObject = new SourceObject('jack', assetsWrapper);
    this.d_object = distributedDataObject.create(this.context, source);

    // [StartExclude dataObject_multi_asset]
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
    // [EndExclude dataObject_multi_asset]
  }

  // [StartExclude dataObject_multi_asset]
  handleDistributedData(want: Want) {
    // ...
    // 创建一个各属性为空的资产对象
    let attachment1: commonType.Asset = {
      name: '',
      uri: '',
      path: '',
      createTime: '',
      modifyTime: '',
      size: '',
    }
    let attachment2: commonType.Asset = {
      name: '',
      uri: '',
      path: '',
      createTime: '',
      modifyTime: '',
      size: '',
    }

    let assets: commonType.Assets = [];
    assets.push(attachment1);
    assets.push(attachment2);
    let assetsWrapper: Object = this.GetAssetsWrapper(assets);

    // 读取分布式数据对象组网id
    let dataSessionId = '';
    if (want.parameters !== undefined) {
      dataSessionId = want.parameters.dataSessionId as string;
    }

    // 使用该空资产对象创建分布式数据对象，其余基础属性可以直接使用undefined
    let source: SourceObject = new SourceObject(undefined, undefined);
    this.d_object = distributedDataObject.create(this.context, source);

    this.d_object.on('status', (sessionId: string, networkId: string, status: 'online' | 'offline' | 'restored') => {
      if (status === 'restored') {
        // 收到监听的restored回调，表示分布式资产对象同步完成
        if (this.d_object) {
          hilog.info(DOMAIN_NUMBER, TAG, 'restored attachment:' + JSON.stringify(this.d_object['assets']));
          let sourceObjMultiAsset: SourceObject =
            new SourceObject(this.d_object['name'], this.d_object['assets']);
          AppStorage.setOrCreate<SourceObject>('sourceObjMultiAsset', sourceObjMultiAsset);
        }
      }
    });

    // 激活分布式数据对象
    this.d_object.setSessionId(dataSessionId);
  }

  onCreate(want: Want, launchParam: AbilityConstant.LaunchParam): void {
    if (launchParam.launchReason === AbilityConstant.LaunchReason.CONTINUATION) {
      console.info(`EntryAbility onCreate ${AbilityConstant.LaunchReason.CONTINUATION}`)
      this.context.restoreWindowStage(this.contentStorage);
      // 调用封装好的分布式数据对象处理函数
      this.handleDistributedData(want);
    }
  }

  onNewWant(want: Want, launchParam: AbilityConstant.LaunchParam): void {
    if (launchParam.launchReason === AbilityConstant.LaunchReason.CONTINUATION) {
      if (want.parameters !== undefined) {
        console.info(`EntryAbility onNewWant ${AbilityConstant.LaunchReason.CONTINUATION}`)
        this.context.restoreWindowStage(this.contentStorage);
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

    windowStage.loadContent('continue/MultiAsset', (err) => {
      if (err.code) {
        console.error('testTag', 'Failed to load the content. Cause: %{public}s', JSON.stringify(err));
        return;
      }
      console.info('testTag', 'Succeeded in loading the content.');
    });
  }

  onWindowStageRestore(windowStage: window.WindowStage) {
    // 若不需要自动迁移页面栈信息，则需要在此处设置应用迁移后进入的页面
    windowStage.loadContent('continue/MultiAsset', (err, data) => {
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
  // [EndExclude dataObject_multi_asset]
}
// [End dataObject_multi_asset]
