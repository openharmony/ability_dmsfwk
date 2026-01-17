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
import { AbilityConstant, UIAbility, Want } from '@kit.AbilityKit';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { promptAction, window } from '@kit.ArkUI';

const DOMAIN = 0x0000;

export default class Ability_deviceB extends UIAbility {
  storage: LocalStorage = new LocalStorage();

  onCreate(want: Want, launchParam: AbilityConstant.LaunchParam): void {
    if (launchParam.launchReason === AbilityConstant.LaunchReason.CONTINUATION) {
      // 将上述的保存的数据取出恢复
      let continueInput = '';
      if (want.parameters !== undefined) {
        continueInput = JSON.stringify(want.parameters.data);
        console.info(`continue input ${continueInput}`)
      }
      // 触发页面恢复
      this.context.restoreWindowStage(this.storage);
    }
  }

  onNewWant(want: Want, launchParam: AbilityConstant.LaunchParam): void {
    console.info(`EntryAbility onNewWant ${AbilityConstant.LaunchReason.CONTINUATION}`)
    if (launchParam.launchReason === AbilityConstant.LaunchReason.CONTINUATION) {
      // 将上述的保存的数据取出恢复
      let continueInput = '';
      if (want.parameters !== undefined) {
        continueInput = JSON.stringify(want.parameters.data);
        console.info(`continue input ${continueInput}`);
      }
      this.context.restoreWindowStage(this.storage);
    }
  }

  onDestroy(): void {
    hilog.info(DOMAIN, 'testTag', '%{public}s', 'Ability onDestroy');
  }

  onWindowStageCreate(windowStage: window.WindowStage): void {
    // Main window is created, set main page for this ability
    hilog.info(DOMAIN, 'testTag', '%{public}s', 'Ability onWindowStageCreate');

    windowStage.loadContent('pages/Index', (err) => {
      if (err.code) {
        hilog.error(DOMAIN, 'testTag', 'Failed to load the content. Cause: %{public}s', JSON.stringify(err));
        return;
      }
      hilog.info(DOMAIN, 'testTag', 'Succeeded in loading the content.');
    });
  }

  onWindowStageDestroy(): void {
    // Main window is destroyed, release UI related resources
    hilog.info(DOMAIN, 'testTag', '%{public}s', 'Ability onWindowStageDestroy');
  }

  onForeground(): void {
    // Ability has brought to foreground
    hilog.info(DOMAIN, 'testTag', '%{public}s', 'Ability onForeground');
  }

  onBackground(): void {
    // Ability has back to background
    hilog.info(DOMAIN, 'testTag', '%{public}s', 'Ability onBackground');
  }

  onContinue(wantParam: Record<string, Object>) {
    const targetVersion = wantParam.version; // 获取迁移对端应用的版本号
    // 应用可根据源端版本号设置支持接续的最小兼容版本号，源端版本号可从app.json5文件中的versionCode字段获取；防止目标端版本号过低导致不兼容。
    const versionThreshold: number = 0; // 替换为应用自己支持兼容的最小版本号
    // 兼容性校验
    if (targetVersion < versionThreshold) {
      // 建议在校验版本兼容性失败后，提示用户拒绝迁移的原因
      promptAction.showToast({
        message: '目标端应用版本号过低，不支持接续，请您升级应用版本后再试',
        duration: 2000
      })
      // 在兼容性校验不通过时返回MISMATCH
      return AbilityConstant.OnContinueResult.MISMATCH;
    }
    console.info(`onContinue version = ${wantParam.version}, targetDevice: ${wantParam.targetDevice}`)
    // 迁移数据保存
    const continueInput = '迁移的数据';
    if (continueInput) {
      // 将要迁移的数据保存在wantParam的自定义字段（如：data）中;
      wantParam['data'] = continueInput;
    }
    return AbilityConstant.OnContinueResult.AGREE;
  }
}
