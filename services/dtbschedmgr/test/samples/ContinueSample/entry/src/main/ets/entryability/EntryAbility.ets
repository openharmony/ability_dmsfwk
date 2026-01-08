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

// [Start onContinue]
// [Start onCreate]
// [Start onNewWant]
// [Start onCreate_setContinueState]
// [Start keep_continuity]
// [Start continue_page_stack]
// [Start continue_source_exit]
import { AbilityConstant, UIAbility, Want, wantConstant } from '@kit.AbilityKit';
// [StartExclude onCreate]
// [StartExclude onNewWant]
// [StartExclude onCreate_setContinueState]
// [StartExclude keep_continuity]
// [StartExclude continue_page_stack]
// [StartExclude continue_source_exit]
// [EndExclude continue_page_stack]
import { promptAction } from '@kit.ArkUI';
// [StartExclude onContinue]
import { window } from '@kit.ArkUI';
// [EndExclude onContinue]
// [EndExclude onCreate]
// [EndExclude onNewWant]
// [EndExclude onCreate_setContinueState]
// [EndExclude keep_continuity]
// [EndExclude continue_source_exit]
export default class EntryAbility extends UIAbility {
  // [StartExclude onContinue]
  // [StartExclude keep_continuity]
  // [StartExclude continue_page_stack]
  // [StartExclude continue_source_exit]
  // [StartExclude onCreate_setContinueState]
  storage: LocalStorage = new LocalStorage();
  // [EndExclude keep_continuity]
  // [EndExclude onCreate_setContinueState]
  // [StartExclude onNewWant]
  onCreate(want: Want, launchParam: AbilityConstant.LaunchParam): void {
    // [StartExclude onCreate_setContinueState]
    // [StartExclude keep_continuity]
    if (launchParam.launchReason === AbilityConstant.LaunchReason.CONTINUATION) {
      // 将上述的保存的数据取出恢复
      let continueInput = '';
      if (want.parameters !== undefined) {
        continueInput = JSON.stringify(want.parameters.data);
        console.info(`continue input ${continueInput}`)
      }
      // [EndExclude onCreate_setContinueState]
      // [StartExclude onCreate]
      this.context.setMissionContinueState(AbilityConstant.ContinueState.INACTIVE, (result) => {
        console.info(`setMissionContinueState: ${JSON.stringify(result)}`);
      });
      // [EndExclude onCreate]
      // [StartExclude onCreate_setContinueState]
      // 触发页面恢复
      this.context.restoreWindowStage(this.storage);
    }
    // [EndExclude keep_continuity]
    // [StartExclude onCreate]
    // 迁移冷启动时，设置状态为可迁移
    this.context.setMissionContinueState(AbilityConstant.ContinueState.ACTIVE, (result) => {
      console.info(`setMissionContinueState: ${JSON.stringify(result)}`);
    });
    // [EndExclude onCreate]
    // [EndExclude onCreate_setContinueState]
  }

  // [StartExclude onCreate]
  // [EndExclude onNewWant]
  // [StartExclude onCreate_setContinueState]
  onNewWant(want: Want, launchParam: AbilityConstant.LaunchParam): void {
    // [StartExclude keep_continuity]
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
    // [EndExclude keep_continuity]
    // [StartExclude onNewWant]
    // 迁移热启动时，设置状态为可迁移
    if (launchParam.launchReason === AbilityConstant.LaunchReason.CONTINUATION) {
      this.context.setMissionContinueState(AbilityConstant.ContinueState.ACTIVE, (result) => {
        console.info('setMissionContinueState ACTIVE result: ', JSON.stringify(result));
      });
    }
    // [EndExclude onNewWant]
  }

  // [StartExclude keep_continuity]
  // [StartExclude onNewWant]
  onDestroy(): void {
    console.info('testTag', '%{public}s', 'Ability onDestroy');
  }

  onWindowStageCreate(windowStage: window.WindowStage): void {
    // Main window is created, set main page for this ability
    console.info('testTag', '%{public}s', 'Ability onWindowStageCreate');

    windowStage.loadContent('pages/Index', (err) => {
      if (err.code) {
        console.error('testTag', 'Failed to load the content. Cause: %{public}s', JSON.stringify(err));
        return;
      }
      console.info('testTag', 'Succeeded in loading the content.');
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

  // [EndExclude onContinue]
  // [EndExclude continue_page_stack]
  // [EndExclude continue_source_exit]
  onContinue(wantParam: Record<string, Object>) {
    // [StartExclude continue_page_stack]
    // [StartExclude continue_source_exit]
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
    // [EndExclude continue_page_stack]
    // [EndExclude continue_source_exit]
    // [StartExclude onContinue]
    console.info(`onContinue version = ${wantParam.version}, targetDevice: ${wantParam.targetDevice}`);
    // [StartExclude continue_source_exit]
    wantParam[wantConstant.Params.SUPPORT_CONTINUE_PAGE_STACK_KEY] = false;
    // [EndExclude continue_source_exit]
    // [StartExclude continue_page_stack]
    wantParam[wantConstant.Params.SUPPORT_CONTINUE_SOURCE_EXIT_KEY] = false;
    // [EndExclude continue_page_stack]
    // [EndExclude onContinue]
    return AbilityConstant.OnContinueResult.AGREE;
  }

  // [StartExclude continue_source_exit]
  // [StartExclude onContinue]
  onWindowStageRestore(windowStage: window.WindowStage) {
    // 若不需要自动迁移页面栈信息，则需要在此处设置应用迁移后进入的页面
    windowStage.loadContent('continue/PageName', (err, data) => {
      if (err.code) {
        console.info('Failed to load the content. Cause: %{public}s', JSON.stringify(err) ?? '');
        return;
      }
      console.info('Succeeded in loading the content. Data: %{public}s', JSON.stringify(data) ?? '');
    });
  }
  // [EndExclude onContinue]
  // [EndExclude onCreate]
  // [EndExclude onNewWant]
  // [EndExclude onCreate_setContinueState]
  // [EndExclude keep_continuity]
  // [EndExclude continue_source_exit]
}
// [End onContinue]
// [End onCreate]
// [End onNewWant]
// [End onCreate_setContinueState]
// [End keep_continuity]
// [End continue_page_stack]
// [End continue_source_exit]