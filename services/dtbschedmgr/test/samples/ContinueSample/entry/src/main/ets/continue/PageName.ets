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

// [Start onPageShow_setContinueState]
// [Start component_setContinueState]
import { AbilityConstant, common } from '@kit.AbilityKit';
// [StartExclude onPageShow_setContinueState]
// [StartExclude component_setContinueState]
import CommonConstants from '../commom/Constants';
// [EndExclude onPageShow_setContinueState]
// [EndExclude component_setContinueState]

@Entry
@Component
struct PageName {
  private context = getContext(this) as common.UIAbilityContext;

  // [StartExclude component_setContinueState]
  onPageShow() {
    // 进入该页面时，将应用设置为可迁移状态
    this.context.setMissionContinueState(AbilityConstant.ContinueState.ACTIVE, (result) => {
      console.info('setMissionContinueState ACTIVE result: ', JSON.stringify(result));
    });
  }

  // [EndExclude component_setContinueState]
  build() {
    // [StartExclude onPageShow_setContinueState]
    // [StartExclude component_setContinueState]
    Column() {
      // [EndExclude component_setContinueState]

      Button($r('app.string.setMissionContinueState_active')).onClick(() => {
        //点击该按钮时，将应用设置为可迁移状态
        this.context.setMissionContinueState(AbilityConstant.ContinueState.ACTIVE, (result) => {
          console.info('setMissionContinueState ACTIVE result: ', JSON.stringify(result));
        });
      })
        // [StartExclude component_setContinueState]
        .margin({ top: CommonConstants.BUTTON_MARGIN_TOP })
        // [EndExclude component_setContinueState]

      // [StartExclude component_setContinueState]
      Button($r('app.string.setMissionContinueState_inactive')).onClick(() => {
        //点击该按钮时，将应用设置为不可迁移状态
        this.context.setMissionContinueState(AbilityConstant.ContinueState.INACTIVE, (result) => {
          console.info('setMissionContinueState INACTIVE result: ', JSON.stringify(result));
        });
      })
        .margin(CommonConstants.BUTTON_MARGIN)
      // [EndExclude component_setContinueState]
    }
    // [StartExclude component_setContinueState]
    .width('100%')
    .height('100%')
    // [EndExclude onPageShow_setContinueState]
  }
  // [EndExclude component_setContinueState]
}

// [End onPageShow_setContinueState]
// [End component_setContinueState]