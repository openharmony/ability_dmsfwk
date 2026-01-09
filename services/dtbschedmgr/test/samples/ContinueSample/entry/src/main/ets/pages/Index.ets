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
import { common, Want } from '@kit.AbilityKit';
import { router } from '@kit.ArkUI';
import CommonConstants from '../commom/Constants';
import logger from '../commom/Logger';

const TAG: string = '[Index]';

@Entry
@Component
struct Index {
  private context = getContext(this) as common.UIAbilityContext;

  build() {
    Column() {
      Button($r('app.string.setMissionContinueState')).onClick(() => {
        router.pushUrl({ url: 'continue/PageName' }, () => {
          logger.info(`${TAG} setTimeout router pushUrl continue/PageName`);
        })
      })
        .margin({ top: CommonConstants.BUTTON_MARGIN_TOP })
        .width(CommonConstants.BUTTON_WIDTH)

      Button($r('app.string.basic_continue_data_example')).onClick(() => {
        let want: Want = {
          bundleName: 'com.sample.continue',
          abilityName: 'Ability_deviceA'
        }
        this.context.startAbility(want);
      })
        .margin(CommonConstants.BUTTON_MARGIN)
        .width(CommonConstants.BUTTON_WIDTH)

      Button($r('app.string.migrate_data_using_dataObject')).onClick(() => {
        let want: Want = {
          bundleName: 'com.sample.continue',
          abilityName: 'MigrationAbility'
        }
        this.context.startAbility(want);
      })
        .margin(CommonConstants.BUTTON_MARGIN)
        .width(CommonConstants.BUTTON_WIDTH)

      Button($r('app.string.migrate_data_using_dataObject_asset')).onClick(() => {
        let want: Want = {
          bundleName: 'com.sample.continue',
          abilityName: 'MigrationAbility_asset'
        }
        this.context.startAbility(want);
      })
        .margin(CommonConstants.BUTTON_MARGIN)
        .width(CommonConstants.BUTTON_WIDTH)

      Button($r('app.string.migrate_data_using_dataObject_multi_asset')).onClick(() => {
        let want: Want = {
          bundleName: 'com.sample.continue',
          abilityName: 'MigrationAbility_multi_asset'
        }
        this.context.startAbility(want);
      })
        .margin(CommonConstants.BUTTON_MARGIN)
        .width(CommonConstants.BUTTON_WIDTH)
    }
    .width('100%')
    .height('100%')
  }
}