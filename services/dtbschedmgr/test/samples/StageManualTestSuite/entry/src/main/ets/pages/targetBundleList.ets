/**
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

import router from '@ohos.router';
import featureAbility from '@ohos.ability.featureAbility';
import wantConstant from '@ohos.app.ability.wantConstant';
import Prompt from '@system.prompt';
import RemoteDeviceModel from '../Model/getRemoteDeviceModel';
import { BusinessError } from '@ohos.base';
import { GlobalThis } from '../Model/GlobalThis';
import common from '@ohos.app.ability.common';
import Want from '@ohos.app.ability.Want';

let remoteDeviceId = '';
let remoteDeviceModel : null | RemoteDeviceModel = null;

@Entry
@Component
struct TargetBundleList {
  private BUNDLE_NAME = 'com.example.continue.freeInstall';
  private ABILITY_NAME = 'com.example.continue.MainAbility';
  private MODULE_NAME_ENTRY = 'entry';
  private MODULE_NAME_SECOND = 'module2';
  private MODULE_NAME_THIRD = 'module3';
  private MODULE_NAME_ERROR = 'module';
  private content: string = "Four Page"
  private contextText: string= '';
  private tipsMsg = '请输入对端的deviceId';
  private isOn = false;
  private context = getContext(this) as common.UIAbilityContext;

  build() {
    Flex({ direction: FlexDirection.Column, alignItems: ItemAlign.Start, justifyContent: FlexAlign.Center }) {
      Button() {
        Text('back to index')
          .fontSize(20)
          .fontWeight(FontWeight.Bold);
      }
      .type(ButtonType.Capsule)
      .backgroundColor('#0D9FFB')
      .onClick(() => {
        router.back();
      });
      Row() {
        Text('打开测试startAbilityForResult，关闭是startAbility：')
          .fontSize($r('app.float.font_20'))

          .fontColor(Color.White)
          .align(Alignment.Center)
          .fontColor(Color.Black)
          .fontSize($r('app.float.font_20'))
          .margin({ left: $r('app.float.wh_value_15'), right: $r('app.float.wh_value_15') })
        Toggle({ type: ToggleType.Switch, isOn: this.isOn })
          .width($r('app.float.wh_value_70'))
          .height($r('app.float.wh_value_60'))
          .onChange((isOn) => {
            console.info('startAbility startAbilityPromise isOn：' + isOn);
            this.isOn = isOn;
            console.info('startAbility startAbilityPromise this.isOn：' + this.isOn);
          });
      }
      .margin({ right: $r('app.float.wh_value_15') })

      TextInput({ placeholder: '请输入deviceId', text: this.contextText })
        .placeholderColor(Color.Blue)
        .placeholderFont({
          size: $r('app.float.wh_value_20'),
          weight: 2,
          family: "sans-serif",
          style: FontStyle.Normal
        })
        .caretColor(Color.Blue)
        .height($r('app.float.wh_value_70'))
        .backgroundColor(Color.Gray)
        .type(InputType.Normal)
        .width('100%')
        .fontStyle(FontStyle.Italic)
        .margin({ left: $r('app.float.wh_value_15'), right: $r('app.float.wh_value_15') })
        .onChange((value: string) => {
          this.contextText = value;
          console.info('startAbility startAbilityPromise contextText：' + this.contextText);
        });

      Button() {
        Text('StartAbilityPromise016，本设备跨应用免安装')
          .fontSize($r('app.float.font_20'))
          .width('100%')
          .fontColor(Color.White)
          .align(Alignment.Center)
          .margin({ left: $r('app.float.wh_value_15'), right: $r('app.float.wh_value_15') })
      }
      .height($r('app.float.wh_value_60'))
      .margin({
        left: $r('app.float.wh_value_15'),
        right: $r('app.float.wh_value_15'),
        top: $r('app.float.wh_value_15')
      })
      .onClick(() => {
        let str: Want = {
          'bundleName': this.BUNDLE_NAME,
          'abilityName': this.ABILITY_NAME,
          'moduleName': this.MODULE_NAME_ENTRY,
          'flags': wantConstant.Flags.FLAG_INSTALL_ON_DEMAND
        };
        if (this.isOn) {
          this.startAbilityForResultPromise('StartAbilityPromise016', str);
        } else {
          this.startAbilityPromise('StartAbilityPromise016', str);
        }
      })

      Button() {
        Text('StartAbilityPromiseKSB012，原子化服务未添加到targetBundleList里，传入对端设备的deviceId')
          .fontSize($r('app.float.font_20'))
          .width('100%')
          .fontColor(Color.White)
          .align(Alignment.Center)
          .margin({ left: $r('app.float.wh_value_15'), right: $r('app.float.wh_value_15') })
      }
      .height($r('app.float.wh_value_60'))
      .margin({
        left: $r('app.float.wh_value_15'),
        right: $r('app.float.wh_value_15'),
        top: $r('app.float.wh_value_15')
      })
      .onClick(() => {
        this.tips(remoteDeviceId);
        if ('' === remoteDeviceId && '' === this.contextText) {
          this.tips(this.tipsMsg);
        }
        let str: Want = {
          'deviceId': '' === this.contextText ? remoteDeviceId : this.contextText,
          'bundleName': this.BUNDLE_NAME,
          'abilityName': this.ABILITY_NAME,
          'moduleName': this.MODULE_NAME_ENTRY,
          'flags': wantConstant.Flags.FLAG_INSTALL_ON_DEMAND,

        };
        if (this.isOn) {
          this.startAbilityForResultPromise('StartAbilityPromiseKSB012', str);
        } else {
          this.startAbilityPromise('StartAbilityPromiseKSB012', str);
        }
      })
    }
    .width('100%')
    .height('100%')
  }

  async startAbilityPromise(tag: string, str: Want) {
    console.info(tag + ' startAbility startAbilityPromise START' + JSON.stringify(str));
    await this.context.startAbility(str)
      .then((data) => {
        console.info(tag + ' startAbility Operation successful. Promise Data: ' + JSON.stringify(data))
      }).catch((error: BusinessError) => {
        console.info(tag + ' startAbility Operation failed. Promise Cause: ' + JSON.stringify(error));
      })
    console.info(tag + ' startAbility startAbilityPromise END');
  }

  async startAbilityForResultPromise(tag: string, str: Want) {
    console.info(tag + ' startAbilityForResultPromise START' + JSON.stringify(str));

    await this.context.startAbilityForResult(str)
      .then((data) => {
        this.tips('成功');
        console.info(tag + ' startAbilityForResultPromise Operation successful. Promise Data: ' + JSON.stringify(data))
      }).catch((error: BusinessError) => {
        console.info(tag + ' startAbilityForResultPromise Operation failed. Promise Cause: ' + JSON.stringify(error));
        this.tips('失败');
      })
    console.info(tag + ' startAbilityForResultPromise startAbilityPromise END');
  }

  tips(msg: string) {
    Prompt.showToast({
      message: msg,
      duration: 2000,
      bottom: '150px'
    });
  }

  onBackPress() {
    console.log('[startAbility] get device onBackPress in');
    this.contextText = '';
    console.log('[startAbility] get device onBackPress out');
  }

  aboutToAppear(): void {
    console.info('[startAbility] aboutToAppear in');
    remoteDeviceModel = new RemoteDeviceModel;
    if (remoteDeviceModel) {
      remoteDeviceModel.registerDeviceListCallback();
    } else {
      console.error('[startAbility] aboutToAppear remoteDeviceModel is null');
    }
    console.info('[startAbility] aboutToAppear end');
  }

  onPageShow(): void{
    console.info('[startAbility] onPageShow in');
    let numDevices: number = 0;
    if (remoteDeviceModel) {
      numDevices = remoteDeviceModel.deviceList.length;
    } else {
      console.error('[startAbility] aboutToDisappear remoteDeviceModel is null');
    }

    if (numDevices === 0) {
      this.tips('[startAbility] onStartRemoteAbility no device found')
      return;
    }

    if (remoteDeviceModel) {
      remoteDeviceId = remoteDeviceModel.deviceList[0].deviceId;
      console.info('[startAbility] onPageShow deviceId is ' + remoteDeviceId);
    } else {
      console.error('[startAbility] onPageShow remoteDeviceModel is null');
    }
  }

  aboutToDisappear() {
    console.info('[startAbility] aboutToDisappear in');
    if (remoteDeviceModel) {
      remoteDeviceModel.unregisterDeviceListCallback();
    } else {
      console.error('[startAbility] aboutToDisappear remoteDeviceModel is null');
    }
    console.info('[startAbility] aboutToDisappear out');
  }
}