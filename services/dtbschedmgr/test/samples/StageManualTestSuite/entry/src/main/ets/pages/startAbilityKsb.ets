/**
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

import Utils from '../Model/Utils';
import router from '@system.router';
import featureAbility from '@ohos.ability.featureAbility';
import wantConstant from '@ohos.ability.wantConstant'
import Prompt from '@system.prompt';
import RemoteDeviceModel from '../Model/getRemoteDeviceModel';

const BUNDLE_NAME = 'com.example.continue.freeInstall';
const ABILITY_NAME = 'com.example.continue.MainAbility';
const ABILITY_NAME_FIRST = 'com.example.freeInstall.MainAbility1';
const ABILITY_NAME_SECOND = 'com.example.freeInstall.MainAbility2';
const MODULE_NAME_ENTRY = 'entry';
const MODULE_NAME_SECOND = 'module2';
const MODULE_NAME_THIRD = 'module3';
const MODULE_NAME_FOURTH = 'module4';
const MODULE_NAME_ERROR = 'module';

let remoteDeviceId = '';
let remoteDeviceModel = null;

@Entry
@Component
struct StartAbility {
  private contextText: string= '';
  private localDeviceId: string= '';
  private tipsMsg = '请输入对端的deviceId';

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

      TextInput({ placeholder: '请输入deviceId', text: this.contextText })
        .placeholderColor(Color.White)
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
        });

      Button() {
        Text('StartAbilityPromiseKSB001，跨设备，Promise，传入对端设备的deviceId')
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
        this.tips(this.contextText);
        if ('' === remoteDeviceId && '' === this.contextText) {
          this.tips(this.tipsMsg);
          return;
        }
        var str = {
          'deviceId': '' === this.contextText ? remoteDeviceId : this.contextText,
          'bundleName': BUNDLE_NAME,
          'abilityName': ABILITY_NAME,
          'moduleName': MODULE_NAME_ENTRY,
          'flags': wantConstant.Flags.FLAG_INSTALL_ON_DEMAND,

        };
        this.startAbilityPromise('StartAbilityPromiseKSB001', str);
      })

      Button() {
        Text('StartAbilityCallBackKSB002，跨设备，CallBack，传入对端设备的deviceId')
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
        if ('' === remoteDeviceId && '' === this.contextText) {
          this.tips(this.tipsMsg);
          return;
        }
        var str = {
          'deviceId': '' === this.contextText ? remoteDeviceId : this.contextText,
          'bundleName': BUNDLE_NAME,
          'abilityName': ABILITY_NAME,
          'moduleName': MODULE_NAME_ENTRY,
          'flags': wantConstant.Flags.FLAG_INSTALL_ON_DEMAND,
        };
        this.startAbilityCallBack('StartAbilityCallBackKSB002', str);
      })

      Button() {
        Text('StartAbilityPromiseKSB003，跨设备，跨应用，拉起与entry相同的bundleName不同abilityName的hap')
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
        if ('' === remoteDeviceId && '' === this.contextText) {
          this.tips(this.tipsMsg);
          return;
        }
        var str = {
          'deviceId': '' === this.contextText ? remoteDeviceId : this.contextText,
          'bundleName': BUNDLE_NAME,
          'abilityName': ABILITY_NAME_FIRST,
          'moduleName': MODULE_NAME_SECOND,
          'flags': wantConstant.Flags.FLAG_INSTALL_ON_DEMAND,
        };
        this.startAbilityPromise('StartAbilityPromiseKSB003', str);
      })

      Button() {
        Text('StartAbilityPromiseKSB004，跨设备，跨应用，对端FA的visable为false无法拉起')
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
        if ('' === remoteDeviceId && '' === this.contextText) {
          this.tips(this.tipsMsg);
          return;
        }
        var str = {
          'deviceId': '' === this.contextText ? remoteDeviceId : this.contextText,
          'bundleName': BUNDLE_NAME,
          'abilityName': ABILITY_NAME_SECOND,
          'moduleName': MODULE_NAME_THIRD,
          'flags': wantConstant.Flags.FLAG_INSTALL_ON_DEMAND,
        }
        this.startAbilityPromise('StartAbilityPromiseKSB004', str);
      })

      Button() {
        Text('StartAbilityPromiseKSB005，跨设备，传入错误的flags=23232333333333')
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
        if ('' === remoteDeviceId && '' === this.contextText) {
          this.tips(this.tipsMsg);
          return;
        }
        var str = {
          'deviceId': '' === this.contextText ? remoteDeviceId : this.contextText,
          'bundleName': BUNDLE_NAME,
          'abilityName': ABILITY_NAME,
          'moduleName': MODULE_NAME_ENTRY,
          'flags': 23232333333333,
        };
        this.startAbilityPromise('StartAbilityPromiseKSB005', str);
      })

      Button() {
        Text('StartAbilityPromiseKSB006，跨设备，参数正常传入，应用在免安装时，发起端设备网络断开')
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
        if ('' === remoteDeviceId && '' === this.contextText) {
          this.tips(this.tipsMsg);
          return;
        }
        var str = {
          'deviceId': '' === this.contextText ? remoteDeviceId : this.contextText,
          'bundleName': BUNDLE_NAME,
          'abilityName': ABILITY_NAME,
          'moduleName': MODULE_NAME_ENTRY,
          'flags': wantConstant.Flags.FLAG_INSTALL_ON_DEMAND,
        };
        this.startAbilityPromise('StartAbilityPromiseKSB006', str);
      })

      Button() {
        Text('StartAbilityCallBackKSB007，无跨设备权限(本端和对端)')
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
        if ('' === remoteDeviceId && '' === this.contextText) {
          this.tips(this.tipsMsg);
          return;
        }
        var str = {
          'deviceId': '' === this.contextText ? remoteDeviceId : this.contextText,
          'bundleName': BUNDLE_NAME,
          'abilityName': ABILITY_NAME,
          'moduleName': MODULE_NAME_ENTRY,
          'flags': wantConstant.Flags.FLAG_INSTALL_ON_DEMAND,
        };
        this.startAbilityCallBack('StartAbilityCallBackKSB007', str);
      })

      Button() {
        Text('StartAbilityPromiseKSB008，跨设备，DMS免安装超时')
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
        this.tips(this.contextText);
        if ('' === remoteDeviceId && '' === this.contextText) {
          this.tips(this.tipsMsg);
          return;
        }
        var str = {
          'deviceId': '' === this.contextText ? remoteDeviceId : this.contextText,
          'bundleName': BUNDLE_NAME,
          'abilityName': ABILITY_NAME,
          'moduleName': MODULE_NAME_ENTRY,
          'flags': wantConstant.Flags.FLAG_INSTALL_ON_DEMAND,
        };
        this.startAbilityPromise('StartAbilityPromiseKSB008', str);
      })

      Button() {
        Text('StartAbilityPromiseKSB009，传入错误的deviceId')
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
        var str = {
          'deviceId': '43536232356562352415454521241545454545445',
          'bundleName': BUNDLE_NAME,
          'abilityName': ABILITY_NAME,
          'moduleName': MODULE_NAME_ENTRY,
          'flags': wantConstant.Flags.FLAG_INSTALL_ON_DEMAND,
        };
        this.startAbilityPromise('StartAbilityPromiseKSB009', str);
      })

      Button() {
        Text('StartAbilityPromiseKSB017，hapA、hapB的bundleName、abilityName都相同，moduleName不同')
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
        var str = {
          'deviceId': '' === this.contextText ? remoteDeviceId : this.contextText,
          'bundleName': BUNDLE_NAME,
          'abilityName': ABILITY_NAME_SECOND,
          'moduleName': MODULE_NAME_SECOND,
          'flags': wantConstant.Flags.FLAG_INSTALL_ON_DEMAND,
        };
        this.startAbilityPromise('StartAbilityPromiseKSB017', str);
      })

      Button() {
        Text('StartAbilityPromiseKSB018，不传moduleName')
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
        var str = {
          'deviceId': '' === this.contextText ? remoteDeviceId : this.contextText,
          'bundleName': BUNDLE_NAME,
          'abilityName': ABILITY_NAME,
          'flags': wantConstant.Flags.FLAG_INSTALL_ON_DEMAND,
        };
        this.startAbilityPromise('StartAbilityPromiseKSB018', str);
      })

      Button() {
        Text('StartAbilityPromiseKSB019，传入错误的moduleName')
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
        var str = {
          'deviceId': '' === this.contextText ? remoteDeviceId : this.contextText,
          'bundleName': BUNDLE_NAME,
          'abilityName': ABILITY_NAME,
          'moduleName': MODULE_NAME_ERROR,
          'flags': wantConstant.Flags.FLAG_INSTALL_ON_DEMAND,
        };
        this.startAbilityPromise('StartAbilityPromiseKSB019', str);
      })

      Button() {
        Text('StartAbilityPromiseKSB021，want里面传parameters字段')
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
        var str = {
          'deviceId': '' === this.contextText ? remoteDeviceId : this.contextText,
          'bundleName': BUNDLE_NAME,
          'abilityName': ABILITY_NAME,
          'moduleName': MODULE_NAME_ENTRY,
          'flags': wantConstant.Flags.FLAG_INSTALL_ON_DEMAND,
          'parameters': {
            "name": "1111",
            "Ext2": "ExtValue2",
            "site": "test"}
        }
        this.startAbilityPromise('StartAbilityPromiseKSB021', str);
      })

      Button() {
        Text('StartAbilityPromiseKSB022，不传flag')
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
        var str = {
          'deviceId': '' === this.contextText ? remoteDeviceId : this.contextText,
          'bundleName': BUNDLE_NAME,
          'abilityName': ABILITY_NAME,
          'moduleName': MODULE_NAME_ENTRY
        };
        this.startAbilityPromise('StartAbilityPromiseKSB022', str);
      })
    }
    .width('100%')
    .height('100%')
  }

  async startAbilityPromise(tag, str) {
    console.info(tag + ' startAbility startAbilityPromise START' + JSON.stringify(str));
    let code;
    await globalThis.abilityContext.startAbility(str)
      .then((data) => {
        console.info(tag + ' startAbility Operation successful. Promise Data: ' + JSON.stringify(data))
        code = data;
      }).catch((error) => {
        console.info(tag + ' startAbility Operation failed. Promise Cause: ' + JSON.stringify(error));
        code = error;
      })
    console.info(tag + ' startAbility Operation code Promise: ' + JSON.stringify(code));
    if (code === 0) {
      this.tips('成功');
    } else {
      this.tips('错误码：' + code.code);
    }
    console.info(tag + ' startAbility startAbilityPromise END');
  }

  async startAbilityCallBack(tag, str) {
    let code;
    console.info(tag + 'startAbility startAbilityCallBack START' + JSON.stringify(str));
    globalThis.abilityContext.startAbility(str, (err, data) => {
      code = data;
      if (err) {
        console.error(tag + ' Operation failed. CallBack Cause:' + JSON.stringify(err));
        code = err;
      }
      if (code === 0) {
        this.tips('成功');
      } else {
        this.tips('错误码：' + code.code);
      }
      console.info('Operation successful. CallBack Data: ' + JSON.stringify(data))
    });
    console.info(tag + 'startAbility startAbilityCallBack END');
  }

  tips(msg) {
    Prompt.showToast({
      message: msg,
      duration: 2000,
      bottom: '150px'
    });
  }

  onBackPress() {
    console.log('startAbility get device onBackPress in');
    this.contextText = '';
    console.log('startAbility get device onBackPress out');
  }

  aboutToAppear(): void {
    console.info('[startAbility] aboutToAppear in');
    remoteDeviceModel = new RemoteDeviceModel;
    remoteDeviceModel.registerDeviceListCallback();
    console.info('[startAbility] aboutToAppear end');
  }

  onPageShow(): void{
    console.info('[startAbility] onPageShow in');
    let numDevices = remoteDeviceModel.deviceList.length;
    if (numDevices === 0) {
      this.tips('onStartRemoteAbility no device found')
      return;
    }
    remoteDeviceId = remoteDeviceModel.deviceList[0].deviceId;
    console.info('[startAbility] onPageShow deviceId is ' + remoteDeviceId);
  }

  aboutToDisappear() {
    console.info('[startAbility] aboutToDisappear in');
    remoteDeviceModel.unregisterDeviceListCallback();
    console.info('[startAbility] aboutToDisappear out');
  }
}