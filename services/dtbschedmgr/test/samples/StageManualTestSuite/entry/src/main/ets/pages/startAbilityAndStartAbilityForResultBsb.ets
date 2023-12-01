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
import wantConstant from '@ohos.app.ability.wantConstant';
import Prompt from '@system.prompt';
import Utils from '../Model/Utils';
import Want from '@ohos.app.ability.Want';
import StartOptions from '@ohos.app.ability.StartOptions';
import { BusinessError } from '@ohos.base';
import common from '@ohos.app.ability.common';

@Entry
@Component
struct StartAbilityAndStartAbilityForResultModel {
  private contextText: string= '';
  private localDeviceId: string= '';
  private BUNDLE_NAME = 'com.example.continue.freeInstall';
  private ABILITY_NAME = 'com.example.continue.MainAbility';
  private ABILITY_NAME_FIRST = 'com.example.freeInstall.MainAbility1';
  private ABILITY_NAME_SECOND = 'com.example.freeInstall.MainAbility2';
  private MODULE_NAME_ENTRY = 'entry';
  private MODULE_NAME_SECOND = 'module2';
  private MODULE_NAME_THIRD = 'module3';
  private MODULE_NAME_FOURTH = 'module4';
  private MODULE_NAME_ERROR = 'module';
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
      .align(Alignment.End);

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
        .fontColor(Color.White)
        .margin({ left: $r('app.float.wh_value_15'), right: $r('app.float.wh_value_15') })
        .onChange((value: string) => {
          this.contextText = value;
          console.info('startAbility startAbilityPromise contextText：' + this.contextText);
        });

      Button() {
        Text('StartAbilityPromise000，ServiceAbility')
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
          'bundleName': 'com.dms.stage_manual_test_suite',
          'abilityName': 'ServiceAbility2',
        };
        if (this.isOn) {
          let str1: Want = {
            'bundleName': 'com.dms.stage_manual_test_suite',
            'abilityName': 'ServiceAbility',
          }
          this.startAbilityPromise('StartAbilityPromise000', str1);
        } else {
          this.startAbilityPromise('StartAbilityPromise000', str);
        }
      })

      Button() {
        Text('StartAbilityPromise001，传入的deviceId为空')
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
          'deviceId': '',
          'bundleName': this.BUNDLE_NAME,
          'abilityName': this.ABILITY_NAME,
          'moduleName': this.MODULE_NAME_ENTRY,
          'flags': wantConstant.Flags.FLAG_INSTALL_ON_DEMAND
        };
        let options: StartOptions ={
          windowMode: 0,
          displayId:2
        }
        if (this.isOn) {
          this.startAbilityForResultPromise('StartAbilityPromise001', str, 0);
        } else {
          this.startAbilityPromiseAddOperation('StartAbilityPromise001', str, options);
        }
      })

      Button() {
        Text('StartAbilityPromise002，不传deviceId，本设备未安装该应用')
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
          this.startAbilityForResultPromise('startAbilityPromise002', str, 0);
        } else {
          this.startAbilityPromise('startAbilityPromise002', str);
        }
      })

      Button() {
        Text('StartAbilityPromise003，不传deviceId，本设备已安装该应用')
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
        let options: StartOptions ={
          windowMode: 0,
          displayId:2
        }
        if (this.isOn) {
          this.startAbilityForResultPromise('StartAbilityPromise003', str, 0);
        } else {
          this.startAbilityPromiseAddOperation('StartAbilityPromise003', str, options);
        }
      })

      Button() {
        Text('StartAbilityPromise004，传入本设备的deviceId')
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
        if ('' === this.contextText) {
          this.tips('请输入本设备的deviceId！');
          return;
        }
        let str: Want = {
          'deviceId': this.contextText,
          'bundleName': this.BUNDLE_NAME,
          'abilityName': this.ABILITY_NAME,
          'moduleName': this.MODULE_NAME_ENTRY,
          'flags': wantConstant.Flags.FLAG_INSTALL_ON_DEMAND
        };
        if (this.isOn) {
          this.startAbilityForResultPromise('StartAbilityPromise004', str, 0);
        } else {
          this.startAbilityPromise('StartAbilityPromise004', str);
        }
      })

      Button() {
        Text('StartAbilityPromise005，不传deviceId，拉起与entry相同的bundleName不同abilityName的hap')
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
          'abilityName': this.ABILITY_NAME_FIRST,
          'moduleName': this.MODULE_NAME_SECOND,
          'flags': wantConstant.Flags.FLAG_INSTALL_ON_DEMAND
        };
        if (this.isOn) {
          this.startAbilityForResultPromise('StartAbilityPromise005', str, 0);
        } else {
          this.startAbilityPromise('StartAbilityPromise005', str);
        }
      })

      Button() {
        Text('StartAbilityCallBack007，callback，不传deviceId')
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
          this.startAbilityForResultCallBack('StartAbilityCallBack007', str);
        } else {
          this.startAbilityCallBack('StartAbilityCallBack007', str);
        }
      })

      Button() {
        Text('StartAbilityPromise008，传入错误的flags=1717')
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
          'flags': 1717
        };
        let options: StartOptions ={
          windowMode: 0,
          displayId:2
        }
        if (this.isOn) {
          this.startAbilityForResultPromise('StartAbilityPromise008', str, 1);
        } else {
          this.startAbilityPromiseAddOperation('StartAbilityPromise008', str, options);
        }
      })

      Button() {
        Text('StartAbilityPromise011，不传flag')
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
          'moduleName': this.MODULE_NAME_ENTRY
        };
        let options: StartOptions ={
          windowMode: 0,
          displayId:2
        }
        if (this.isOn) {
          this.startAbilityForResultPromise('StartAbilityPromise011', str, 1);
        } else {
          this.startAbilityPromiseAddOperation('StartAbilityPromise011', str, options);
        }
      })

      Button() {
        Text('StartAbilityPromise012，当前服务不在前台，A页面先跳转到B页面，A页面延迟5s调用接口')
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
          this.startMainAbility2('StartAbilityPromise012', str, 1);
        } else {
          this.startMainAbility2('StartAbilityPromise012', str, 0);
        }
      })

      Button() {
        Text('StartAbilityPromise013，want里面传parameters字段')
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
          'flags': wantConstant.Flags.FLAG_INSTALL_ON_DEMAND,
          'parameters': {
            "name": "1111",
            "Ext2": "ExtValue2",
            "site": "test"
          }
        };
        if (this.isOn) {
          this.startAbilityForResultPromise('StartAbilityPromise013', str, 0);
        } else {
          this.startAbilityPromise('StartAbilityPromise013', str);
        }
      })

      Button() {
        Text('StartAbilityPromise014，当前服务不在前台，在页面A点击按钮延时5s调用接口，按home键回到桌面')
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
        let options: StartOptions ={
          windowMode: 0,
          displayId:2
        }
        if (this.isOn) {
          this.startAbilityForResultPromise('StartAbilityPromise014', str, 0);
        } else {
          this.startAbilityPromiseAddOperation('StartAbilityPromise014', str, options);
        }
      })

      Button() {
        Text('StartAbilityPromise015，FA服务中心免安装超时')
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
          'flags': wantConstant.Flags.FLAG_INSTALL_ON_DEMAND,
        };
        if (this.isOn) {
          this.startAbilityForResultPromise('StartAbilityPromise015', str, 0);
        } else {
          this.startAbilityPromise('StartAbilityPromise015', str);
        }
      })

      Button() {
        Text('StartAbilityPromise019，hapA、hapB的bundleName、abilityName都相同，moduleName不同')
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
          'abilityName': this.ABILITY_NAME_FIRST,
          'moduleName': this.MODULE_NAME_FOURTH,
          'flags': wantConstant.Flags.FLAG_INSTALL_ON_DEMAND
        };
        if (this.isOn) {
          this.startAbilityForResultPromise('StartAbilityPromise019', str, 0);
        } else {
          this.startAbilityPromise('StartAbilityPromise019', str);
        }
      })

      Button() {
        Text('StartAbilityPromise020，传入错误的moduleName')
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
          'moduleName': this.MODULE_NAME_ERROR,
          'flags': wantConstant.Flags.FLAG_INSTALL_ON_DEMAND
        };
        if (this.isOn) {
          this.startAbilityForResultPromise('StartAbilityPromise020', str, 0);
        } else {
          this.startAbilityPromise('StartAbilityPromise020', str);
        }
      })

      Button() {
        Text('StartAbilityPromise021，不传moduleName')
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
          'flags': wantConstant.Flags.FLAG_INSTALL_ON_DEMAND
        };
        let options: StartOptions ={
          windowMode: 0,
          displayId:2
        }
        if (this.isOn) {
          this.startAbilityForResultPromise('StartAbilityPromise021', str, 0);
        } else {
          this.startAbilityPromiseAddOperation('StartAbilityPromise021', str, options);
        }
      })
    }
    .width('100%')
    .height('100%')
  }

  async startMainAbility2(tag: string, str1: Want, type: number) {
    console.info(tag + ' startMainAbility2 START');
    let str: Want = {
      "deviceId": "",
      "bundleName": "com.dms.stage_manual_test_suite",
      "abilityName": "MainAbility1",
    };
    this.context.startAbility(str)
      .then(() => {
        console.info(tag + ' startAbility Operation successful.')
      }).catch((error: BusinessError) => {
      console.info(tag + ' startAbility Operation failed. Promise Cause: ' + JSON.stringify(error));
    })
    if (type === 0) {
      this.startAbilityPromise(tag, str1);
    } else {
      this.startAbilityForResultPromise(tag, str1, 0);
    }
  }

  async startAbilityPromise(tag: string, str: Want) {
    if ('StartAbilityPromise012' === tag || 'StartAbilityPromise014' === tag) {
      await Utils.sleep(5000);
    }
    console.info(tag + ' startAbility startAbilityPromise START' + JSON.stringify(str));
    await this.context.startAbility(str)
      .then((data) => {
        console.info(tag + ' startAbility Operation successful. Promise Data: ' + JSON.stringify(data))
        this.tips('成功');
      }).catch((error: BusinessError) => {
        console.info(tag + ' startAbility Operation failed. Promise Cause: ' + JSON.stringify(error));
        this.tips('失败：' + JSON.stringify(error));
      })
    console.info(tag + ' startAbility startAbilityPromise END');
  }

  async startAbilityPromiseAddOperation(tag: string, str: Want, options: StartOptions) {
    if ('StartAbilityPromise012' === tag || 'StartAbilityPromise014' === tag) {
      await Utils.sleep(5000);
    }
    console.info(tag + ' startAbility startAbilityPromiseAndOperation START' + JSON.stringify(str));
    await this.context.startAbility(str, options)
      .then((data:void) => {
        console.info(tag + ' startAbility Operation successful. Promise Data: ' + JSON.stringify(data))
        this.tips('成功');
      }).catch((error: BusinessError) => {
        console.info(tag + ' startAbility Operation failed. Promise Cause: ' + JSON.stringify(error));
        this.tips('失败:' + JSON.stringify(error));
      })
    console.info(tag + ' startAbility startAbilityPromise END');
  }

  async startAbilityCallBack(tag: string, str: Want) {
    console.info(tag + 'startAbility startAbilityCallBack START' + JSON.stringify(str));
    this.context.startAbility(str, (err, data) => {
      if (err) {
        this.tips("失败: " + JSON.stringify(err));
      }
      this.tips('成功');
      console.info(tag + 'Operation CallBack err: ' + JSON.stringify(err) + ', data: ' + JSON.stringify(data))
    });
    console.info(tag + 'startAbility startAbilityCallBack END');
  }

  async startAbilityForResultPromise(tag: string, str: Want, type: number) {
    if ('StartAbilityPromise012' === tag || 'StartAbilityPromise014' === tag) {
      await Utils.sleep(5000);
    }
    console.info(tag + ' startAbilityForResultPromise START' + JSON.stringify(str));
    await this.context.startAbilityForResult(str)
      .then((data) => {
        if (0 === type) {
          this.tips('成功');
        }
        console.info(tag + ' startAbilityForResultPromise Operation successful. Promise Data: ' + JSON.stringify(data))
      }).catch((error: BusinessError) => {
        console.info(tag + ' startAbilityForResultPromise Operation failed. Promise Cause: ' + JSON.stringify(error));
        this.tips('失败');
      })
    console.info(tag + ' startAbilityForResultPromise startAbilityPromise END');
  }

  async startAbilityForResultCallBack(tag: string, str: Want) {
    console.info(tag + 'startAbilityForResultCallBack START' + JSON.stringify(str));
    this.context.startAbilityForResult(str, (err, data) => {
      console.info(tag + 'startAbilityForResultCallBack Operation CallBack Data: ' + JSON.stringify(data))
      if (err) {
        this.tips('失败');
        console.info(tag + 'startAbilityForResultCallBack Operation CallBack err:' + JSON.stringify(err));
        return;
      }
      this.tips('成功');
    });
    console.info(tag + 'startAbilityForResultCallBack END');
  }

  tips(msg: string) {
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
}