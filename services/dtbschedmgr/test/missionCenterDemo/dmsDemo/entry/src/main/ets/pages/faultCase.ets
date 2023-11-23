/*
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

import DeviceManager from '../Util/DeviceManager';
import router from '@ohos.router';
import Logger from '../Util/Logger'

@Entry
@Component
struct Index {
  @State deviceManager: DeviceManager = AppStorage.get<DeviceManager>('DeviceManager')
  @State dstDeviceId: string = ''
  @State srcDeviceId: string = ''
  @State missionId: string = ''
  @State isFreeInstall: boolean = true
  @StorageLink('continueResult') continueResult: string = '0'

  build() {
    Column() {
      Blank().height('5%')
      Row() {
        Button() {
          Text(" < Back ")
            .fontSize('30fp')
            .fontWeight(FontWeight.Bold)
            .fontColor(Color.Blue)
        }
        .backgroundColor("")
        .onClick(() => {
          router.back()
        })
        Blank().width('80%')
      }
      Text("异常场景用例")
        .fontSize('40fp')
        .fontWeight(FontWeight.Bold)
      Blank().height('5%')
      Row() {
        Text("dstDeviceId:")
          .fontSize('20fp')
          .width('40%')
        Column() {
          TextInput({text: this.dstDeviceId})
            .borderStyle(BorderStyle.Solid)
            .type(InputType.Normal)
            .onChange((value: string) => {
              Logger.info("select toDeviceId: " + value)
            })
          Blank().height('2%')
          Button() {
            Text("add remote deviceId")
              .fontSize('20fp')
          }
          .height('5%')
          .width('100%')
          .onClick(() => {
            if (this.deviceManager.trustedDeviceList.length > 0) {
              this.dstDeviceId = this.deviceManager.trustedDeviceList[0].deviceInfo.networkId
            }
          })
        }.width('60%')

      }
      Blank().height('5%')
      Row() {
        Text("srcDeviceId:")
          .fontSize('20fp')
          .width('40%')
        Column() {
          TextInput({text: this.srcDeviceId})
            .borderStyle(BorderStyle.Solid)
            .type(InputType.Normal)
            .onChange((value: string) => {
              Logger.info("select fromDeviceId: " + value)
            })
          Blank().height('2%')
          Button() {
            Text("add local deviceId")
              .fontSize('20fp')
          }
          .height('5%')
          .width('100%')
          .onClick(() => {
            this.srcDeviceId = this.deviceManager.localDevice.deviceInfo.deviceId
          })
        }.width('60%')

      }
      Blank().height('5%')
      Row() {
        Text("missionId:")
          .fontSize('20fp')
          .width('40%')
        TextInput({text: this.missionId})
          .width('60%')
          .borderStyle(BorderStyle.Solid)
          .type(InputType.Normal)
          .onChange((value: string) => {
            Logger.info("select fromMissionId: " + value)
            this.missionId = value
          })
      }
      Blank().height('5%')
      Row() {
        Text("isFreeInstall:")
          .fontSize('20fp')
          .width('40%')
        Checkbox()
          .select(this.isFreeInstall)
          .selectedColor(0x39a2db)
          .onChange((value: boolean) => {
            Logger.info("select isFreeInstall: " + value)
            this.isFreeInstall = value
          })
      }
      Blank().height('5%')
      Button() {
        Text("Continue Mission")
          .fontSize('20fp')
      }
      .width('80%')
      .height('7%')
      .onClick(() => {
        this.deviceManager.toDeviceId = this.dstDeviceId
        this.deviceManager.fromDeviceId = this.srcDeviceId
        this.deviceManager.fromMissionId = Number(this.missionId)
        this.deviceManager.isFreeInstall = this.isFreeInstall
        Logger.info("toDeviceId: " + this.deviceManager.toDeviceId)
        Logger.info("fromDeviceId: " + this.deviceManager.fromDeviceId)
        Logger.info("fromMissionId: " + this.deviceManager.fromMissionId)
        Logger.info("isFreeInstall: " + this.deviceManager.isFreeInstall)
        this.deviceManager.onContinueAbility()
      })
      Blank().height('5%')
      Row() {
        Text('迁移错误码: ' + this.continueResult)
          .fontSize('20fp')
          .width('90%')
      }
    }
  }
}