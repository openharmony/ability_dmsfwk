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

import Logger from '../Util/Logger'
import DeviceManager from '../Util/DeviceManager';
import Device from '../Util/Device';
import router from '@ohos.router';
import Mission from '../Util/Mission'
import CommonTools from '../Util/common'

if(!AppStorage.has('isReady')){
  AppStorage.setOrCreate('isReady',false)
}

if(!AppStorage.has('isUpdate')){
  AppStorage.setOrCreate('isUpdate', false)
}

function getBundleNameFromMissionInfo(item: Mission): string {
  if (item.missionInfo.want.bundleName !== undefined) {
    let missionArray = item.missionInfo.want.bundleName.split('.');
    let len = missionArray.length;
    return missionArray[len - 1];
  }
  return '';
}

@Entry
@Component
struct Index {
  @State deviceManager: DeviceManager = DeviceManager.getInstance();
  @StorageLink('isReady') isReady: boolean = false
  @StorageLink('isUpdate') isUpdate: boolean = false
  @StorageLink('continueResult') continueResult: string = '0'
  scroller: Scroller = new Scroller()
  build() {
    Row() {
      Column() {
        Button("InitDeviceList")
          .fontSize('25fp')
          .width('80%')
          .height('5%')
          .onClick(() => {
            Logger.info(' On button InitDeviceList');
            AppStorage.setOrCreate('isReady', true);
            if (this.deviceManager) {
              DeviceManager.releaseIns();
              this.deviceManager = DeviceManager.getInstance();
            }

          })
        Blank().height('2.5%')
        Button("faultCase")
          .fontSize('25fp')
          .width('80%')
          .height('5%')
          .onClick(() => {
            router.pushUrl({ url: 'pages/faultCase' })
          })
        Blank().height('2.5%')
        Row() {
          Text("Continuation")
            .fontSize('40fp')
            .fontWeight(FontWeight.Bold)
        }
        Blank().height('2.5%')
        if (this.isUpdate||true) {
          if (this.isReady) {
            Scroll(this.scroller){
              Row(){
                Text("本机:"+this.deviceManager.localDevice.deviceInfo.deviceName)
                  .textAlign(TextAlign.Center)
                  .fontColor(Color.Black)
                  .backgroundColor(this.deviceManager.localDevice.color)
                  .fontSize('20fp')
                  .width(100)
                  .height(60)
                  .borderRadius(20)
                  .onClick(() => {
                    let networkId = CommonTools.getInstance().getNetworkId(this.deviceManager.localDevice);
                    this.deviceManager.fromDeviceId = networkId;
                    this.deviceManager.currentDevice=this.deviceManager.localDevice
                    this.deviceManager.update()
                  })
                  .onDragEnter((event: DragEvent) => {
                    this.deviceManager.localDevice.color=Color.Blue
                    this.deviceManager.update()
                  })
                  .onDragLeave((event: DragEvent) => {
                    this.deviceManager.localDevice.color=Color.Grey
                    this.deviceManager.update()
                  })
                  .onDrop((event: DragEvent, extraParams: string) => {
                    if(this.deviceManager.localDevice.deviceInfo.networkId &&
                      this.deviceManager.fromDeviceId!=this.deviceManager.localDevice.deviceInfo.networkId) {
                      let networkId = CommonTools.getInstance().getNetworkId(this.deviceManager.localDevice);
                      this.deviceManager.toDeviceId = networkId;
                      Logger.info("fromDeviceId: "+this.deviceManager.fromDeviceId)
                      Logger.info("missionId: "+this.deviceManager.fromMissionId.toString())
                      Logger.info("toDeviceId: "+this.deviceManager.toDeviceId)
                      this.deviceManager.localDevice.color = Color.Green
                      this.deviceManager.onSelectToDevice(this.deviceManager.localDevice.deviceInfo.networkId)
                      this.deviceManager.onContinueAbility()
                    } else {
                      Logger.info("the same device")
                      this.deviceManager.localDevice.color = Color.Grey
                      this.deviceManager.update()
                    }
                  })
                Blank().width(10)
                ForEach(this.deviceManager.trustedDeviceList, (item: Device) => {
                  Text(item.deviceInfo.deviceName)
                    .textAlign(TextAlign.Center)
                    .fontColor(Color.Black)
                    .backgroundColor(item.color)
                    .fontSize('20fp')
                    .width(100)
                    .height(60)
                    .borderRadius(20)
                    .onClick(() => {
                      let networkId = CommonTools.getInstance().getNetworkId(item);
                      this.deviceManager.fromDeviceId = networkId;
                      this.deviceManager.currentDevice=item
                      this.deviceManager.update()
                    })
                    .onDragEnter((event: DragEvent) => {
                      item.color=Color.Blue
                      this.deviceManager.update()
                    })
                    .onDragLeave((event: DragEvent) => {
                      item.color=Color.Grey
                      this.deviceManager.update()
                    })
                    .onDrop((event: DragEvent, extraParams: string) => {
                      if (this.deviceManager.localDevice.deviceInfo.networkId &&
                        this.deviceManager.fromDeviceId == this.deviceManager.localDevice.deviceInfo.networkId) {
                        let networkId = CommonTools.getInstance().getNetworkId(item);
                        this.deviceManager.toDeviceId = networkId;
                        Logger.info("fromDeviceId: "+this.deviceManager.fromDeviceId)
                        Logger.info("missionId: "+this.deviceManager.fromMissionId.toString())
                        Logger.info("toDeviceId: "+this.deviceManager.toDeviceId)
                        item.color = Color.Green
                        this.deviceManager.onSelectToDevice(item.deviceInfo.networkId)
                        this.deviceManager.onContinueAbility()
                      }
                      else{
                        Logger.info("must to local")
                        this.deviceManager.localDevice.color = Color.Grey
                        this.deviceManager.update()
                      }
                    })
                  Blank().width(10)
                })
              }
            }
            Blank().height(20)
            Text(this.deviceManager.currentDevice.deviceInfo.deviceName)
              .textAlign(TextAlign.Center)
              .fontColor(Color.Black)
              .backgroundColor("")
              .fontSize('20fp')
            Blank().height(50)

            List({ space: 20, initialIndex: 0 }) {
              ForEach(this.deviceManager.currentDevice.missionList, (item: Mission) => {
                ListItem() {
                  Row() {
                    Text(getBundleNameFromMissionInfo(item))
                      .width(200)
                      .height(300)
                      .fontSize('30fp')
                      .textAlign(TextAlign.Center)
                      .borderRadius(10)
                      .backgroundColor(Color.Grey)
                  }
                }
                .onDragStart(() => {
                  this.deviceManager.fromMissionId=item.missionInfo.missionId
                  Logger.info("onDragStart")
                  return this.pixelMapBuilder
                })
              })
            }
            .listDirection(Axis.Horizontal)
            .height('70%')
          }
        }
      }
      .width('100%')
    }
    .height('100%')
  }
  @Builder pixelMapBuilder() {
    Column() {
      Text(this.deviceManager.fromMissionId.toString())
        .width('100%').height('100%').fontSize("30fp").borderRadius(10)
        .textAlign(TextAlign.Center).backgroundColor(Color.Grey)
        .opacity(0.5)
    }
    .width(200)
    .height(300)
  }
}
class TrustedDevice {
  localDeviceId: string
  localMission: number[]

  constructor(deviceid: string, mission: number[]) {
    this.localDeviceId = deviceid
    this.localMission = mission
  }
}