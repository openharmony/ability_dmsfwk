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

import { GlobalThis } from '../Model/GlobalThis';
import router from '@ohos.router';
import RemoteDeviceModel from '../Model/RemoteDeviceModel';
import distributedDeviceManager from '@ohos.distributedDeviceManager';

const remoteDeviceModel = new RemoteDeviceModel();
let printLog = '[ServiceExtensionDemo]'
AppStorage.link<string>("message")
AppStorage.link<string>("receiveMessage")

@Entry
@Component
struct Index {
  @State selectDeviceName : string = "";
  @State DeviceIdList: string[] = [];
  @StorageLink("message") message : string = "";
  @StorageLink("receiveMessage") receiveMessage : string = "";

  RegisterDeviceListCallback() {
    remoteDeviceModel.registerDeviceListCallback(()=>{
      this.DeviceIdList = [];
      let deviceSize = remoteDeviceModel.deviceList.length;
      for (let i = 0; i < deviceSize; ++i) {
        this.DeviceIdList.push(remoteDeviceModel.deviceList[i].networkId);
      }
    })
  }

  build() {
    Column() {
      Row() {
        Text("select device id : " + this.selectDeviceName)
          .width('100%')
          .height('100%')
          .fontSize(20)
          .textAlign(TextAlign.Start)
      }
        .height('10%')
        .width('100%')

      Row() {
        Column() {
          Button('back')
            .width(100)
            .height(50)
            .onClick(() => {
              router.back();
            })
          Button('InitDeviceList')
            .width(100)
            .height(50)
            .onClick(() => {
              this.RegisterDeviceListCallback();
            })
          Button('connect')
            .width(100)
            .height(50)
            .onClick(() => {
              GlobalThis.ConnectRemoteAbility();
            })

          Button('discon')
            .width(100)
            .height(50)
            .onClick(() => {
              GlobalThis.DisconnectRemoteAbility();
            })

          List({ space: 10, initialIndex: 0}) {
            ForEach(GlobalThis.DeviceIdList, (item : string) => {
              ListItem() {
                Button(item)
                  .width('100%').height(50).fontSize(10)
                  .onClick(() => {
                    console.log(printLog + "select device : " + item)
                    this.selectDeviceName = item
                    GlobalThis.selectDevice = item
                    AppStorage.set<string>('receiveMessage', AppStorage.get<string>("receiveMessage") + "select device:" + item + '\n')
                  })
              }//.editable(true);
            }, (item : string) => item.toString())
          }.height('75%').width('100%').borderWidth(1).align(Alignment.Start)
        }.width('30%').height('100%').padding(5)

        Column() {
          Text('日志')
            .height('5%')
            .width('100%')
            .fontSize(20)
            .borderWidth(1)
            .textAlign(TextAlign.Center)
            .backdropBlur(Color.Gray)

          Scroll() {
            Text(this.receiveMessage)
              .width('100%')
              .fontSize(15)
              .textAlign(TextAlign.Start)
          }.scrollBar(BarState.Auto)
          .height('55%')
          .align(Alignment.Start)
          .borderWidth(1)

          Text("待发送数据：")
            .height('5%')
            .width('100%')
            .fontSize(20)
            .borderWidth(1)
            .textAlign(TextAlign.Center)
            .backgroundColor(Color.Gray)

          Text(this.message)
            .height('10%')
            .width('100%')
            .fontSize(15)
            .borderWidth(1)
            .textAlign(TextAlign.Start)

          TextInput({text: "输入消息"})
            .width('100%')
            .height('10%')
            .borderStyle(BorderStyle.Solid)
            .type(InputType.Normal)
            .onChange((value : string) => {
              AppStorage.set<string>('message', value)
            })

          Row() {
            Button('send')
              .width(100)
              .height(50)
              .onClick(() => {
                GlobalThis.SendMessage();
              })
          }.height('15%')
        }.width('70%').height('100%')
      }.width('100%').height('90%')
    }.width('100%').height('100%')
  }
}