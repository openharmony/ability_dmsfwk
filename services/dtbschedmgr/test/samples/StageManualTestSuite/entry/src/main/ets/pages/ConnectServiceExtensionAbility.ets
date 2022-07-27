/*
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
// @ts-nocheck
var printLog = '[ServiceExtensionDemo]'
AppStorage.Link("message")
AppStorage.Link("receiveMessage")

@Entry
@Component
struct Index {
  @State selectDeviceName : string = ""
  @StorageLink("message") message : string = ""
  @StorageLink("receiveMessage") receiveMessage : string = ""

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
          Button('connect')
            .width(100)
            .height(50)
            .onClick(() => {
              globalThis.ConnectRemoteAbility()
            })

          Button('discon')
            .width(100)
            .height(50)
            .onClick(() => {
              globalThis.DisconnectRemoteAbility()
            })

          List({ space: 10, initialIndex: 0}) {
            ForEach(globalThis.DeviceIdList, (item : string) => {
              ListItem() {
                Button(item)
                  .width('100%').height(50).fontSize(10)
                  .onClick(() => {
                    console.log(printLog + "select device : " + item)
                    this.selectDeviceName = item
                    globalThis.selectDevice = item
                    AppStorage.Set<string>('receiveMessage', AppStorage.Get<string>("receiveMessage") + "select device:" + item + '\n')
                  })
              }.editable(this.editFlag)
            }, (item : string) => item.toString())
          }.height('100%').width('100%').borderWidth(1).align(ItemAlign.Start)
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
          .align(ItemAlign.Start)
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

          TextInput("输入消息")
            .width('100%')
            .height('10%')
            .borderStyle(BorderStyle.Solid)
            .type(InputType.Normal)
            .onChange((value : string) => {
              AppStorage.Set<string>('message', value)
            })

          Row() {
            Button('send')
              .width(100)
              .height(50)
              .onClick(() => {
                globalThis.SendMessage()
              })
          }.height('15%')
        }.width('70%').height('100%')
      }.width('100%').height('90%')
    }.width('100%').height('100%')
  }
}