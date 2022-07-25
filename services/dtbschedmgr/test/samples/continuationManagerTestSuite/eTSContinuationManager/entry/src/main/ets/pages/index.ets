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

import prompt from '@system.prompt';

@Entry
@Component
struct Index {
  private scroller: Scroller = new Scroller();

  private aboutToAppear() {
    prompt.showToast({
      message: "MainAbility aboutToAppear"
    });
  }

  build() {
    Row() {
      Column() {

        Scroll(this.scroller) {
          Column() {

            Button() {
              Text('register')
                .fontSize(20)
                .fontWeight(FontWeight.Bold)
            }
            .type(ButtonType.Capsule)
            .margin({
              top: 20
            })
            .backgroundColor('#0D9FFB')
            .width(350)
            .height(30)
            .onClick(() => {
              globalThis.register();
            })

            Button() {
              Text('registerWithExtraParams')
                .fontSize(20)
                .fontWeight(FontWeight.Bold)
            }
            .type(ButtonType.Capsule)
            .margin({
              top: 20
            })
            .backgroundColor('#0D9FFB')
            .width(350)
            .height(30)
            .onClick(() => {
              globalThis.registerWithExtraParams();
            })

            Button() {
              Text('registerWithInvalidFilter')
                .fontSize(20)
                .fontWeight(FontWeight.Bold)
            }
            .type(ButtonType.Capsule)
            .margin({
              top: 20
            })
            .backgroundColor('#0D9FFB')
            .width(350)
            .height(30)
            .onClick(() => {
              globalThis.registerWithInvalidFilter();
            })

            Button() {
              Text('registerWithoutFilter')
                .fontSize(20)
                .fontWeight(FontWeight.Bold)
            }
            .type(ButtonType.Capsule)
            .margin({
              top: 20
            })
            .backgroundColor('#0D9FFB')
            .width(350)
            .height(30)
            .onClick(() => {
              globalThis.registerWithoutFilter();
            })

            Button() {
              Text('registerWithInvalidContinuationMode')
                .fontSize(20)
                .fontWeight(FontWeight.Bold)
            }
            .type(ButtonType.Capsule)
            .margin({
              top: 20
            })
            .backgroundColor('#0D9FFB')
            .width(350)
            .height(30)
            .onClick(() => {
              globalThis.registerWithInvalidContinuationMode();
            })

            Button() {
              Text('onDeviceConnect')
                .fontSize(20)
                .fontWeight(FontWeight.Bold)
            }
            .type(ButtonType.Capsule)
            .margin({
              top: 20
            })
            .backgroundColor('#0D9FFB')
            .width(350)
            .height(30)
            .onClick(() => {
              globalThis.onDeviceConnect();
            })

            Button() {
              Text('onDeviceConnectWithInvalidToken')
                .fontSize(20)
                .fontWeight(FontWeight.Bold)
            }
            .type(ButtonType.Capsule)
            .margin({
              top: 20
            })
            .backgroundColor('#0D9FFB')
            .width(350)
            .height(30)
            .onClick(() => {
              globalThis.onDeviceConnectWithInvalidToken();
            })

            Button() {
              Text('onDeviceDisconnect')
                .fontSize(20)
                .fontWeight(FontWeight.Bold)
            }
            .type(ButtonType.Capsule)
            .margin({
              top: 20
            })
            .backgroundColor('#0D9FFB')
            .width(350)
            .height(30)
            .onClick(() => {
              globalThis.onDeviceDisconnect();
            })

            Button() {
              Text('onDeviceDisconnectWithInvalidToken')
                .fontSize(20)
                .fontWeight(FontWeight.Bold)
            }
            .type(ButtonType.Capsule)
            .margin({
              top: 20
            })
            .backgroundColor('#0D9FFB')
            .width(350)
            .height(30)
            .onClick(() => {
              globalThis.onDeviceDisconnectWithInvalidToken();
            })

            Button() {
              Text('startDeviceManager')
                .fontSize(20)
                .fontWeight(FontWeight.Bold)
            }
            .type(ButtonType.Capsule)
            .margin({
              top: 20
            })
            .backgroundColor('#0D9FFB')
            .width(350)
            .height(30)
            .onClick(() => {
              globalThis.startDeviceManager();
            })

            Button() {
              Text('startDeviceManagerWithExtraParam')
                .fontSize(20)
                .fontWeight(FontWeight.Bold)
            }
            .type(ButtonType.Capsule)
            .margin({
              top: 20
            })
            .backgroundColor('#0D9FFB')
            .width(350)
            .height(30)
            .onClick(() => {
              globalThis.startDeviceManagerWithExtraParam();
            })

            Button() {
              Text('startDeviceManagerWithInvalidToken')
                .fontSize(20)
                .fontWeight(FontWeight.Bold)
            }
            .type(ButtonType.Capsule)
            .margin({
              top: 20
            })
            .backgroundColor('#0D9FFB')
            .width(350)
            .height(30)
            .onClick(() => {
              globalThis.startDeviceManagerWithInvalidToken();
            })

            Button() {
              Text('startDeviceManagerWithInvalidFilter')
                .fontSize(20)
                .fontWeight(FontWeight.Bold)
            }
            .type(ButtonType.Capsule)
            .margin({
              top: 20
            })
            .backgroundColor('#0D9FFB')
            .width(350)
            .height(30)
            .onClick(() => {
              globalThis.startDeviceManagerWithInvalidFilter();
            })

            Button() {
              Text('startDeviceManagerWithoutFilter')
                .fontSize(20)
                .fontWeight(FontWeight.Bold)
            }
            .type(ButtonType.Capsule)
            .margin({
              top: 20
            })
            .backgroundColor('#0D9FFB')
            .width(350)
            .height(30)
            .onClick(() => {
              globalThis.startDeviceManagerWithoutFilter();
            })

            Button() {
              Text('startDeviceManagerWithInvalidContinuationMode')
                .fontSize(20)
                .fontWeight(FontWeight.Bold)
            }
            .type(ButtonType.Capsule)
            .margin({
              top: 20
            })
            .backgroundColor('#0D9FFB')
            .width(350)
            .height(30)
            .onClick(() => {
              globalThis.startDeviceManagerWithInvalidContinuationMode();
            })

            Button() {
              Text('updateConnectStatus')
                .fontSize(20)
                .fontWeight(FontWeight.Bold)
            }
            .type(ButtonType.Capsule)
            .margin({
              top: 20
            })
            .backgroundColor('#0D9FFB')
            .width(350)
            .height(30)
            .onClick(() => {
              globalThis.updateConnectStatus();
            })

            Button() {
              Text('updateConnectStatusWithInvalidToken')
                .fontSize(20)
                .fontWeight(FontWeight.Bold)
            }
            .type(ButtonType.Capsule)
            .margin({
              top: 20
            })
            .backgroundColor('#0D9FFB')
            .width(350)
            .height(30)
            .onClick(() => {
              globalThis.updateConnectStatusWithInvalidToken();
            })

            Button() {
              Text('updateConnectStatusWithInvalidDeviceId')
                .fontSize(20)
                .fontWeight(FontWeight.Bold)
            }
            .type(ButtonType.Capsule)
            .margin({
              top: 20
            })
            .backgroundColor('#0D9FFB')
            .width(350)
            .height(30)
            .onClick(() => {
              globalThis.updateConnectStatusWithInvalidDeviceId();
            })

            Button() {
              Text('updateConnectStatusWithInvalidConnectStatus')
                .fontSize(20)
                .fontWeight(FontWeight.Bold)
            }
            .type(ButtonType.Capsule)
            .margin({
              top: 20
            })
            .backgroundColor('#0D9FFB')
            .width(350)
            .height(30)
            .onClick(() => {
              globalThis.updateConnectStatusWithInvalidConnectStatus();
            })

            Button() {
              Text('offDeviceConnect')
                .fontSize(20)
                .fontWeight(FontWeight.Bold)
            }
            .type(ButtonType.Capsule)
            .margin({
              top: 20
            })
            .backgroundColor('#0D9FFB')
            .width(350)
            .height(30)
            .onClick(() => {
              globalThis.offDeviceConnect();
            })

            Button() {
              Text('offDeviceConnectWithInvalidToken')
                .fontSize(20)
                .fontWeight(FontWeight.Bold)
            }
            .type(ButtonType.Capsule)
            .margin({
              top: 20
            })
            .backgroundColor('#0D9FFB')
            .width(350)
            .height(30)
            .onClick(() => {
              globalThis.offDeviceConnectWithInvalidToken();
            })

            Button() {
              Text('offDeviceDisconnect')
                .fontSize(20)
                .fontWeight(FontWeight.Bold)
            }
            .type(ButtonType.Capsule)
            .margin({
              top: 20
            })
            .backgroundColor('#0D9FFB')
            .width(350)
            .height(30)
            .onClick(() => {
              globalThis.offDeviceDisconnect();
            })

            Button() {
              Text('offDeviceDisconnectWithInvalidToken')
                .fontSize(20)
                .fontWeight(FontWeight.Bold)
            }
            .type(ButtonType.Capsule)
            .margin({
              top: 20
            })
            .backgroundColor('#0D9FFB')
            .width(350)
            .height(30)
            .onClick(() => {
              globalThis.offDeviceDisconnectWithInvalidToken();
            })

            Button() {
              Text('unregister')
                .fontSize(20)
                .fontWeight(FontWeight.Bold)
            }
            .type(ButtonType.Capsule)
            .margin({
              top: 20
            })
            .backgroundColor('#0D9FFB')
            .width(350)
            .height(30)
            .onClick(() => {
              globalThis.unregister();
            })

            Button() {
              Text('unregisterWithInvalidToken')
                .fontSize(20)
                .fontWeight(FontWeight.Bold)
            }
            .type(ButtonType.Capsule)
            .margin({
              top: 20
            })
            .backgroundColor('#0D9FFB')
            .width(350)
            .height(30)
            .onClick(() => {
              globalThis.unregisterWithInvalidToken();
            })

            Button() {
              Text('startRemoteAbility')
                .fontSize(20)
                .fontWeight(FontWeight.Bold)
            }
            .type(ButtonType.Capsule)
            .margin({
              top: 20
            })
            .backgroundColor('#0D9FFB')
            .width(350)
            .height(30)
            .onClick(() => {
              globalThis.startRemoteAbility();
            })

            Button() {
              Text('connectRemoteAbility')
                .fontSize(20)
                .fontWeight(FontWeight.Bold)
            }
            .type(ButtonType.Capsule)
            .margin({
              top: 20
            })
            .backgroundColor('#0D9FFB')
            .width(350)
            .height(30)
            .onClick(() => {
              globalThis.connectRemoteAbility();
            })

          }
        }
        .width("100%").height("100%")
      }
      .width('100%')
    }
    .height('100%')
  }
}