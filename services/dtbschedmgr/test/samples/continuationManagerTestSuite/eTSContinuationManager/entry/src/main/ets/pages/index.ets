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

import prompt from '@system.prompt';
import { GlobalThis } from './GlobalThis';

@Entry
@Component
struct Index {
  scroller: Scroller = new Scroller();

  aboutToAppear() {
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
              GlobalThis.register();
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
              GlobalThis.registerWithExtraParams();
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
              GlobalThis.registerWithInvalidFilter();
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
              GlobalThis.registerWithoutFilter();
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
              GlobalThis.registerWithInvalidContinuationMode();
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
              GlobalThis.onDeviceConnect();
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
              GlobalThis.onDeviceConnectWithInvalidToken();
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
              GlobalThis.onDeviceDisconnect();
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
              GlobalThis.onDeviceDisconnectWithInvalidToken();
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
              GlobalThis.startDeviceManager();
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
              GlobalThis.startDeviceManagerWithExtraParam();
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
              GlobalThis.startDeviceManagerWithInvalidToken();
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
              GlobalThis.startDeviceManagerWithInvalidFilter();
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
              GlobalThis.startDeviceManagerWithoutFilter();
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
              GlobalThis.startDeviceManagerWithInvalidContinuationMode();
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
              GlobalThis.updateConnectStatus();
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
              GlobalThis.updateConnectStatusWithInvalidToken();
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
              GlobalThis.updateConnectStatusWithInvalidDeviceId();
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
              GlobalThis.updateConnectStatusWithInvalidConnectStatus();
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
              GlobalThis.offDeviceConnect();
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
              GlobalThis.offDeviceConnectWithInvalidToken();
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
              GlobalThis.offDeviceDisconnect();
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
              GlobalThis.offDeviceDisconnectWithInvalidToken();
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
              GlobalThis.unregister();
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
              GlobalThis.unregisterWithInvalidToken();
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
              GlobalThis.startRemoteAbility();
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
              GlobalThis.connectRemoteAbility();
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