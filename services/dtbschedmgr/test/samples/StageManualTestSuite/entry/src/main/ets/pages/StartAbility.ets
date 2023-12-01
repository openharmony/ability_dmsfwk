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

@Entry
@Component
struct Index {
  @State message: string = 'StartAbility'

  build() {
    Row() {
      Column() {
        Text(this.message)
          .fontSize(50)
          .fontWeight(FontWeight.Bold)

        Button() {
          Text('back to main page')
            .fontSize(20)
            .fontWeight(FontWeight.Bold);
        }
        .type(ButtonType.Capsule)
        .backgroundColor('#0D9FFB')
        .onClick(() => {
          router.back();
        })

        Button() {
          Text('config.json已配置targetBundleList值时 测本设备免安装')
            .fontSize($r('app.float.font_20'))
            .width('100%')
            .fontColor(Color.White)
            .align(Alignment.Center)
            .margin({ left: $r('app.float.wh_value_15'), right: $r('app.float.wh_value_15') })
        }
        .height($r('app.float.wh_value_60'))
        .margin({ left: $r('app.float.wh_value_15'), right: $r('app.float.wh_value_15') })
        .onClick(() => {
          routePage('pages/startAbilityAndStartAbilityForResultBsb')
        })

        Button() {
          Text('测跨设备免安装')
            .fontSize($r('app.float.font_20'))
            .width('100%')
            .fontColor(Color.White)
            .align(Alignment.Center)
            .margin({ left: $r('app.float.wh_value_15'), right: $r('app.float.wh_value_15') })
        }
        .height($r('app.float.wh_value_60'))
        .margin({ left: $r('app.float.wh_value_15'), right: $r('app.float.wh_value_15'),top:$r('app.float.wh_value_15') })
        .onClick(() => {
          routePage('pages/startAbilityKsb')
        })

        Button() {
          Text('config.json配置targetBundleList值未在清单中时测试')
            .fontSize($r('app.float.font_20'))
            .width('100%')
            .fontColor(Color.White)
            .align(Alignment.Center)
            .margin({ left: $r('app.float.wh_value_15'), right: $r('app.float.wh_value_15') })
            .alignSelf(ItemAlign.Center)
        }
        .height($r('app.float.wh_value_60'))
        .margin({ left: $r('app.float.wh_value_15'), right: $r('app.float.wh_value_15') ,top:$r('app.float.wh_value_15')})
        .onClick(() => {
          routePage('pages/targetBundleList')
        })
      }
      .height('100%')
    }
  }
}

async function routePage(page: string) {
  let options: router.RouterOptions = {
    url: page
  }
  try {
    await router.pushUrl(options)
  } catch (err) {
    console.error(`fail callback, code: ${JSON.stringify(err)}`);
  }
}

