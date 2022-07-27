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
import router from '@system.router'

@Entry
@Component
struct Index {
  build() {
    Column() {
      Text("StageManualTestSuite")
        .width('100%')
        .height('10%')
        .fontSize(20)
        .textAlign(TextAlign.Center)

      Button('ConnectServiceExtensionAbility')
        .width("90%")
        .height(50)
        .onClick(() => {
          router.push({uri : 'pages/ConnectServiceExtensionAbility'})
        })

      Button('other')
        .width("90%")
        .height(50)
        .onClick(() => {
        })
    }.width('100%').height('100%')
  }
}