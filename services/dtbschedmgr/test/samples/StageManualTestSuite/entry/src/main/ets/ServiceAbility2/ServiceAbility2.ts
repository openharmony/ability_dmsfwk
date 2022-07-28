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
// @ts-nocheck

import ServiceExtensionAbility from '@ohos.application.ServiceExtensionAbility';
import wantConstant from '@ohos.ability.wantConstant'

export default class ServiceAbility2 extends ServiceExtensionAbility {
    onCreate() {
        console.info('ServiceAbility2 onCreate');
    }

    onRequest(want, startId) {
        console.info('ServiceAbility2 onRequest, want: ' + want.abilityName);
        console.info('ServiceAbility2 onRequest, startId: ' + startId);
        console.info('ServiceAbility2 onRequest');
        let str = {
            'deviceId': '',
            'bundleName': 'com.example.continue.hmservice',
            'abilityName': 'com.example.continue.ServiceAbility',
            'flags': wantConstant.Flags.FLAG_INSTALL_ON_DEMAND,
        }
        console.info('ServiceAbility2 onRequest START, str is : ' + JSON.stringify(str));

        let options ={
            windowMode: 0,
            displayId:2
        }
        console.info('ServiceAbility2 onRequest START, options is : ' + JSON.stringify(options));

        this.context.startAbility(str, options).then((data) => {
            console.log("ServiceAbility2 onRequest data: " + JSON.stringify(data))
        }).catch((error) => {
            console.log("ServiceAbility2 onRequest error: " + JSON.stringify(error))
        })
    }

    onDestroy() {
        console.info('ServiceAbility2 onDestroy');
    }
};