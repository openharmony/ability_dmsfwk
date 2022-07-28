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

import rpc from '@ohos.rpc';
import ServiceExtensionAbility from '@ohos.application.ServiceExtensionAbility';
var printLog = '[ServiceExtension]'

class MyServiceExtensionAbilityStub extends rpc.RemoteObject {
    constructor(des) {
        super(des)
    }

    onRemoteRequest(code, data, reply, option) {
        showLog(printLog + "MyServiceExtensionAbility onRemoteRequest call")
        if (code === 1) {
            globalThis.receiveMessage = data.readString()
            showLog(printLog + "receive message : " + globalThis.receiveMessage)
        } else {
            showLog(printLog + "unknown request code")
        }
        reply.writeString("MyServiceExtensionAbility receive your message")
        return true
    }

    queryLocalInterface(descriptor) {
        return null
    }

    getInterfaceDescriptor() {
        return ''
    }

    sendRequest(code, data, reply, option) {
        return null
    }

    getCallingPid() {
        return 1
    }

    getCallingUid() {
        return 1
    }

    attachLocalInterface(localInterface, descriptor) {}
}

function showLog(logMessage) {
    console.log(logMessage)
    AppStorage.Set<string>("receiveMessage", AppStorage.Get<string>("receiveMessage") + logMessage + "\n")
}

export default class MyServiceExtensionAbility extends ServiceExtensionAbility {
    onCreate(want) {
        console.log(printLog + 'MyServiceExtensionAbility OnCreate, want : ' + want.abilityName)
    }
    onRequest(want) {
        console.log(printLog + 'MyServiceExtensionAbility onRequest, want : ' + want.abilityName)
    }
    onConnect(want) {
        showLog(printLog + 'MyServiceExtensionAbility onConnect, want : ' + want.abilityName)
        return new MyServiceExtensionAbilityStub('test')
    }
    onDisconnect(want) {
        showLog(printLog + 'MyServiceExtensionAbility onDisconnect, want : ' + want.abilityName)
    }
    onDestroy() {
        console.log(printLog + 'MyServiceExtensionAbility onDestroy')
    }
}