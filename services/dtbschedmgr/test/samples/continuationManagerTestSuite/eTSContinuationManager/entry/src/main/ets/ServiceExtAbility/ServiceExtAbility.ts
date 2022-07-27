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

import Extension from '@ohos.application.ServiceExtensionAbility'
import rpc from '@ohos.rpc'

class StubTest extends rpc.RemoteObject {
    constructor(des) {
        super(des);
    }
    onRemoteRequest(code, data, reply, option) {
        console.info('[Demo]onRemoteRequest');
        if (code === 1) {
            let op1 = data.readInt();
            let op2 = data.readInt();
            console.log("op1 = " + op1 + ", op2 = " + op2);
            reply.writeInt(op1 + op2);
        } else {
            console.log("[Demo]StubTest unknown request code");
        }
        return true;
    }
    queryLocalInterface(descriptor) {
        return null;
    }
    getInterfaceDescriptor() {
        return "";
    }
    sendRequest(code, data, reply, options) {
        return null;
    }
    getCallingPid() {
        return START_DEVICE_MANAGER;
    }
    getCallingUid() {
        return START_DEVICE_MANAGER;
    }
    attachLocalInterface(localInterface, descriptor){}
}

export default class ServiceExtAbility extends Extension {
    onCreate(want) {
        globalThis.mainAbilityContext = this.context;
        console.info('[Demo]onCreate, want: ' + want.abilityName);
    }
    onRequest(want, startId) {
        console.info('[Demo]onRequest, want: ' + want.abilityName);
    }
    onConnect(want) {
        console.info('[Demo]onConnect, want: ' + want.abilityName);
        return new StubTest("test");
    }
    onDisconnect(want) {
        console.info('[Demo]onDisconnect, want: ' + want.abilityName);
    }
    onDestroy() {
        console.info('[Demo]onDestroy');
    }
}