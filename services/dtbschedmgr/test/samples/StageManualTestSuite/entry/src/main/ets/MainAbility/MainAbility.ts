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

import Ability from '@ohos.application.Ability'
import RemoteDeviceModel from '../Model/RemoteDeviceModel'
import rpc from '@ohos.rpc'

var printLog = '[MainAbility]'
var remoteDeviceModel = new RemoteDeviceModel
var messageProxy = null
var connectedAbility

var options = {
    onConnect: async function (elementName, proxy) {
        showLog(printLog + "service extension ability connect success")
        if (proxy === null) {
            showLog("can not get proxy")
            return
        }
        messageProxy = proxy
        showLog(printLog + "get proxy, elementName: " + elementName)
    },
    onDisconnect: function () {
        showLog(printLog + "service extension ability disconnect success")
    },
    onFailed: function () {
        showLog(printLog + "service extension ability connect fail")
    }
}

function ConnectRemoteAbility() {
    showLog(printLog + "connect service extension ability begin")
    showLog(printLog + "connect remote device id is " + globalThis.selectDevice)
    let want = {
        bundleName: "com.dms.stage_manual_test_suite",
        abilityName: "MyServiceExtensionAbility",
        deviceId: globalThis.selectDevice
    }
    connectedAbility = globalThis.context.connectAbility(want, options)
    showLog(printLog + "connect service extension ability, connectId = " + connectedAbility)
}

async function DisconnectRemoteAbility() {
    showLog(printLog + "disconnect service extension ability begin")
    showLog(printLog + "disconnect remote device id is " + globalThis.selectDevice)
    await globalThis.context.disconnectAbility(connectedAbility)
    showLog(printLog + "disconnect service extension ability, connectId = " + connectedAbility)
    connectedAbility = null
}

async function SendMessage() {
    if (messageProxy === null) {
        showLog(printLog + "can not get proxy")
        return
    }
    showLog(printLog + "send message : " + AppStorage.Get<string>("message"))
    let option = new rpc.MessageOption()
    let data = new rpc.MessageParcel()
    let reply = new rpc.MessageParcel()
    data.writeString(AppStorage.Get<string>("message"))

    await messageProxy.sendRequest(1, data, reply, option)
    showLog(printLog + "send message success")

    globalThis.receiveMessage = reply.readString()
    showLog(printLog + "receive reply message : " + globalThis.receiveMessage)
}

function showLog(logMessage) {
    console.log(logMessage)
    AppStorage.Set<string>("receiveMessage", AppStorage.Get<string>("receiveMessage") + logMessage + "\n")
}

function RegisterDeviceListCallback() {
    remoteDeviceModel.registerDeviceListCallback(() => {
        let deviceSize = remoteDeviceModel.deviceList.length
        for (var i = 0; i < deviceSize; i++) {
            globalThis.DeviceIdList.push(remoteDeviceModel.deviceList[i].deviceId)
        }
    })
}

export default class MainAbility extends Ability {
    onCreate(want, launchParam) {
        console.log("[ServiceExtensionDemo] MainAbility onCreate")
        globalThis.abilityWant = want;
        globalThis.context = this.context
        globalThis.DeviceIdList = []
        globalThis.selectDevice
        globalThis.receiveMessage = ""
        RegisterDeviceListCallback()
    }

    onDestroy() {
        AppStorage.Set<string>("receiveMessage", "")
        console.log("[ServiceExtensionDemo] MainAbility onDestroy")
    }

    onWindowStageCreate(windowStage) {
        // Main window is created, set main page for this ability
        console.log("[ServiceExtension] MainAbility onWindowStageCreate")
        globalThis.ConnectRemoteAbility = ConnectRemoteAbility
        globalThis.DisconnectRemoteAbility = DisconnectRemoteAbility
        globalThis.SendMessage = SendMessage
        windowStage.loadContent("pages/MainPage", (err, data) => {
            if (err.code) {
                console.error('Failed to load the content. Cause:' + JSON.stringify(err));
                return;
            }
            console.info('Succeeded in loading the content. Data: ' + JSON.stringify(data))
        });
    }

    onWindowStageDestroy() {
        // Main window is destroyed, release UI related resources
        console.log("[ServiceExtension] MainAbility onWindowStageDestroy")
    }

    onForeground() {
        // Ability has brought to foreground
        console.log("[ServiceExtension] MainAbility onForeground")
    }

    onBackground() {
        // Ability has back to background
        console.log("[ServiceExtension] MainAbility onBackground")
    }
};
