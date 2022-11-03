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

import Ability from '@ohos.app.ability.UIAbility'
import abilityAccessCtrl from "@ohos.abilityAccessCtrl";
import bundle from '@ohos.bundle';
import continuationManager from '@ohos.continuation.continuationManager';
import prompt from '@system.prompt';
import rpc from '@ohos.rpc'

const SHOW_TOAST_TIME = 3000; // ms
const DEVICE_TYPE = "00E";
const INVALID_TOKEN = 1000000000;
const INVALID_CONTINUATION_MODE = 30;
const INVALID_CONNECT_STATUS = 30;

let mRemote;
let connectedAbility;
let token = -1;

async function requestPermission() {
    let permissions: Array<string> = [
        "ohos.permission.DISTRIBUTED_DATASYNC"
    ];
    let needGrantPermission = false;
    let accessManger = abilityAccessCtrl.createAtManager();

    let bundleInfo = await bundle.getApplicationInfo('ohos.samples.continuationmanager', 0, 100)
    for (const permission of permissions) {
        console.info('[Demo]app permission query grant status' + permission);
        try {
            let grantStatus = await accessManger.verifyAccessToken(bundleInfo.accessTokenId, permission);
            if (grantStatus === abilityAccessCtrl.GrantStatus.PERMISSION_DENIED) {
                needGrantPermission = true;
                break;
            }
        } catch (err) {
            console.error('[Demo]app permission query grant status error' + JSON.stringify(err));
            needGrantPermission = true;
            break;
        }
    }
    if (needGrantPermission) {
        console.info('[Demo]app permission needGrantPermission');
        try {
            await globalThis.context.requestPermissionsFromUser(permissions);
        } catch (err) {
            console.error('[Demo]app permission' + JSON.stringify(err));
        }
    } else {
        console.info('[Demo]app permission already granted');
    }
}

function register() {
    console.info('[Demo]register begin');
    continuationManager.register()
    .then((data) => {
        console.info('[Demo]register finished, ' + JSON.stringify(data));
        token = data;
        prompt.showToast({
            message: "[Demo]register token: " + JSON.stringify(data),
            duration: SHOW_TOAST_TIME
        });
    })
    .catch((err) => {
        console.error('[Demo]register failed, cause: ' + JSON.stringify(err));
        prompt.showToast({
            message: "[Demo]register err: " + err,
            duration: SHOW_TOAST_TIME
        });
    });
    console.info('[Demo]register end');
}

function registerWithExtraParams() {
    console.info('[Demo]registerWithExtraParams begin');
    let continuationExtraParams = {
        deviceType: [DEVICE_TYPE],
        targetBundle: "targetBundle",
        description: "description",
        filter: {"name": "filter", "length": 6},
        continuationMode: continuationManager.ContinuationMode.COLLABORATION_MULTIPLE,
        authInfo: {"name": "authInfo", "length": 8}
    };
    continuationManager.register(continuationExtraParams)
    .then((data) => {
        console.info('[Demo]registerWithExtraParams finished, ' + JSON.stringify(data));
        token = data;
        prompt.showToast({
            message: "[Demo]registerWithExtraParams token: " + JSON.stringify(data),
            duration: SHOW_TOAST_TIME
        });
    })
    .catch((err) => {
        console.error('[Demo]registerWithExtraParams failed, cause: ' + JSON.stringify(err));
        prompt.showToast({
            message: "[Demo]registerWithExtraParams err: " + err,
            duration: SHOW_TOAST_TIME
        });
    });
    console.info('[Demo]registerWithExtraParams end');
}

function registerWithInvalidFilter() {
    console.info('[Demo]registerWithInvalidFilter begin');
    let continuationExtraParams = {
        deviceType: [DEVICE_TYPE],
        targetBundle: "targetBundle",
        description: "description",
        filter: "invalid filter",
        continuationMode: continuationManager.ContinuationMode.COLLABORATION_MULTIPLE,
        authInfo: {"name": "authInfo", "length": 8}
    };
    continuationManager.register(continuationExtraParams)
    .then((data) => {
        console.info('[Demo]registerWithInvalidFilter finished, ' + JSON.stringify(data));
        token = data;
        prompt.showToast({
            message: "[Demo]registerWithInvalidFilter token: " + JSON.stringify(data),
            duration: SHOW_TOAST_TIME
        });
    })
    .catch((err) => {
        console.error('[Demo]registerWithInvalidFilter failed, cause: ' + JSON.stringify(err));
        prompt.showToast({
            message: "[Demo]registerWithInvalidFilter err: " + err,
            duration: SHOW_TOAST_TIME
        });
    });
    console.info('[Demo]registerWithInvalidFilter end');
}

function registerWithoutFilter() {
    console.info('[Demo]registerWithoutFilter begin');
    let continuationExtraParams = {
        deviceType: [DEVICE_TYPE],
        targetBundle: "targetBundle",
        description: "description",
        continuationMode: continuationManager.ContinuationMode.COLLABORATION_MULTIPLE,
        authInfo: {"name": "authInfo", "length": 8}
    };
    continuationManager.register(continuationExtraParams)
    .then((data) => {
        console.info('[Demo]registerWithoutFilter finished, ' + JSON.stringify(data));
        token = data;
        prompt.showToast({
            message: "[Demo]registerWithoutFilter token: " + JSON.stringify(data),
            duration: SHOW_TOAST_TIME
        });
    })
    .catch((err) => {
        console.error('[Demo]registerWithoutFilter failed, cause: ' + JSON.stringify(err));
        prompt.showToast({
            message: "[Demo]registerWithoutFilter err: " + err,
            duration: SHOW_TOAST_TIME
        });
    });
    console.info('[Demo]registerWithoutFilter end');
}

function registerWithInvalidContinuationMode() {
    console.info('[Demo]registerWithInvalidContinuationMode begin');
    let continuationExtraParams = {
        deviceType: [DEVICE_TYPE],
        targetBundle: "targetBundle",
        description: "description",
        filter: {"name": "filter", "length": 6},
        continuationMode: INVALID_CONTINUATION_MODE,
        authInfo: {"name": "authInfo", "length": 8}
    };
    continuationManager.register(continuationExtraParams)
    .then((data) => {
        console.info('[Demo]registerWithInvalidContinuationMode finished, ' + JSON.stringify(data));
        token = data;
        prompt.showToast({
            message: "[Demo]registerWithInvalidContinuationMode token: " + JSON.stringify(data),
            duration: SHOW_TOAST_TIME
        });
    })
    .catch((err) => {
        console.error('[Demo]registerWithInvalidContinuationMode failed, cause: ' + JSON.stringify(err));
        prompt.showToast({
            message: "[Demo]registerWithInvalidContinuationMode err: " + err,
            duration: SHOW_TOAST_TIME
        });
    });
    console.info('[Demo]registerWithInvalidContinuationMode end');
}

function onDeviceConnect() {
    console.info('[Demo]onDeviceConnect begin');
    continuationManager.on("deviceConnect", token, (data) => {
        console.info('[Demo]onDeviceConnect len: ' + data.length);
        for (let i = 0; i < data.length; i++) {
            console.info('[Demo]onDeviceConnect deviceId: ' + JSON.stringify(data[i].id));
            console.info('[Demo]onDeviceConnect deviceType: ' + JSON.stringify(data[i].type));
            console.info('[Demo]onDeviceConnect deviceName: ' + JSON.stringify(data[i].name));
        }
        prompt.showToast({
            message: "[Demo]onDeviceConnect continuationResults: " + JSON.stringify(data),
            duration: SHOW_TOAST_TIME
        });
        console.info('[Demo]onDeviceConnect finished.');
    });
    console.info('[Demo]onDeviceConnect end');
}

function onDeviceConnectWithInvalidToken() {
    console.info('[Demo]onDeviceConnectWithInvalidToken begin');
    continuationManager.on("deviceConnect", INVALID_TOKEN, (data) => {
        console.info('[Demo]onDeviceConnectWithInvalidToken len: ' + data.length);
        for (let i = 0; i < data.length; i++) {
            console.info('[Demo]onDeviceConnectWithInvalidToken deviceId: ' + JSON.stringify(data[i].id));
            console.info('[Demo]onDeviceConnectWithInvalidToken deviceType: ' + JSON.stringify(data[i].type));
            console.info('[Demo]onDeviceConnectWithInvalidToken deviceName: ' + JSON.stringify(data[i].name));
        }
        prompt.showToast({
            message: "[Demo]onDeviceConnectWithInvalidToken continuationResults: " + JSON.stringify(data),
            duration: SHOW_TOAST_TIME
        });
        console.info('[Demo]onDeviceConnectWithInvalidToken finished.');
    });
    console.info('[Demo]onDeviceConnectWithInvalidToken end');
}

function onDeviceDisconnect() {
    console.info('[Demo]onDeviceDisconnect begin');
    continuationManager.on("deviceDisconnect", token, (data) => {
        console.info('[Demo]onDeviceDisconnect len: ' + data.length);
        for (let i = 0; i < data.length; i++) {
            console.info('[Demo]onDeviceDisconnect deviceId: ' + JSON.stringify(data[i]));
        }
        prompt.showToast({
            message: "[Demo]onDeviceDisconnect deviceIds: " + JSON.stringify(data),
            duration: SHOW_TOAST_TIME
        });
        console.info('[Demo]onDeviceDisconnect finished.');
    });
    console.info('[Demo]onDeviceDisconnect end');
}

function onDeviceDisconnectWithInvalidToken() {
    console.info('[Demo]onDeviceDisconnectWithInvalidToken begin');
    continuationManager.on("deviceDisconnect", INVALID_TOKEN, (data) => {
        console.info('[Demo]onDeviceDisconnectWithInvalidToken len: ' + data.length);
        for (let i = 0; i < data.length; i++) {
            console.info('[Demo]onDeviceDisconnectWithInvalidToken deviceId: ' + JSON.stringify(data[i]));
        }
        prompt.showToast({
            message: "[Demo]onDeviceDisconnectWithInvalidToken deviceIds: " + JSON.stringify(data),
            duration: SHOW_TOAST_TIME
        });
        console.info('[Demo]onDeviceDisconnectWithInvalidToken finished.');
    });
    console.info('[Demo]onDeviceDisconnectWithInvalidToken end');
}

function startDeviceManager() {
    console.info('[Demo]startDeviceManager begin');
    continuationManager.startDeviceManager(token)
    .then((data) => {
        console.info('[Demo]startDeviceManager finished, ' + JSON.stringify(data));
        prompt.showToast({
            message: "[Demo]startDeviceManager data: " + JSON.stringify(data),
            duration: SHOW_TOAST_TIME
        });
    })
    .catch((err) => {
        console.error('[Demo]startDeviceManager failed, cause: ' + JSON.stringify(err));
        prompt.showToast({
            message: "[Demo]startDeviceManager err: " + err,
            duration: SHOW_TOAST_TIME
        });
    });
    console.info('[Demo]startDeviceManager end');
}

function startDeviceManagerWithExtraParam() {
    console.info('[Demo]startDeviceManagerWithExtraParam begin');
    let continuationExtraParams = {
        deviceType: [DEVICE_TYPE],
        targetBundle: "targetBundle",
        description: "description",
        filter: {"name": "filter", "length": 6},
        continuationMode: continuationManager.ContinuationMode.COLLABORATION_MULTIPLE,
        authInfo: {"name": "authInfo", "length": 8}
    };
    continuationManager.startDeviceManager(token, continuationExtraParams)
    .then((data) => {
        console.info('[Demo]startDeviceManagerWithExtraParam finished, ' + JSON.stringify(data));
        prompt.showToast({
            message: "[Demo]startDeviceManagerWithExtraParam data: " + JSON.stringify(data),
            duration: SHOW_TOAST_TIME
        });
    })
    .catch((err) => {
        console.error('[Demo]startDeviceManagerWithExtraParam failed, cause: ' + JSON.stringify(err));
        prompt.showToast({
            message: "[Demo]startDeviceManagerWithExtraParam err: " + err,
            duration: SHOW_TOAST_TIME
        });
    });
    console.info('[Demo]startDeviceManagerWithExtraParam end');
}

function startDeviceManagerWithInvalidToken() {
    console.info('[Demo]startDeviceManagerWithInvalidToken begin');
    continuationManager.startDeviceManager(INVALID_TOKEN)
    .then((data) => {
        console.info('[Demo]startDeviceManagerWithInvalidToken finished, ' + JSON.stringify(data));
        prompt.showToast({
            message: "[Demo]startDeviceManagerWithInvalidToken data: " + JSON.stringify(data),
            duration: SHOW_TOAST_TIME
        });
    })
    .catch((err) => {
        console.error('[Demo]startDeviceManagerWithInvalidToken failed, cause: ' + JSON.stringify(err));
        prompt.showToast({
            message: "[Demo]startDeviceManagerWithInvalidToken err: " + err,
            duration: SHOW_TOAST_TIME
        });
    });
    console.info('[Demo]startDeviceManagerWithInvalidToken end');
}

function startDeviceManagerWithInvalidFilter() {
    console.info('[Demo]startDeviceManagerWithInvalidFilter begin');
    let continuationExtraParams = {
        deviceType: [DEVICE_TYPE],
        targetBundle: "targetBundle",
        description: "description",
        filter: "invalid filter",
        continuationMode: continuationManager.ContinuationMode.COLLABORATION_MULTIPLE,
        authInfo: {"name": "authInfo", "length": 8}
    };
    continuationManager.startDeviceManager(token, continuationExtraParams)
    .then((data) => {
        console.info('[Demo]startDeviceManagerWithInvalidFilter finished, ' + JSON.stringify(data));
        prompt.showToast({
            message: "[Demo]startDeviceManagerWithInvalidFilter data: " + JSON.stringify(data),
            duration: SHOW_TOAST_TIME
        });
    })
    .catch((err) => {
        console.error('[Demo]startDeviceManagerWithInvalidFilter failed, cause: ' + JSON.stringify(err));
        prompt.showToast({
            message: "[Demo]startDeviceManagerWithInvalidFilter err: " + err,
            duration: SHOW_TOAST_TIME
        });
    });
    console.info('[Demo]startDeviceManagerWithInvalidFilter end');
}

function startDeviceManagerWithoutFilter() {
    console.info('[Demo]startDeviceManagerWithoutFilter begin');
    let continuationExtraParams = {
        deviceType: [DEVICE_TYPE],
        targetBundle: "targetBundle",
        description: "description",
        continuationMode: continuationManager.ContinuationMode.COLLABORATION_MULTIPLE,
        authInfo: {"name": "authInfo", "length": 8}
    };
    continuationManager.startDeviceManager(token, continuationExtraParams)
    .then((data) => {
        console.info('[Demo]startDeviceManagerWithoutFilter finished, ' + JSON.stringify(data));
        prompt.showToast({
            message: "[Demo]startDeviceManagerWithoutFilter data: " + JSON.stringify(data),
            duration: SHOW_TOAST_TIME
        });
    })
    .catch((err) => {
        console.error('[Demo]startDeviceManagerWithoutFilter failed, cause: ' + JSON.stringify(err));
        prompt.showToast({
            message: "[Demo]startDeviceManagerWithoutFilter err: " + err,
            duration: SHOW_TOAST_TIME
        });
    });
    console.info('[Demo]startDeviceManagerWithoutFilter end');
}

function startDeviceManagerWithInvalidContinuationMode() {
    console.info('[Demo]startDeviceManagerWithInvalidContinuationMode begin');
    let continuationExtraParams = {
        deviceType: [DEVICE_TYPE],
        targetBundle: "targetBundle",
        description: "description",
        filter: {"name": "filter", "length": 6},
        continuationMode: INVALID_CONTINUATION_MODE,
        authInfo: {"name": "authInfo", "length": 8}
    };
    continuationManager.startDeviceManager(token, continuationExtraParams)
    .then((data) => {
        console.info('[Demo]startDeviceManagerWithInvalidContinuationMode finished, ' + JSON.stringify(data));
        prompt.showToast({
            message: "[Demo]startDeviceManagerWithInvalidContinuationMode data: " + JSON.stringify(data),
            duration: SHOW_TOAST_TIME
        });
    })
    .catch((err) => {
        console.error('[Demo]startDeviceManagerWithInvalidContinuationMode failed, cause: ' + JSON.stringify(err));
        prompt.showToast({
            message: "[Demo]startDeviceManagerWithInvalidContinuationMode err: " + err,
            duration: SHOW_TOAST_TIME
        });
    });
    console.info('[Demo]startDeviceManagerWithInvalidContinuationMode end');
}

function updateConnectStatus() {
    console.info('[Demo]updateConnectStatus begin');
    let deviceId: string = "test deviceId";
    let deviceConnectStatus = continuationManager.DeviceConnectState.CONNECTED;
    continuationManager.updateConnectStatus(token, deviceId, deviceConnectStatus)
    .then((data) => {
        console.info('[Demo]updateConnectStatus finished, ' + JSON.stringify(data));
        prompt.showToast({
            message: "[Demo]updateConnectStatus data: " + JSON.stringify(data),
            duration: SHOW_TOAST_TIME
        });
    })
    .catch((err) => {
        console.error('[Demo]updateConnectStatus failed, cause: ' + JSON.stringify(err));
        prompt.showToast({
            message: "[Demo]updateConnectStatus err: " + err,
            duration: SHOW_TOAST_TIME
        });
    });
    console.info('[Demo]updateConnectStatus end');
}

function updateConnectStatusWithInvalidToken() {
    console.info('[Demo]updateConnectStatusWithInvalidToken begin');
    let deviceId: string = "test deviceId";
    let deviceConnectStatus = continuationManager.DeviceConnectState.CONNECTED;
    continuationManager.updateConnectStatus(INVALID_TOKEN, deviceId, deviceConnectStatus)
    .then((data) => {
        console.info('[Demo]updateConnectStatusWithInvalidToken finished, ' + JSON.stringify(data));
        prompt.showToast({
            message: "[Demo]updateConnectStatusWithInvalidToken data: " + JSON.stringify(data),
            duration: SHOW_TOAST_TIME
        });
    })
    .catch((err) => {
        console.error('[Demo]updateConnectStatusWithInvalidToken failed, cause: ' + JSON.stringify(err));
        prompt.showToast({
            message: "[Demo]updateConnectStatusWithInvalidToken err: " + err,
            duration: SHOW_TOAST_TIME
        });
    });
    console.info('[Demo]updateConnectStatusWithInvalidToken end');
}

function updateConnectStatusWithInvalidDeviceId() {
    console.info('[Demo]updateConnectStatusWithInvalidDeviceId begin');
    let deviceId: string = "";
    let deviceConnectStatus = continuationManager.DeviceConnectState.CONNECTED;
    continuationManager.updateConnectStatus(token, deviceId, deviceConnectStatus)
    .then((data) => {
        console.info('[Demo]updateConnectStatusWithInvalidDeviceId finished, ' + JSON.stringify(data));
        prompt.showToast({
            message: "[Demo]updateConnectStatusWithInvalidDeviceId data: " + JSON.stringify(data),
            duration: SHOW_TOAST_TIME
        });
    })
    .catch((err) => {
        console.error('[Demo]updateConnectStatusWithInvalidDeviceId failed, cause: ' + JSON.stringify(err));
        prompt.showToast({
            message: "[Demo]updateConnectStatusWithInvalidDeviceId err: " + err,
            duration: SHOW_TOAST_TIME
        });
    });
    console.info('[Demo]updateConnectStatusWithInvalidDeviceId end');
}

function updateConnectStatusWithInvalidConnectStatus() {
    console.info('[Demo]updateConnectStatusWithInvalidConnectStatus begin');
    let deviceId: string = "test deviceId";
    let deviceConnectStatus = INVALID_CONNECT_STATUS;
    continuationManager.updateConnectStatus(token, deviceId, deviceConnectStatus)
    .then((data) => {
        console.info('[Demo]updateConnectStatusWithInvalidConnectStatus finished, ' + JSON.stringify(data));
        prompt.showToast({
            message: "[Demo]updateConnectStatusWithInvalidConnectStatus data: " + JSON.stringify(data),
            duration: SHOW_TOAST_TIME
        });
    })
    .catch((err) => {
        console.error('[Demo]updateConnectStatusWithInvalidConnectStatus failed, cause: ' + JSON.stringify(err));
        prompt.showToast({
            message: "[Demo]updateConnectStatusWithInvalidConnectStatus err: " + err,
            duration: SHOW_TOAST_TIME
        });
    });
    console.info('[Demo]updateConnectStatusWithInvalidConnectStatus end');
}

function offDeviceConnect() {
    console.info('[Demo]offDeviceConnect begin');
    continuationManager.off("deviceConnect", token);
    console.info('[Demo]offDeviceConnect end');
}

function offDeviceConnectWithInvalidToken() {
    console.info('[Demo]offDeviceConnectWithInvalidToken begin');
    continuationManager.off("deviceConnect", INVALID_TOKEN);
    console.info('[Demo]offDeviceConnectWithInvalidToken end');
}

function offDeviceDisconnect() {
    console.info('[Demo]offDeviceDisconnect begin');
    continuationManager.off("deviceDisconnect", token);
    console.info('[Demo]offDeviceDisconnect end');
}

function offDeviceDisconnectWithInvalidToken() {
    console.info('[Demo]offDeviceDisconnectWithInvalidToken begin');
    continuationManager.off("deviceDisconnect", INVALID_TOKEN);
    console.info('[Demo]offDeviceDisconnectWithInvalidToken end');
}

function unregister() {
    console.info('[Demo]unregister begin');
    continuationManager.unregister(token)
    .then((data) => {
        console.info('[Demo]unregister finished, ' + JSON.stringify(data));
        prompt.showToast({
            message: "[Demo]unregister data: " + JSON.stringify(data),
            duration: SHOW_TOAST_TIME
        });
    })
    .catch((err) => {
        console.error('[Demo]unregister failed, cause: ' + JSON.stringify(err));
        prompt.showToast({
            message: "[Demo]unregister err: " + err,
            duration: SHOW_TOAST_TIME
        });
    });
    console.info('[Demo]unregister end');
}

function unregisterWithInvalidToken() {
    console.info('[Demo]unregisterWithInvalidToken begin');
    continuationManager.unregister(INVALID_TOKEN)
    .then((data) => {
        console.info('[Demo]unregisterWithInvalidToken finished, ' + JSON.stringify(data));
        prompt.showToast({
            message: "[Demo]unregisterWithInvalidToken data: " + JSON.stringify(data),
            duration: SHOW_TOAST_TIME
        });
    })
    .catch((err) => {
        console.error('[Demo]unregisterWithInvalidToken failed, cause: ' + JSON.stringify(err));
        prompt.showToast({
            message: "[Demo]unregisterWithInvalidToken err: " + err,
            duration: SHOW_TOAST_TIME
        });
    });
    console.info('[Demo]unregisterWithInvalidToken end');
}

function startRemoteAbility() {
    let token = -1;
    continuationManager.register()
    .then((data) => {
        console.info('[Demo]register finished, ' + JSON.stringify(data));
        token = data;
        globalThis.token = data;
        console.info('[Demo]startRemoteAbility register token = ' + globalThis.token);
        continuationManager.on("deviceConnect", token, (data) => {
            console.info('[Demo]registerDeviceConnectCallback len: ' + data.length);
            if (data.length <= 0) {
                console.info('[Demo]no selected device');
                return;
            }
            for (let i = 0; i < data.length; i++) {
                startRemoteAbilityWithDeviceId(data[i].id);
            }
        });
        continuationManager.startDeviceManager(token)
        .then((data) => {
            console.info('[Demo]startDeviceManager finished, ' + JSON.stringify(data));
        })
        .catch((err) => {
            console.error('[Demo]startDeviceManager failed, cause: ' + JSON.stringify(err));
        });
    })
    .catch((err) => {
        console.error('[Demo]register failed, cause: ' + JSON.stringify(err));
    });
}

function startRemoteAbilityWithDeviceId(remoteDeviceId) {
    console.info('[Demo]startRemoteAbilityWithDeviceId remoteDeviceId = ' + remoteDeviceId);
    let want = {
        deviceId: remoteDeviceId,
        bundleName: 'ohos.samples.continuationmanager',
        abilityName: 'MainAbility'
    };
    globalThis.context.startAbility(want).then((data) => {
        console.info('StartRemoteAbility finished, ' + JSON.stringify(data));
    });
}

function connectRemoteAbility() {
    let token = -1;
    continuationManager.register()
    .then((data) => {
        console.info('[Demo]register finished, ' + JSON.stringify(data));
        token = data;
        globalThis.token = data;
        console.info('[Demo]connectRemoteAbility register token = ' + globalThis.token);
        continuationManager.on("deviceConnect", token, (data) => {
            console.info('[Demo]registerDeviceConnectCallback len: ' + data.length);
            if (data.length <= 0) {
                console.info('[Demo]no selected device');
                return;
            }
            for (let i = 0; i < data.length; i++) {
                connectRemoteAbilityWithDeviceId(data[i].id);
            }
        });
        continuationManager.startDeviceManager(token)
        .then((data) => {
            console.info('[Demo]startDeviceManager finished, ' + JSON.stringify(data));
        })
        .catch((err) => {
            console.error('[Demo]startDeviceManager failed, cause: ' + JSON.stringify(err));
        });
    })
    .catch((err) => {
        console.error('[Demo]register failed, cause: ' + JSON.stringify(err));
    });
}

function connectRemoteAbilityWithDeviceId(remoteDeviceId) {
    console.info('[Demo]connectRemoteAbilityWithDeviceId remoteDeviceId = ' + remoteDeviceId);
    async function onConnectCallback(element, remote) {
        console.log('[Demo]connectRemoteAbilityWithDeviceId onConnectDone element: ' + element);
        console.log('[Demo]connectRemoteAbilityWithDeviceId onConnectDone remote: ' + remote);
        mRemote = remote;
        if (mRemote == null) {
            prompt.showToast({
                message: "connectRemoteAbilityWithDeviceId not connected yet"
            });
            return;
        }
        let option = new rpc.MessageOption();
        let data = new rpc.MessageParcel();
        let reply = new rpc.MessageParcel();
        data.writeInt(1);
        data.writeInt(99);
        await mRemote.sendRequest(1, data, reply, option);
        let msg = reply.readInt();
        prompt.showToast({
            message: "connectRemoteAbilityWithDeviceId connect result: " + msg,
            duration: SHOW_TOAST_TIME
        });
    }
    function onDisconnectCallback(element) {
        console.log('[Demo]connectRemoteAbilityWithDeviceId onDisconnectDone element: ' + element);
    }
    function onFailedCallback(code) {
        console.log('[Demo]connectRemoteAbilityWithDeviceId onFailed errCode: ' + code);
    }
    connectedAbility = globalThis.context.connectAbility(
        {
            deviceId: remoteDeviceId,
            bundleName: "ohos.samples.continuationmanager",
            abilityName: "ServiceExtAbility",
        },
        {
            onConnect: onConnectCallback,
            onDisconnect: onDisconnectCallback,
            onFailed: onFailedCallback,
        },
    );
}

export default class MainAbility extends Ability {
    onCreate(want, launchParam) {
        console.log("[Demo] MainAbility onCreate")
        globalThis.abilityWant = want;
        globalThis.context = this.context;
    }

    onDestroy() {
        console.log("[Demo] MainAbility onDestroy")
    }

    onWindowStageCreate(windowStage) {
        // Main window is created, set main page for this ability
        console.log("[Demo] MainAbility onWindowStageCreate")
        requestPermission();

        globalThis.register = (()=>{ register(); })
        globalThis.registerWithExtraParams = (()=>{ registerWithExtraParams(); })
        globalThis.registerWithInvalidFilter = (()=>{ registerWithInvalidFilter(); })
        globalThis.registerWithoutFilter = (()=>{ registerWithoutFilter(); })
        globalThis.registerWithInvalidContinuationMode = (()=>{ registerWithInvalidContinuationMode(); })
        globalThis.onDeviceConnect = (()=>{ onDeviceConnect(); })
        globalThis.onDeviceConnectWithInvalidToken = (()=>{ onDeviceConnectWithInvalidToken(); })
        globalThis.onDeviceDisconnect = (()=>{ onDeviceDisconnect(); })
        globalThis.onDeviceDisconnectWithInvalidToken = (()=>{ onDeviceDisconnectWithInvalidToken(); })
        globalThis.startDeviceManager = (()=>{ startDeviceManager(); })
        globalThis.startDeviceManagerWithExtraParam = (()=>{ startDeviceManagerWithExtraParam(); })
        globalThis.startDeviceManagerWithInvalidToken = (()=>{ startDeviceManagerWithInvalidToken(); })
        globalThis.startDeviceManagerWithInvalidFilter = (()=>{ startDeviceManagerWithInvalidFilter(); })
        globalThis.startDeviceManagerWithoutFilter = (()=>{ startDeviceManagerWithoutFilter(); })
        globalThis.startDeviceManagerWithInvalidContinuationMode = (()=>{ startDeviceManagerWithInvalidContinuationMode(); })
        globalThis.updateConnectStatus = (()=>{ updateConnectStatus(); })
        globalThis.updateConnectStatusWithInvalidToken = (()=>{ updateConnectStatusWithInvalidToken(); })
        globalThis.updateConnectStatusWithInvalidDeviceId = (()=>{ updateConnectStatusWithInvalidDeviceId(); })
        globalThis.updateConnectStatusWithInvalidConnectStatus = (()=>{ updateConnectStatusWithInvalidConnectStatus(); })
        globalThis.offDeviceConnect = (()=>{ offDeviceConnect(); })
        globalThis.offDeviceConnectWithInvalidToken = (()=>{ offDeviceConnectWithInvalidToken(); })
        globalThis.offDeviceDisconnect = (()=>{ offDeviceDisconnect(); })
        globalThis.offDeviceDisconnectWithInvalidToken = (()=>{ offDeviceDisconnectWithInvalidToken(); })
        globalThis.unregister = (()=>{ unregister(); })
        globalThis.unregisterWithInvalidToken = (()=>{ unregisterWithInvalidToken(); })
        globalThis.startRemoteAbility = (()=>{ startRemoteAbility(); })
        globalThis.connectRemoteAbility = (()=>{ connectRemoteAbility(); })

        windowStage.setUIContent(this.context, "pages/index", null)
    }

    onWindowStageDestroy() {
        // Main window is destroyed, release UI related resources
        console.log("[Demo] MainAbility onWindowStageDestroy")
    }

    onForeground() {
        // Ability has brought to foreground
        console.log("[Demo] MainAbility onForeground")
    }

    onBackground() {
        // Ability has back to background
        console.log("[Demo] MainAbility onBackground")
        console.info('[Demo]onBackground unregister, token = ' + globalThis.token);
        continuationManager.unregister(globalThis.token)
        .then((data) => {
            console.info('[Demo]unregister finished, ' + JSON.stringify(data));
        })
        .catch((err) => {
            console.error('[Demo]unregister failed, cause: ' + JSON.stringify(err));
        });
    }
};
