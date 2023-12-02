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
import abilityAccessCtrl, { Permissions } from "@ohos.abilityAccessCtrl";
import bundle from '@ohos.bundle';
import continuationManager from '@ohos.continuation.continuationManager';
import prompt from '@system.prompt';
import rpc from '@ohos.rpc'
import bundleManager from '@ohos.bundle.bundleManager';
import Want from '@ohos.app.ability.Want';

const SHOW_TOAST_TIME = 3000; // ms
const DEVICE_TYPE = "00E";
const INVALID_TOKEN = 1000000000;
const INVALID_CONTINUATION_MODE = 30;
const INVALID_CONNECT_STATUS = 30;

let mRemote;
let connectedAbility;
let token = -1;



function registerContinuation(): void {
    console.info('[Demo]registerContinuation begin');
    continuationManager.registerContinuation()
    .then((data) => {
        console.info('[Demo]registerContinuation finished, ' + JSON.stringify(data));
        token = data;
        prompt.showToast({
            message: "[Demo]registerContinuation token: " + JSON.stringify(data),
            duration: SHOW_TOAST_TIME
        });
    })
    .catch((err) => {
        console.error('[Demo]registerContinuation failed, cause: ' + JSON.stringify(err));
        prompt.showToast({
            message: "[Demo]registerContinuation err: " + err,
            duration: SHOW_TOAST_TIME
        });
    });
    console.info('[Demo]registerContinuation end');
}

function registerWithExtraParams(): void {
    console.info('[Demo]registerWithExtraParams begin');
    let continuationExtraParams = {
        deviceType: [DEVICE_TYPE],
        targetBundle: "targetBundle",
        description: "description",
        filter: {"name": "filter", "length": 6},
        continuationMode: continuationManager.ContinuationMode.COLLABORATION_MULTIPLE,
        authInfo: {"name": "authInfo", "length": 8}
    };
    continuationManager.registerContinuation(continuationExtraParams)
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

function registerWithInvalidFilter(): void {
    console.info('[Demo]registerWithInvalidFilter begin');
    let continuationExtraParams = {
        deviceType: [DEVICE_TYPE],
        targetBundle: "targetBundle",
        description: "description",
        filter: "invalid filter",
        continuationMode: continuationManager.ContinuationMode.COLLABORATION_MULTIPLE,
        authInfo: {"name": "authInfo", "length": 8}
    };
    continuationManager.registerContinuation(continuationExtraParams)
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

function registerWithoutFilter(): void {
    console.info('[Demo]registerWithoutFilter begin');
    let continuationExtraParams = {
        deviceType: [DEVICE_TYPE],
        targetBundle: "targetBundle",
        description: "description",
        continuationMode: continuationManager.ContinuationMode.COLLABORATION_MULTIPLE,
        authInfo: {"name": "authInfo", "length": 8}
    };
    continuationManager.registerContinuation(continuationExtraParams)
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

function registerWithInvalidContinuationMode(): void {
    console.info('[Demo]registerWithInvalidContinuationMode begin');
    let continuationExtraParams = {
        deviceType: [DEVICE_TYPE],
        targetBundle: "targetBundle",
        description: "description",
        filter: {"name": "filter", "length": 6},
        continuationMode: INVALID_CONTINUATION_MODE,
        authInfo: {"name": "authInfo", "length": 8}
    };
    continuationManager.registerContinuation(continuationExtraParams)
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

function onDeviceConnect() : void{
    console.info('[Demo]onDeviceConnect begin');
    continuationManager.on("deviceSelected", token, (data) => {
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

function onDeviceConnectWithInvalidToken(): void {
    console.info('[Demo]onDeviceConnectWithInvalidToken begin');
    continuationManager.on("deviceSelected", INVALID_TOKEN, (data) => {
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

function onDeviceDisconnect(): void {
    console.info('[Demo]onDeviceDisconnect begin');
    continuationManager.on("deviceUnselected", token, (data) => {
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

function onDeviceDisconnectWithInvalidToken(): void {
    console.info('[Demo]onDeviceDisconnectWithInvalidToken begin');
    continuationManager.on("deviceUnselected", INVALID_TOKEN, (data) => {
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

function startContinuationDeviceManager(): void {
    console.info('[Demo]startContinuationDeviceManager begin');
    continuationManager.startContinuationDeviceManager(token)
    .then((data) => {
        console.info('[Demo]startContinuationDeviceManager finished, ' + JSON.stringify(data));
        prompt.showToast({
            message: "[Demo]startContinuationDeviceManager data: " + JSON.stringify(data),
            duration: SHOW_TOAST_TIME
        });
    })
    .catch((err) => {
        console.error('[Demo]startContinuationDeviceManager failed, cause: ' + JSON.stringify(err));
        prompt.showToast({
            message: "[Demo]startContinuationDeviceManager err: " + err,
            duration: SHOW_TOAST_TIME
        });
    });
    console.info('[Demo]startContinuationDeviceManager end');
}

function startDeviceManagerWithExtraParam(): void {
    console.info('[Demo]startDeviceManagerWithExtraParam begin');
    let continuationExtraParams = {
        deviceType: [DEVICE_TYPE],
        targetBundle: "targetBundle",
        description: "description",
        filter: {"name": "filter", "length": 6},
        continuationMode: continuationManager.ContinuationMode.COLLABORATION_MULTIPLE,
        authInfo: {"name": "authInfo", "length": 8}
    };
    continuationManager.startContinuationDeviceManager(token, continuationExtraParams)
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

function startDeviceManagerWithInvalidToken(): void {
    console.info('[Demo]startDeviceManagerWithInvalidToken begin');
    continuationManager.startContinuationDeviceManager(INVALID_TOKEN)
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

function startDeviceManagerWithInvalidFilter(): void {
    console.info('[Demo]startDeviceManagerWithInvalidFilter begin');
    let continuationExtraParams = {
        deviceType: [DEVICE_TYPE],
        targetBundle: "targetBundle",
        description: "description",
        filter: "invalid filter",
        continuationMode: continuationManager.ContinuationMode.COLLABORATION_MULTIPLE,
        authInfo: {"name": "authInfo", "length": 8}
    };
    continuationManager.startContinuationDeviceManager(token, continuationExtraParams)
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

function startDeviceManagerWithoutFilter(): void {
    console.info('[Demo]startDeviceManagerWithoutFilter begin');
    let continuationExtraParams = {
        deviceType: [DEVICE_TYPE],
        targetBundle: "targetBundle",
        description: "description",
        continuationMode: continuationManager.ContinuationMode.COLLABORATION_MULTIPLE,
        authInfo: {"name": "authInfo", "length": 8}
    };
    continuationManager.startContinuationDeviceManager(token, continuationExtraParams)
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

function startDeviceManagerWithInvalidContinuationMode(): void {
    console.info('[Demo]startDeviceManagerWithInvalidContinuationMode begin');
    let continuationExtraParams = {
        deviceType: [DEVICE_TYPE],
        targetBundle: "targetBundle",
        description: "description",
        filter: {"name": "filter", "length": 6},
        continuationMode: INVALID_CONTINUATION_MODE,
        authInfo: {"name": "authInfo", "length": 8}
    };
    continuationManager.startContinuationDeviceManager(token, continuationExtraParams)
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

function updateContinuationState(): void {
    console.info('[Demo]updateContinuationState begin');
    let deviceId: string = "test deviceId";
    let deviceConnectStatus = continuationManager.DeviceConnectState.CONNECTED;
    continuationManager.updateContinuationState(token, deviceId, deviceConnectStatus)
    .then((data) => {
        console.info('[Demo]updateContinuationState finished, ' + JSON.stringify(data));
        prompt.showToast({
            message: "[Demo]updateContinuationState data: " + JSON.stringify(data),
            duration: SHOW_TOAST_TIME
        });
    })
    .catch((err) => {
        console.error('[Demo]updateContinuationState failed, cause: ' + JSON.stringify(err));
        prompt.showToast({
            message: "[Demo]updateContinuationState err: " + err,
            duration: SHOW_TOAST_TIME
        });
    });
    console.info('[Demo]updateContinuationState end');
}

function updateConnectStatusWithInvalidToken(): void {
    console.info('[Demo]updateConnectStatusWithInvalidToken begin');
    let deviceId: string = "test deviceId";
    let deviceConnectStatus = continuationManager.DeviceConnectState.CONNECTED;
    continuationManager.updateContinuationState(INVALID_TOKEN, deviceId, deviceConnectStatus)
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

function updateConnectStatusWithInvalidDeviceId(): void {
    console.info('[Demo]updateConnectStatusWithInvalidDeviceId begin');
    let deviceId: string = "";
    let deviceConnectStatus = continuationManager.DeviceConnectState.CONNECTED;
    continuationManager.updateContinuationState(token, deviceId, deviceConnectStatus)
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

function updateConnectStatusWithInvalidConnectStatus(): void {
    console.info('[Demo]updateConnectStatusWithInvalidConnectStatus begin');
    let deviceId: string = "test deviceId";
    let deviceConnectStatus = INVALID_CONNECT_STATUS;
    continuationManager.updateContinuationState(token, deviceId, deviceConnectStatus)
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

function offDeviceConnect(): void {
    console.info('[Demo]offDeviceConnect begin');
    continuationManager.off("deviceSelected", token);
    console.info('[Demo]offDeviceConnect end');
}

function offDeviceConnectWithInvalidToken(): void {
    console.info('[Demo]offDeviceConnectWithInvalidToken begin');
    continuationManager.off("deviceSelected", INVALID_TOKEN);
    console.info('[Demo]offDeviceConnectWithInvalidToken end');
}

function offDeviceDisconnect(): void {
    console.info('[Demo]offDeviceDisconnect begin');
    continuationManager.off("deviceUnselected", token);
    console.info('[Demo]offDeviceDisconnect end');
}

function offDeviceDisconnectWithInvalidToken(): void {
    console.info('[Demo]offDeviceDisconnectWithInvalidToken begin');
    continuationManager.off("deviceUnselected", INVALID_TOKEN);
    console.info('[Demo]offDeviceDisconnectWithInvalidToken end');
}

function unregisterContinuation(): void {
    console.info('[Demo]unregisterContinuation begin');
    continuationManager.unregisterContinuation(token)
    .then((data) => {
        console.info('[Demo]unregisterContinuation finished, ' + JSON.stringify(data));
        prompt.showToast({
            message: "[Demo]unregisterContinuation data: " + JSON.stringify(data),
            duration: SHOW_TOAST_TIME
        });
    })
    .catch((err) => {
        console.error('[Demo]unregisterContinuation failed, cause: ' + JSON.stringify(err));
        prompt.showToast({
            message: "[Demo]unregisterContinuation err: " + err,
            duration: SHOW_TOAST_TIME
        });
    });
    console.info('[Demo]unregisterContinuation end');
}

function unregisterWithInvalidToken(): void {
    console.info('[Demo]unregisterWithInvalidToken begin');
    continuationManager.unregisterContinuation(INVALID_TOKEN)
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

function startRemoteAbility(): void {
    let token = -1;
    continuationManager.registerContinuation()
    .then((data) => {
        console.info('[Demo]registerContinuation finished, ' + JSON.stringify(data));
        token = data;
        globalThis.token = data;
        console.info('[Demo]startRemoteAbility registerContinuation token = ' + globalThis.token);
        continuationManager.on("deviceSelected", token, (data) => {
            console.info('[Demo]registerDeviceConnectCallback len: ' + data.length);
            if (data.length <= 0) {
                console.info('[Demo]no selected device');
                return;
            }
            for (let i = 0; i < data.length; i++) {
                startRemoteAbilityWithDeviceId(data[i].id);
            }
        });
        continuationManager.startContinuationDeviceManager(token)
        .then((data) => {
            console.info('[Demo]startContinuationDeviceManager finished, ' + JSON.stringify(data));
        })
        .catch((err) => {
            console.error('[Demo]startContinuationDeviceManager failed, cause: ' + JSON.stringify(err));
        });
    })
    .catch((err) => {
        console.error('[Demo]registerContinuation failed, cause: ' + JSON.stringify(err));
    });
}

function startRemoteAbilityWithDeviceId(remoteDeviceId): void {
    console.info('[Demo]startRemoteAbilityWithDeviceId remoteDeviceId = ' + remoteDeviceId);
    let want: Want = {
        deviceId: remoteDeviceId,
        bundleName: 'ohos.samples.continuationmanager',
        abilityName: 'MainAbility'
    };
    globalThis.context.startAbility(want).then((data) => {
        console.info('StartRemoteAbility finished, ' + JSON.stringify(data));
    });
}

function connectRemoteAbility(): void {
    let token = -1;
    continuationManager.registerContinuation()
    .then((data) => {
        console.info('[Demo]registerContinuation finished, ' + JSON.stringify(data));
        token = data;
        globalThis.token = data;
        console.info('[Demo]connectRemoteAbility registerContinuation token = ' + globalThis.token);
        continuationManager.on("deviceSelected", token, (data) => {
            console.info('[Demo]registerDeviceConnectCallback len: ' + data.length);
            if (data.length <= 0) {
                console.info('[Demo]no selected device');
                return;
            }
            for (let i = 0; i < data.length; i++) {
                connectRemoteAbilityWithDeviceId(data[i].id);
            }
        });
        continuationManager.startContinuationDeviceManager(token)
        .then((data) => {
            console.info('[Demo]startContinuationDeviceManager finished, ' + JSON.stringify(data));
        })
        .catch((err) => {
            console.error('[Demo]startContinuationDeviceManager failed, cause: ' + JSON.stringify(err));
        });
    })
    .catch((err) => {
        console.error('[Demo]registerContinuation failed, cause: ' + JSON.stringify(err));
    });
}

function connectRemoteAbilityWithDeviceId(remoteDeviceId): void {
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
        let data = new rpc.MessageSequence();
        let reply = new rpc.MessageSequence();
        data.writeInt(1);
        data.writeInt(99);
        await mRemote.sendRequest(1, data, reply, option);
        let msg = reply.readInt();
        prompt.showToast({
            message: "connectRemoteAbilityWithDeviceId connect result: " + msg,
            duration: SHOW_TOAST_TIME
        });
    }
    function onDisconnectCallback(element): void {
        console.log('[Demo]connectRemoteAbilityWithDeviceId onDisconnectDone element: ' + element);
    }
    function onFailedCallback(code): void {
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
    //获取当前应用的权限的授予状态：grantStatus（授予返回：0，未授予：-1）
    async getGrantStatus(permission: Permissions): Promise<abilityAccessCtrl.GrantStatus>{
        let atManager = abilityAccessCtrl.createAtManager();
        let grantStatus : abilityAccessCtrl.GrantStatus = -1;

        //获取tokenId:
        let tokenId :number = 0;
        try {
            let bundleInfo: bundleManager.BundleInfo = await bundleManager.getBundleInfoForSelf(bundleManager.BundleFlag.GET_BUNDLE_INFO_WITH_APPLICATION);
            let appInfo: bundleManager.ApplicationInfo = bundleInfo.appInfo;
            tokenId = appInfo.accessTokenId;
        }catch (err){
            console.info('Failed to get bundle info for self,cause ${public}s' ,JSON.stringify(err)??'');
        }

        // 检验应用是否被授予此权限，授予返回：PERMISSION_GRANTED = 0，未授予：PERMISSION_DENIED = -1
        try {
            grantStatus = await atManager.checkAccessToken(tokenId,permission);
        }catch (err){
            console.info('Failed to check Access Token ,cause %{public}s' ,JSON.stringify(err)??'');
        }

        return grantStatus;
    }

    //检验权限授予情况&动态申请权限
    async checkPermissions():Promise<void>{
        const permissions:Array<Permissions> = ['ohos.permission.DISTRIBUTED_DATASYNC'];

        let grantStatus:abilityAccessCtrl.GrantStatus = await this.getGrantStatus(permissions[0]);
        // 检验权限授予情况
        if(grantStatus === abilityAccessCtrl.GrantStatus.PERMISSION_GRANTED){
            //已授予
            console.info('Permission already granted.');
        }else{
            //未授予,向用户弹框动态申请授权
            let atManager = abilityAccessCtrl.createAtManager();
            try {
                atManager.requestPermissionsFromUser(this.context, ['ohos.permission.DISTRIBUTED_DATASYNC'], (err, data) => {
                    console.info('data: ' + JSON.stringify(data));
                });
            }catch (err){
                console.info('catch err ,' + JSON.stringify(err)??'');
                return;
            }
        }
    }
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
        this.checkPermissions();

        globalThis.registerContinuation = (()=>{ registerContinuation(); })
        globalThis.registerWithExtraParams = (()=>{ registerWithExtraParams(); })
        globalThis.registerWithInvalidFilter = (()=>{ registerWithInvalidFilter(); })
        globalThis.registerWithoutFilter = (()=>{ registerWithoutFilter(); })
        globalThis.registerWithInvalidContinuationMode = (()=>{ registerWithInvalidContinuationMode(); })
        globalThis.onDeviceConnect = (()=>{ onDeviceConnect(); })
        globalThis.onDeviceConnectWithInvalidToken = (()=>{ onDeviceConnectWithInvalidToken(); })
        globalThis.onDeviceDisconnect = (()=>{ onDeviceDisconnect(); })
        globalThis.onDeviceDisconnectWithInvalidToken = (()=>{ onDeviceDisconnectWithInvalidToken(); })
        globalThis.startContinuationDeviceManager = (()=>{ startContinuationDeviceManager(); })
        globalThis.startDeviceManagerWithExtraParam = (()=>{ startDeviceManagerWithExtraParam(); })
        globalThis.startDeviceManagerWithInvalidToken = (()=>{ startDeviceManagerWithInvalidToken(); })
        globalThis.startDeviceManagerWithInvalidFilter = (()=>{ startDeviceManagerWithInvalidFilter(); })
        globalThis.startDeviceManagerWithoutFilter = (()=>{ startDeviceManagerWithoutFilter(); })
        globalThis.startDeviceManagerWithInvalidContinuationMode = (()=>{ startDeviceManagerWithInvalidContinuationMode(); })
        globalThis.updateContinuationState = (()=>{ updateContinuationState(); })
        globalThis.updateConnectStatusWithInvalidToken = (()=>{ updateConnectStatusWithInvalidToken(); })
        globalThis.updateConnectStatusWithInvalidDeviceId = (()=>{ updateConnectStatusWithInvalidDeviceId(); })
        globalThis.updateConnectStatusWithInvalidConnectStatus = (()=>{ updateConnectStatusWithInvalidConnectStatus(); })
        globalThis.offDeviceConnect = (()=>{ offDeviceConnect(); })
        globalThis.offDeviceConnectWithInvalidToken = (()=>{ offDeviceConnectWithInvalidToken(); })
        globalThis.offDeviceDisconnect = (()=>{ offDeviceDisconnect(); })
        globalThis.offDeviceDisconnectWithInvalidToken = (()=>{ offDeviceDisconnectWithInvalidToken(); })
        globalThis.unregisterContinuation = (()=>{ unregisterContinuation(); })
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
        console.info('[Demo]onBackground unregisterContinuation, token = ' + globalThis.token);
        continuationManager.unregisterContinuation(globalThis.token)
        .then((data) => {
            console.info('[Demo]unregisterContinuation finished, ' + JSON.stringify(data));
        })
        .catch((err) => {
            console.error('[Demo]unregisterContinuation failed, cause: ' + JSON.stringify(err));
        });
    }
};
