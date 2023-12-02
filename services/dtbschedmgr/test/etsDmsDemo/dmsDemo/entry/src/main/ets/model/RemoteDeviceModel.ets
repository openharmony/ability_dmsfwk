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

import distributedDeviceManager from '@ohos.distributedDeviceManager';
import { Callback } from '@ohos.base';

let SUBSCRIBE_ID = 100;
let BundleName = 'com.ohos.distributedmusicplayer';

export default class RemoteDeviceModel {
    deviceList: distributedDeviceManager.DeviceBasicInfo[] = [];
    discoverList: distributedDeviceManager.DeviceBasicInfo[] = [];
    callback: Callback<void> = ()=>{};
    authCallback: Callback<void>| null = null;
    deviceManager = distributedDeviceManager.createDeviceManager(BundleName);

    constructor() {
    }

    registerDeviceListCallback(callback: Callback<void>) {
        if (typeof (this.deviceManager) === 'undefined') {
            this.deviceManager = distributedDeviceManager.createDeviceManager(BundleName);
            if (this.deviceManager) {
                console.info('create DeviceManager success');
                this.registerDeviceListCallback_(callback);
            } else {
                console.error('create DeviceManager error');
            }
            console.log('[dmsDemo] deviceManager.createDeviceManager begin');
        } else {
            this.registerDeviceListCallback_(callback);
        }
    }

    registerDeviceListCallback_(callback: Callback<void>) {
        console.info('[dmsDemo] registerDeviceListCallback');
        this.callback = callback;
        if (this.deviceManager == undefined) {
            console.error('[dmsDemo] deviceManager has not initialized');
            this.callback();
            return;
        }

        console.info('[dmsDemo] getTrustedDeviceListSync begin');
        let list = this.deviceManager.getAvailableDeviceListSync();
        console.info('[dmsDemo] getTrustedDeviceListSync end, deviceList=' + JSON.stringify(list));
        if (typeof (list) != 'undefined' && typeof (list.length) != 'undefined') {
            this.deviceList = list;
        }
        this.callback();
        console.info('[dmsDemo] callback finished');

        this.registerDeviceStateChangeCallback();
        this.registerDeviceFoundCallback();
        this.registerDiscoverFailCallback();
        this.registerServiceDieCallback();

        SUBSCRIBE_ID = Math.floor(65536 * Math.random());
        console.info('[dmsDemo] startDeviceDiscovery ' + SUBSCRIBE_ID);
        this.deviceManager.startDiscovering({
            subscribeId: SUBSCRIBE_ID,
            mode: 0xAA,
            medium: 2,
            freq: 2,
            isSameAccount: false,
            isWakeRemote: true,
            capability: 0
        })
    }

    registerDeviceStateChangeCallback() {
        this.deviceManager.on('deviceStateChange', (data) => {
            console.info('[dmsDemo] deviceStateChange data=' + JSON.stringify(data));
            switch (data.action) {
                case 0:
                    this.deviceList[this.deviceList.length] = data.device;
                    console.info('[dmsDemo] online, updated device list=' + JSON.stringify(this.deviceList));
                    this.callback();
                    if (this.authCallback != null) {
                        this.authCallback();
                        this.authCallback = null;
                    }
                    break;
                case 2:
                    if (this.deviceList.length > 0) {
                        for (let i = 0; i < this.deviceList.length; i++) {
                            if (this.deviceList[i].deviceId === data.device.deviceId) {
                                this.deviceList[i] = data.device;
                                break;
                            }
                        }
                    }
                    console.info('[dmsDemo] change, updated device list=' + JSON.stringify(this.deviceList));
                    this.callback();
                    break;
                case 1:
                    if (this.deviceList.length > 0) {
                        let list: distributedDeviceManager.DeviceBasicInfo[] = [];
                        for (let i = 0; i < this.deviceList.length; i++) {
                            if (this.deviceList[i].networkId != data.device.networkId) {
                                list[i] = data.device as distributedDeviceManager.DeviceBasicInfo;
                            }
                        }
                        this.deviceList = list;
                    }
                    console.info('[dmsDemo] offline, updated device list=' + JSON.stringify(data.device));
                    this.callback();
                    break;
                default:
                    break;
            }
        });
    }

    registerDeviceFoundCallback() {
        this.deviceManager.on('discoverSuccess', (data) => {
            console.info('[dmsDemo] deviceFound data=' + JSON.stringify(data));
            console.info('[dmsDemo] deviceFound this.deviceList=' + this.deviceList);
            console.info('[dmsDemo] deviceFound this.deviceList.length=' + this.deviceList.length);
            for (let i = 0; i < this.discoverList.length; i++) {
                if (this.discoverList[i].deviceId === data.device.deviceId) {
                    console.info('[dmsDemo] device founded, ignored');
                    return;
                }
            }
            this.discoverList[this.discoverList.length] = data.device;
            this.callback();
        });
    }

    registerDiscoverFailCallback() {
        this.deviceManager.on('discoverFailure', (data) => {
            console.info('[dmsDemo] discoverFail data=' + JSON.stringify(data));
        });
    }

    registerServiceDieCallback() {
        this.deviceManager.on('serviceDie', () => {
            console.error('[dmsDemo] serviceDie');
        });
    }

    authDevice(deviceId: string, callback: Callback<void>) {
        console.info('[dmsDemo] authDevice ' + deviceId);
        for (let i = 0; i < this.discoverList.length; i++) {
            if (this.discoverList[i].deviceId === deviceId) {
                console.info('[dmsDemo] device founded, ignored');
                console.info('[dmsDemo] authenticateDevice ' + JSON.stringify(this.discoverList[i]));
                this.deviceManager.bindTarget(this.discoverList[i].networkId,
                    {
                        "authType": 1,
                        "appIcon": '',
                        "appThumbnail": '',
                        "extraInfo": {
                            "targetPkgName": 'com.ohos.distributedmusicplayer',
                            "appName": 'Music',
                            "appDescription": 'Music player application',
                            "business": '0'
                        }
                    }, (err, data) => {
                        if (err) {
                            console.info('[dmsDemo] authenticateDevice failed, err=' + JSON.stringify(err));
                            this.authCallback = null;
                        } else {
                            console.info('[dmsDemo] authenticateDevice succeed, data=' + JSON.stringify(data));
                            this.authCallback = callback;
                        }
                    });
            }
        }
    }

    unregisterDeviceListCallback() {
        console.info('[dmsDemo] stopDeviceDiscovery ');
        this.deviceManager.stopDiscovering();
        this.deviceManager.off('deviceStateChange');
        this.deviceManager.off('discoverSuccess');
        this.deviceManager.off('discoverFailure');
        this.deviceManager.off('serviceDie');
        this.deviceList = [];
    }
}