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
import { GlobalThis } from '../Model/GlobalThis';

const SUBSCRIBE_ID = 100;
const BundleName = 'com.example.serviceextensiondemo';
const PrintLog = '[ServiceExtensionDemo]: ';

export default class RemoteDeviceModel {
    deviceList: distributedDeviceManager.DeviceBasicInfo[] = [];
    discoverList: distributedDeviceManager.DeviceBasicInfo[] = [];
    callback: Callback<void> = () => {};
    authCallback = null;
    MyDeviceManager: distributedDeviceManager.DeviceManager = distributedDeviceManager.createDeviceManager(BundleName);

    constructor() {
    }

    registerDeviceListCallback(callback: Callback<void>): void {
        console.info(PrintLog + 'registerDeviceListCallback in');
        if (typeof (this.MyDeviceManager) === 'undefined') {
            console.log(PrintLog + ' deviceManager.createDeviceManager begin');
            try {
                this.MyDeviceManager = distributedDeviceManager.createDeviceManager(BundleName);
                this.registerDeviceListCallback_(callback);
            } catch (err) {
                console.error(PrintLog + 'createDeviceManager error: ' + JSON.stringify(err));
            }
            console.log(PrintLog + ' deviceManager.createDeviceManager end');
        } else {
            this.registerDeviceListCallback_(callback);
        }
    }

    registerDeviceListCallback_(callback: Callback<void>): void {
        console.info(PrintLog + ' registerDeviceListCallback_');
        this.callback = callback;
        if (this.MyDeviceManager == undefined) {
            console.error(PrintLog + ' deviceManager has not initialized');
            this.callback();
        } else {
            console.info(PrintLog + ' getTrustedDeviceListSync begin');
            const list = this.MyDeviceManager.getAvailableDeviceListSync();
            console.info(PrintLog + ' getTrustedDeviceListSync end, deviceList=' + JSON.stringify(list));
            if (typeof (list) != 'undefined' && typeof (list.length) != 'undefined') {
                this.deviceList = list;
            }
            this.callback();
        }
        console.info(PrintLog + ' callback finished');
    }

    getTrustDeviceList(callback: Callback<void>): void {
        console.info(PrintLog + ' getTrustDeviceListSync begin');
        const list = this.MyDeviceManager.getAvailableDeviceListSync();
        console.info(PrintLog + ' getTrustedDeviceListSync end, deviceList=' + JSON.stringify(list));
        if (typeof (list) != 'undefined' && typeof (list.length) != 'undefined') {
            this.deviceList = list;
        }
        console.info(PrintLog + ' getTrustDeviceListSync end');
        callback();
    }
}