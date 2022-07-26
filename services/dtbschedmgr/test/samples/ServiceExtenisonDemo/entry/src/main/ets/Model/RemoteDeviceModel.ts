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

import deviceManager from '@ohos.distributedHardware.deviceManager';

var SUBSCRIBE_ID = 100;

export default class RemoteDeviceModel {
    deviceList = [];
    discoverList = [];
    callback;
    authCallback = null;
    #deviceManager;

    constructor() {
    }

    registerDeviceListCallback(callback) {
        if (typeof (this.#deviceManager) === 'undefined') {
            console.log('[ServiceExtensionDemo] deviceManager.createDeviceManager begin');
            let self = this;
            deviceManager.createDeviceManager('com.example.serviceextensiondemo', (error, value) => {
                if (error) {
                    console.error('createDeviceManager failed.');
                    return;
                }
                self.#deviceManager = value;
                self.registerDeviceListCallback_(callback);
                console.log('[ServiceExtensionDemo] createDeviceManager callback returned, error=' + error + ' value=' + value);
            });
            console.log('[ServiceExtensionDemo] deviceManager.createDeviceManager end');
        } else {
            this.registerDeviceListCallback_(callback);
        }
    }

    registerDeviceListCallback_(callback) {
        console.info('[ServiceExtensionDemo] registerDeviceListCallback');
        this.callback = callback;
        if (this.#deviceManager == undefined) {
            console.error('[ServiceExtensionDemo] deviceManager has not initialized');
            this.callback();
            return;
        }

        console.info('[ServiceExtensionDemo] getTrustedDeviceListSync begin');
        var list = this.#deviceManager.getTrustedDeviceListSync();
        console.info('[ServiceExtensionDemo] getTrustedDeviceListSync end, deviceList=' + JSON.stringify(list));
        if (typeof (list) != 'undefined' && typeof (list.length) != 'undefined') {
            this.deviceList = list;
        }
        this.callback();
        console.info('[ServiceExtensionDemo] callback finished');
    }

    getTrustDeviceList(callback) {
        console.info('[ServiceExtensionDemo] getTrustDeviceListSync begin');
        var list = this.#deviceManager.getTrustedDeviceListSync();
        console.info('[ServiceExtensionDemo] getTrustedDeviceListSync end, deviceList=' + JSON.stringify(list));
        if (typeof (list) != 'undefined' && typeof (list.length) != 'undefined') {
            this.deviceList = list;
        }

        console.info('[ServiceExtensionDemo] getTrustDeviceListSync end');
        callback();
    }

    unregisterDeviceListCallback() {
        console.info('[dmsDemo] stopDeviceDiscovery ' + SUBSCRIBE_ID);
        this.#deviceManager.stopDeviceDiscovery(SUBSCRIBE_ID);
        this.#deviceManager.off('deviceStateChange');
        this.#deviceManager.off('deviceFound');
        this.#deviceManager.off('discoverFail');
        this.#deviceManager.off('serviceDie');
        this.deviceList = [];
    }
}