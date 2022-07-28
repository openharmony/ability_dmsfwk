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

import deviceManager from '@ohos.distributedHardware.deviceManager';

var SUBSCRIBE_ID = 100;

export default class RemoteDeviceModel {
  deviceList = [];
  deviceManager;

  constructor() {
  }

  registerDeviceListCallback() {
    if (typeof (this.deviceManager) === 'undefined') {
      console.log('[dmsDemo] deviceManager.createDeviceManager begin');
      let self = this;
      deviceManager.createDeviceManager('com.ohos.distributedmusicplayer', (error, value) => {
        if (error) {
          console.error('createDeviceManager failed.');
          return;
        }
        self.deviceManager = value;
        self.registerDeviceListCallback_();
        console.log('[dmsDemo] createDeviceManager callback returned, error=' + error + ' value=' + JSON.stringify(value));
      });
      console.log('[dmsDemo] deviceManager.createDeviceManager end');
    } else {
      this.registerDeviceListCallback_();
    }
  }

  registerDeviceListCallback_(){
    console.info('[dmsDemo] registerDeviceListCallback');
    if (this.deviceManager == undefined) {
      console.error('[dmsDemo] deviceManager has not initialized');
      return;
    }

    console.info('[dmsDemo] getTrustedDeviceListSync begin');
    var list = this.deviceManager.getTrustedDeviceListSync();
    console.info('[dmsDemo] getTrustedDeviceListSync end, deviceList=' + JSON.stringify(list));
    if (typeof (list) != 'undefined' && typeof (list.length) != 'undefined') {
      this.deviceList = list;
    }
    console.info('[dmsDemo] callback finished');
  }

  unregisterDeviceListCallback() {
    console.info('[dmsDemo] stopDeviceDiscovery ' + SUBSCRIBE_ID);
    this.deviceManager.stopDeviceDiscovery(SUBSCRIBE_ID);
    this.deviceList = [];
  }
}