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

import distributedDeviceManager from '@ohos.distributedDeviceManager';

const SUBSCRIBE_ID = 100;
const PrintLog = '[dmsDemo] ';
const BundleName = 'com.ohos.distributedmusicplayer';
export default class RemoteDeviceModel {
  deviceList:distributedDeviceManager.DeviceBasicInfo[] = [];
  deviceManager: distributedDeviceManager.DeviceManager = distributedDeviceManager.createDeviceManager(BundleName);

  constructor() {
  }


  registerDeviceListCallback(): void {
    console.info(PrintLog + 'registerDeviceListCallback in');
    if (typeof (this.deviceManager) === 'undefined') {
      console.log(PrintLog + ' deviceManager.createDeviceManager begin');
      try {
        this.registerDeviceListCallback_();
      } catch (err) {
        console.error(PrintLog + 'createDeviceManager error: ' + JSON.stringify(err));
      }
      console.log(PrintLog + ' deviceManager.createDeviceManager end');
    } else {
      this.registerDeviceListCallback_();
    }
  }

  registerDeviceListCallback_(): void {
    console.info('[dmsDemo] registerDeviceListCallback');
    if (this.deviceManager == undefined) {
      console.error('[dmsDemo] deviceManager has not initialized');
      return;
    } else {
      console.info('[dmsDemo] getTrustedDeviceListSync begin');
      let list = this.deviceManager.getAvailableDeviceListSync();
      console.info('[dmsDemo] getTrustedDeviceListSync end, deviceList=' + JSON.stringify(list));
      if (typeof (list) != 'undefined' && typeof (list.length) != 'undefined') {
        this.deviceList = list;
      }
    }
    console.info('[dmsDemo] callback finished');
  }

  unregisterDeviceListCallback(): void {
    console.info('[dmsDemo] stopDeviceDiscovery ' + SUBSCRIBE_ID);
    this.deviceManager.stopDiscovering();
    this.deviceList = [];
  }
}