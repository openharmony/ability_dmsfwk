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

import Mission from './Mission';
import deviceManager from '@ohos.distributedHardware.deviceManager';
import distributedMissionManager from '@ohos.distributedMissionManager'
import Logger from './Logger'
import Device from './Device';

const BUNDLE_NAME = "com.example.mission_center"

class DeviceManager {
  private myDeviceManager: deviceManager.DeviceManager
  toDeviceId: string = ''
  fromDeviceId: string = ''
  fromMissionId: number = -1
  isFreeInstall: boolean = true
  localDevice: Device
  trustedDeviceList: Device[] = []
  currentDevice: Device

  constructor() {
    Logger.info('create DeviceManager begin');
    let self = this;
    deviceManager.createDeviceManager(BUNDLE_NAME, (error, value) => {
      if (error) {
        Logger.error('create DeviceManager failed');
        return;
      }
      self.myDeviceManager = value;
      Logger.info('create DeviceManager success');
      self.initTrustedDeviceMissionList()
      self.initLocalDeviceMission()
      Logger.info('lxw success' + JSON.stringify(self.localDevice));
      self.fromDeviceId = self.localDevice.deviceInfo.networkId
      self.currentDevice = self.localDevice
      self.ready()
    });
    Logger.info('create DeviceManager end');
    this.update()
    AppStorage.SetOrCreate<DeviceManager>('DeviceManager', this)
  }

  private initTrustedDeviceMissionList() {
    Logger.info('init TrustedDeviceMissionList begin');
    if (typeof (this.myDeviceManager) === 'undefined') {
      Logger.error('DeviceManager not initialized');
      return
    }
    var trustedDeviceList = this.myDeviceManager.getTrustedDeviceListSync();
    Logger.info('init TrustedDeviceMissionList end, deviceList = ' + JSON.stringify(trustedDeviceList));
    if (typeof (trustedDeviceList) == 'undefined' || typeof (trustedDeviceList.length) == 'undefined') {
      Logger.info('TrustedDeviceMissionList is null');
    } else {
      for (var i = 0; i < trustedDeviceList.length; i++) {
        var device = new Device(trustedDeviceList[i], false)
        this.trustedDeviceList[this.trustedDeviceList.length] = device
      }
    }
    Logger.info('TrustedDeviceMissionList size = ' + this.trustedDeviceList.length);
    this.update()
  }

  private initLocalDeviceMission() {
    Logger.info('init LocalDeviceMission begin');
    if (typeof  (this.myDeviceManager) === 'undefined') {
      Logger.error('DeviceManager not initialized');
      return
    }
    var deviceInfo = this.myDeviceManager.getLocalDeviceInfoSync();
    Logger.info('init LocalDeviceMission end, device = ' + JSON.stringify(deviceInfo));
    if (typeof (deviceInfo) != 'undefined') {
      this.localDevice = new Device(deviceInfo, true)
    } else {
      Logger.error('LocalDeviceMission is null');
    }
    this.update()
  }

  update() {
    Logger.info('update begin');
    AppStorage.Set('isUpdate',!AppStorage.Get('isUpdate'))
    Logger.info('update end');
  }

  ready() {
    Logger.info('update begin');
    AppStorage.Set('isReady', true)
    Logger.info('update end');
  }

  onSelectToDevice(toDeviceId: string) {
    this.toDeviceId = toDeviceId
  }

  onSelectFromMission(fromDeviceId: string, fromMissionId: number) {
    this.fromDeviceId = fromDeviceId
    this.fromMissionId = fromMissionId
  }

  onContinueAbility() {
    Logger.info('toDeviceId = ' + this.toDeviceId);
    Logger.info('fromDeviceId = ' + this.fromDeviceId);
    Logger.info('fromMissionId = ' + this.fromMissionId);
    if (this.enableContinue()) {
      Logger.info('continue mission start');
      AppStorage.SetOrCreate<string>('continueResult', '等待迁移结果...')
      function OnContinueDone(resultCode) {
        Logger.info('OnContinueDone resultCode: ' + JSON.stringify(resultCode));
        AppStorage.SetOrCreate<string>('continueResult', JSON.stringify(resultCode))
      }

      try {
        distributedMissionManager.continueMission({
          srcDeviceId: this.fromDeviceId,
          dstDeviceId: this.toDeviceId,
          missionId: this.fromMissionId,
          wantParam: { "isFreeInstall": this.isFreeInstall }
        }, {onContinueDone: OnContinueDone })
          .then(data => {
            Logger.info('continueMission start success');
            AppStorage.SetOrCreate<string>('continueResult', '0')
          })
          .catch(error => {
            Logger.info('continueMission failed result ' + JSON.stringify(error));
            Logger.info('continueMission failed info ' + JSON.stringify(error.message));
            AppStorage.SetOrCreate<string>('continueResult', JSON.stringify(error))
          })
      } catch (error) {
        Logger.info('continueMission failed result ' + JSON.stringify(error));
        AppStorage.SetOrCreate<string>('continueResult', JSON.stringify(error))
      }
      Logger.info('continue mission end');
    }
  }

  enableContinue(): boolean {
    return true
    if (this.toDeviceId.length == 0 || this.fromDeviceId.length == 0 || this.fromMissionId <= 0) {
      Logger.error('not select mission');
      return false
    }
    if (this.fromDeviceId == this.toDeviceId) {
      Logger.error('same device can not continue');
      return false
    }
    if (this.toDeviceId == this.localDevice.deviceInfo.networkId) {
      Logger.error('same device can not continue');
      return false
    }
    if (this.fromDeviceId != this.localDevice.deviceInfo.networkId
    && this.toDeviceId != this.localDevice.deviceInfo.networkId) {
      Logger.error('need select a local device');
      return false
    }
    return true
  }
}

export default new DeviceManager