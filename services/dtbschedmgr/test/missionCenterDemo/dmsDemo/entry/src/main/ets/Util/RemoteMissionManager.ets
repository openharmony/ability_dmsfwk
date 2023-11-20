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
 
import distributedMissionManager from '@ohos.distributedMissionManager'
import Device from './Device';
import Logger from './Logger'
import { BusinessError } from '@ohos.base'
import CommonTools from './common';
import distributedDeviceManager from '@ohos.distributedDeviceManager';

class RemoteMissionManager{
  constructor() {
    Logger.info('RemoteMissionManager construct');
  }

  startSyncRemoteMissions(Device: Device){
    Logger.info("sync RemoteMissions start")
    let networkId: string = CommonTools.getInstance().getNetworkId(Device);
    let device: distributedMissionManager.MissionParameter = {
      deviceId: networkId,
      fixConflict: false,
      tag: 0
    };
    distributedMissionManager.startSyncRemoteMissions(device)
    .then(data => {
      Logger.info("sync RemoteMissions success, data = " + data)
      Device.updateMissionInfos()
    }).catch((error: BusinessError) => {
      Logger.error('sync RemoteMissions failed, error = ' + error);
    })
  }

  registerMissionListener(Device: Device){
    Logger.info("register MissionListener start")
    let MissionCallback: distributedMissionManager.MissionCallback = {
      notifyMissionsChanged: (deviceId: string) => {
        Logger.info('notifyMissionsChanged deviceId = ' + deviceId);
        Device.updateMissionInfos()
      },
      notifySnapshot: (deviceId: string, missionId: number) => {
        Logger.info('notifySnapshot missionId = ' + missionId);
      },
      notifyNetDisconnect: (deviceId: string, state: number) => {
        Logger.info('notifyNetDisconnect deviceId = ' + deviceId);
      },
    }
    let networkId: string = CommonTools.getInstance().getNetworkId(Device);
    let device: distributedMissionManager.MissionDeviceInfo = {
      deviceId: networkId
    }
    let self = this
    distributedMissionManager.registerMissionListener(device, MissionCallback).then(data => {
      Logger.info("register MissionListener success")
      self.startSyncRemoteMissions(Device)
    }).catch((error: BusinessError) => {
      Logger.info("register MissionListener failed, error = " + error)
    })
  }
}

export default new RemoteMissionManager