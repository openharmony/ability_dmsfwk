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

class RemoteMissionManager{
  constructor() {
    Logger.info('RemoteMissionManager construct');
  }

  startSyncRemoteMissions(Device: Device){
    Logger.info("sync RemoteMissions start")
    var device = {
      deviceId: Device.deviceInfo.networkId,
      fixConflict: false,
      tag: 0
    };
    distributedMissionManager.startSyncRemoteMissions(device)
    .then(data => {
      Logger.info("sync RemoteMissions success, data = " + data)
      Device.updateMissionInfos()
    }).catch(error => {
      Logger.error('sync RemoteMissions failed, error = ' + error);
    })
  }

  registerMissionListener(Device: Device){
    Logger.info("register MissionListener start")
    var MissionCallback = {
      notifyMissionsChanged: async function(deviceId){
        Logger.info('notifyMissionsChanged deviceId = ' + deviceId);
        Device.updateMissionInfos()
      },
      notifySnapshot: async function(deviceId, missionId){
        Logger.info('notifySnapshot missionId = ' + missionId);
      },
      notifyNetDisconnect: async function(deviceId, state){
        Logger.info('notifyNetDisconnect deviceId = ' + deviceId);
      },
    }
    var device = {
      deviceId:Device.deviceInfo.networkId
    }
    let self = this
    distributedMissionManager.registerMissionListener(device, MissionCallback).then(data => {
      Logger.info("register MissionListener success")
      self.startSyncRemoteMissions(Device)
    }).catch(error => {
      Logger.info("register MissionListener failed, error = " + error)
    })
  }
}

export default new RemoteMissionManager