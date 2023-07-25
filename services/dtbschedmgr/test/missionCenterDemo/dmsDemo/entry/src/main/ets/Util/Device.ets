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

import missionManager from '@ohos.application.missionManager'
import DeviceManager from './DeviceManager'
import LocalMissionManager from './LocalMissionManager'
import Mission from './Mission'
import RemoteMissionManager from './RemoteMissionManager'
import Logger from './Logger'

const NUM_MAX: number = 20

export default class Device{
  isLocal: boolean = true
  color: Color = Color.Gray
  deviceInfo
  missionList: Mission[] = [];
  constructor(deviceInfo, isLocal: boolean) {
    Logger.info('Device construct');
    this.deviceInfo = deviceInfo
    this.isLocal = isLocal
    this.initMissionInfos()
  }

  initMissionInfos(){
    if (this.isLocal) {
      LocalMissionManager.registerMissionListener(this)
    } else {
      RemoteMissionManager.registerMissionListener(this)
    }
  }

  updateMissionInfos(){
    let self = this;
    Logger.info('get MissionInfos begin, device = ' + this.deviceInfo.networkId);
    var promise = missionManager.getMissionInfos(this.deviceInfo.networkId, NUM_MAX).catch(function(error){
      Logger.info('get MissionInfos failed, error.code = ' + error.code);
    })
    promise.then(missions => {
      if (typeof (missions) == 'undefined' || typeof (missions.length) == 'undefined') {
        Logger.info('missionInfos is null');
        return
      }
      Logger.info('get MissionInfos success, mission size = ' + missions?.length);
      self.missionList = []
      let writeList:Set<string> = new Set();
      writeList.add("com.ohos.settings")
      writeList.add("com.ohos.note")
      writeList.add("com.huawei.himovie")
      writeList.add("ohos.samples.distributedcalc")
      for (var i = 0; i < missions.length; i++) {
        Logger.info('update mission = ' + JSON.stringify(missions[i]));
        self.missionList.push(new Mission(missions[i]))
      }
      DeviceManager.update()
    })
  }
}