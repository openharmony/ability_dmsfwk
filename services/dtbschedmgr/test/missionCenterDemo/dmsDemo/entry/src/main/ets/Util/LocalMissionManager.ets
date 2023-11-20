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
import missionManager from '@ohos.app.ability.missionManager';
import distributedMissionManager from '@ohos.distributedMissionManager';
import Device from './Device';
import Logger from './Logger'

class LocalMissionManager{
  constructor() {
    Logger.info('LocalMissionManager construct');
  }

  registerMissionListener(Device: Device){
    let listener: missionManager.MissionListener = {
      onMissionCreated: (mission) => {
        Logger.info('onMissionCreated mission = ' + mission);
        Device.updateMissionInfos()
      },
      onMissionDestroyed: (mission) => {
        Logger.info('onMissionDestroyed mission = ' + mission);
        Device.updateMissionInfos()
      },
      onMissionSnapshotChanged: (mission) => {
        Logger.info('onMissionSnapshotChanged mission = ' + mission);
        Device.updateMissionInfos()
      },
      onMissionMovedToFront: (mission) => {
        Logger.info('onMissionMovedToFront mission = ' + mission);
        Device.updateMissionInfos()
      },
      onMissionIconUpdated: (mission) => {
      },
      onMissionClosed :(mission) => {
      },
      onMissionLabelUpdated: (mission: number) => {
        throw new Error('Function not implement.')
      }
    }
    missionManager.on('mission',listener);
    Device.updateMissionInfos()
  }
}

export default new LocalMissionManager