/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "ability_manager_client_mock.h"

namespace OHOS {
namespace AAFwk {
ErrCode AbilityManagerClient::Connect()
{
    return IAbilityManagerClient::clientMock->Connect();
}

ErrCode AbilityManagerClient::GetMissionInfo(const std::string& deviceId, int32_t missionId,
    MissionInfo &missionInfo)
{
    return IAbilityManagerClient::clientMock->GetMissionInfo(deviceId, missionId, missionInfo);
}

ErrCode AbilityManagerClient::ContinueAbility(const std::string &deviceId, int32_t missionId, uint32_t versionCode)
{
    return IAbilityManagerClient::clientMock->ContinueAbility(deviceId, missionId, versionCode);
}

int32_t AbilityManagerClient::GetAbilityStateByPersistentId(int32_t persistentId, bool &state)
{
    return IAbilityManagerClient::clientMock->GetAbilityStateByPersistentId(persistentId, state);
}

ErrCode AbilityManagerClient::CleanMission(int32_t missionId)
{
    return IAbilityManagerClient::clientMock->CleanMission(missionId);
}

ErrCode AbilityManagerClient::StartAbility(const Want &want, int requestCode, int32_t userId,
    uint64_t specifiedFullTokenId)
{
    return IAbilityManagerClient::clientMock->StartAbility(want, requestCode, userId, specifiedFullTokenId);
}

ErrCode AbilityManagerClient::GetMissionInfos(const std::string& deviceId, int32_t numMax,
    std::vector<MissionInfo> &missionInfos)
{
    return IAbilityManagerClient::clientMock->GetMissionInfos(deviceId, numMax, missionInfos);
}
}
}
