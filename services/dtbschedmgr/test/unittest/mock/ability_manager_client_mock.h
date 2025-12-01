/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#ifndef ABILITY_MANAGER_CLIENT_MOCK_H
#define ABILITY_MANAGER_CLIENT_MOCK_H

#include <gmock/gmock.h>

#include "ability_manager_client.h"

namespace OHOS {
namespace AAFwk {

class IAbilityManagerClient {
public:
    virtual ~IAbilityManagerClient() = default;
    virtual ErrCode Connect() = 0;
    virtual ErrCode GetMissionInfo(const std::string &deviceId, int32_t missionId, MissionInfo &missionInfo) = 0;
    virtual ErrCode ContinueAbility(const std::string &deviceId, int32_t missionId, uint32_t versionCode) = 0;
    virtual int32_t GetAbilityStateByPersistentId(int32_t persistentId, bool &state) = 0;
    virtual ErrCode CleanMission(int32_t missionId) = 0;
    virtual ErrCode StartAbility(const Want &want, int requestCode = DEFAULT_INVAL_VALUE,
        int32_t userId = DEFAULT_INVAL_VALUE, uint64_t specifiedFullTokenId = 0) = 0;
    virtual ErrCode GetMissionInfos(const std::string& deviceId, int32_t numMax,
        std::vector<MissionInfo> &missionInfos) = 0;
public:
    static inline std::shared_ptr<IAbilityManagerClient> clientMock = nullptr;
};

class AbilityManagerClientMock : public IAbilityManagerClient {
public:
    MOCK_METHOD0(Connect, ErrCode());
    MOCK_METHOD3(GetMissionInfo, ErrCode(const std::string &deviceId, int32_t missionId, MissionInfo &missionInfo));
    MOCK_METHOD3(ContinueAbility, ErrCode(const std::string &deviceId, int32_t missionId, uint32_t versionCode));
    MOCK_METHOD2(GetAbilityStateByPersistentId, int32_t(int32_t persistentId, bool &state));
    MOCK_METHOD1(CleanMission, ErrCode(int32_t missionId));
    MOCK_METHOD4(StartAbility, ErrCode(const Want &want, int requestCode, int32_t userId,
        uint64_t specifiedFullTokenId));
    MOCK_METHOD3(GetMissionInfos, ErrCode(const std::string& deviceId, int32_t numMax,
        std::vector<MissionInfo> &missionInfos));
};
}
}
#endif
