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
#ifndef DMS_CONTINUE_CONDITION_MANAGER_MOCK_H
#define DMS_CONTINUE_CONDITION_MANAGER_MOCK_H

#include <gmock/gmock.h>

#include "mission/dms_continue_condition_manager.h"

namespace OHOS {
namespace DistributedSchedule {
using namespace OHOS::AppExecFwk;
class IDmsContinueConditionMgr {
public:
    virtual ~IDmsContinueConditionMgr() = default;
    virtual int32_t UpdateSystemStatus(SysEventType type, bool value);
    virtual int32_t UpdateMissionStatus(int32_t accountId, int32_t missionId, MissionEventType type);
    virtual bool CheckSystemSendCondition();
    virtual bool CheckMissionSendCondition(const MissionStatus& status, MissionEventType type);
    virtual bool IsScreenLocked();
    virtual int32_t GetCurrentFocusedMission(int32_t accountId);
    virtual int32_t GetMissionStatus(int32_t accountId, int32_t missionId, MissionStatus& status);
    virtual int32_t GetMissionIdByBundleName(int32_t accountId, const std::string& bundleName, int32_t& missionId);
    virtual std::string TypeEnumToString(MissionEventType type);
public:
    static inline std::shared_ptr<IDmsContinueConditionMgr> conditionMgrMock = nullptr;
};

class DmsContinueConditionMgrMock : public IDmsContinueConditionMgr {
public:
    MOCK_METHOD2(UpdateSystemStatus, int32_t(SysEventType type, bool value));
    MOCK_METHOD3(UpdateMissionStatus, int32_t(int32_t accountId, int32_t missionId, MissionEventType type));
    MOCK_METHOD0(CheckSystemSendCondition, bool());
    MOCK_METHOD2(CheckMissionSendCondition, bool(const MissionStatus& status, MissionEventType type));
    MOCK_METHOD0(IsScreenLocked, bool());
    MOCK_METHOD1(GetCurrentFocusedMission, int32_t(int32_t accountId));
    MOCK_METHOD3(GetMissionStatus, int32_t(int32_t accountId, int32_t missionId, MissionStatus& status));
    MOCK_METHOD3(GetMissionIdByBundleName, int32_t(int32_t accountId, const std::string& bundleName,
        int32_t& missionId));
    MOCK_METHOD1(TypeEnumToString, std::string(MissionEventType type));
};
}
}
#endif
