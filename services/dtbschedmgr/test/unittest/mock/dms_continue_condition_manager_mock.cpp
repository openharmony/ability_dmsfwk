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
#include "dms_continue_condition_manager_mock.h"
using namespace std;
namespace OHOS {
namespace DistributedSchedule {

IMPLEMENT_SINGLE_INSTANCE(DmsContinueConditionMgr);

int32_t DmsContinueConditionMgr::UpdateSystemStatus(SysEventType type, bool value)
{
    return IDmsContinueConditionMgr::conditionMgrMock->UpdateSystemStatus(type, value);
}

int32_t DmsContinueConditionMgr::UpdateMissionStatus(int32_t accountId, int32_t missionId, MissionEventType type)
{
    return IDmsContinueConditionMgr::conditionMgrMock->UpdateMissionStatus(accountId, missionId, type);
}

bool DmsContinueConditionMgr::CheckSystemSendCondition()
{
    return IDmsContinueConditionMgr::conditionMgrMock->CheckSystemSendCondition();
}

bool DmsContinueConditionMgr::CheckMissionSendCondition(const MissionStatus& status, MissionEventType type)
{
    return IDmsContinueConditionMgr::conditionMgrMock->CheckMissionSendCondition(status, type);
}

bool DmsContinueConditionMgr::IsScreenLocked()
{
    return IDmsContinueConditionMgr::conditionMgrMock->IsScreenLocked();
}

int32_t DmsContinueConditionMgr::GetCurrentFocusedMission(int32_t accountId)
{
    return IDmsContinueConditionMgr::conditionMgrMock->GetCurrentFocusedMission(accountId);
}

int32_t DmsContinueConditionMgr::GetMissionStatus(int32_t accountId, int32_t missionId, MissionStatus& status)
{
    return IDmsContinueConditionMgr::conditionMgrMock->GetMissionStatus(accountId, missionId, status);
}

int32_t DmsContinueConditionMgr::GetMissionIdByBundleName(int32_t accountId, const std::string& bundleName,
    int32_t& missionId)
{
    return IDmsContinueConditionMgr::conditionMgrMock->GetMissionIdByBundleName(accountId, bundleName, missionId);
}

std::string DmsContinueConditionMgr::TypeEnumToString(MissionEventType type)
{
    return IDmsContinueConditionMgr::conditionMgrMock->TypeEnumToString(type);
}
}
}
