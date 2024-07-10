/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "dfx/dms_continue_time_dumper.h"
#include "distributed_ue.h"
#include "dms_constant.h"

#include "hisysevent.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
    const std::string TAG = "DmsUE";
    const std::string NO_FAILED_EXTRAINFO = "NULL";
    constexpr int32_t DEVICE_TYPE_UNKNOWN = 0;
}

IMPLEMENT_SINGLE_INSTANCE(DmsUE);

bool DmsUE::NotifyDockShowIcon(const std::string& bundleName, const std::string& abilityName,
    const std::string& networkId, int32_t errCode)
{   
    int32_t res = ERR_OK;
    if(errCode == ERR_OK) {
        res = HiSysEventWrite(
            CONTINUATION_DOMAIN,
            SHOW_CONTINUATION_ICON,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            PNAMEID, CONTINUATION_DOMAIN,
            PVERSIONID, Constants::DMS_VERSION,
            BUNDLE_NAME, bundleName,
            ABILITY_NAME, abilityName,
            SOURCE_DEVICE_TYPE, GetDeviceTypeByNetworkId(networkId));
    } else {
        res = HiSysEventWrite(
            CONTINUATION_DOMAIN,
            SHOW_CONTINUATION_ICON,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            PNAMEID, CONTINUATION_DOMAIN,
            PVERSIONID, Constants::DMS_VERSION,
            BUNDLE_NAME, bundleName,
            ABILITY_NAME, abilityName,
            SOURCE_DEVICE_TYPE, GetDeviceTypeByNetworkId(networkId)
            ERROR_CODE_UE, errCode);
    }
    if (res != ERR_OK) {
        HILOGE("NotifyDockShowIcon error, res:%{public}d", res);
        return false;
    }
    return true;
}

bool DmsUE::TriggerDmsContinue(const std::string& bundleName, const std::string& abilityName,
    const std::string& networkId, int32_t errCode)
{
    int32_t res = ERR_OK;
    if (errCode == ERR_OK) {
        res = HiSysEventWrite(
            CONTINUATION_DOMAIN,
            CLICK_CONTINUATION_ICON,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            PNAMEID, CONTINUATION_DOMAIN,
            PVERSIONID, Constants::DMS_VERSION,
            BUNDLE_NAME, bundleName,
            ABILITY_NAME, abilityName,
            SOURCE_DEVICE_TYPE, GetDeviceTypeByNetworkId(networkId));
    } else {
        res = HiSysEventWrite(
            CONTINUATION_DOMAIN,
            CLICK_CONTINUATION_ICON,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            PNAMEID, CONTINUATION_DOMAIN,
            PVERSIONID, Constants::DMS_VERSION,
            BUNDLE_NAME, bundleName,
            ABILITY_NAME, abilityName,
            SOURCE_DEVICE_TYPE, GetDeviceTypeByNetworkId(networkId),
            ERROR_CODE, errCode);
    }
    if (res != ERR_OK) {
        HILOGE("TriggerDmsContinue error, res:%{public}d", res);
        return false;
    }
    return true;
}

bool DmsUE::DmsContinueComplete(const std::string& bundleName, const std::string& abilityName,
    const std::string& networkId, int32_t errCode)
{
    int32_t res = ERR_OK;
    if (errCode == ERR_OK) {
        res = HiSysEventWrite(
            CONTINUATION_DOMAIN,
            COMPLETE_OF_CONTINUATION,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            PNAMEID, CONTINUATION_DOMAIN,
            PVERSIONID, Constants::DMS_VERSION,
            BUNDLE_NAME, bundleName,
            ABILITY_NAME, abilityName,
            SOURCE_DEVICE_TYPE, GetDeviceTypeByNetworkId(networkId),
            CONTINUATION_STATE, static_cast<int32_t>(continuationState::CONTINUATION_SUCC),
            FAILED_EXTRAINFO, NO_FAILED_EXTRAINFO,
            CONTINUATION_DURATION, DmsContinueTime::GetInstance().GetTotalTime());
    } else {
        res = HiSysEventWrite(
            CONTINUATION_DOMAIN,
            COMPLETE_OF_CONTINUATION,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            PNAMEID, CONTINUATION_DOMAIN,
            PVERSIONID, Constants::DMS_VERSION,
            BUNDLE_NAME, bundleName,
            ABILITY_NAME, abilityName,
            SOURCE_DEVICE_TYPE, GetDeviceTypeByNetworkId(networkId),
            CONTINUATION_STATE, static_cast<int32_t>(continuationState::CONTINUATION_FAIL),
            FAILED_EXTRAINFO, ConvertErrCodeToStr(errCode),
            CONTINUATION_DURATION, DmsContinueTime::GetInstance().GetTotalTime(),
            ERROR_CODE, errCode);
    }
    if (res != ERR_OK) {
        HILOGE("DmsContinueComplete error, res:%{public}d", res);
        return false;
    }
    return true;
}

bool DmsUE::OriginalSwitchState(const std::string& switchState, int32_t errCode)
{
    int32_t res = ERR_OK;
    if (errCode == ERR_OK) {
        res = HiSysEventWrite(
            CONTINUATION_DOMAIN,
            ORIGINAL_SWITCH_STATE,
            HiviewDFX::HiSysEvent::EventType::STATISTIC,
            PNAMEID, CONTINUATION_DOMAIN,
            PVERSIONID, Constants::DMS_VERSION,
            SWITCH_STATE, switchState);
    } else {
        res = HiSysEventWrite(
            CONTINUATION_DOMAIN,
            ORIGINAL_SWITCH_STATE,
            HiviewDFX::HiSysEvent::EventType::STATISTIC,
            PNAMEID, CONTINUATION_DOMAIN,
            PVERSIONID, Constants::DMS_VERSION,
            SWITCH_STATE, switchState,
            ERROR_CODE, errCode);
    }
    if (res != ERR_OK) {
        HILOGE("OriginalSwitchState error, res:%{public}d", res);
        return false;
    }
    return true;
}

bool DmsUE::ChangedSwitchState(const std::string& switchState, int32_t errCode)
{
    int32_t res = ERR_OK;
    if (errCode == ERR_OK) {
        res = HiSysEventWrite(
            CONTINUATION_DOMAIN,
            CHANGED_SWITCH_STATE,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            PNAMEID, CONTINUATION_DOMAIN,
            PVERSIONID, Constants::DMS_VERSION,
            SWITCH_STATE, switchState);
    } else {
        res = HiSysEventWrite(
            CONTINUATION_DOMAIN,
            CHANGED_SWITCH_STATE,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            PNAMEID, CONTINUATION_DOMAIN,
            PVERSIONID, Constants::DMS_VERSION,
            SWITCH_STATE, switchState,
            ERROR_CODE, errCode);
    }
    if (res != ERR_OK) {
        HILOGE("ChangedSwitchState error, res:%{public}d", res);
        return false;
    }
    return true;
}

int32_t DmsUE::GetDeviceTypeByNetworkId(int32_t networkId)
{
    auto deviceInfo = DtbschedmgrDeviceInfoStorage::GetInstance().GetDeviceInfoById(networkId);
    if (deviceInfo == nullptr) {
        return DEVICE_TYPE_UNKNOWN;
    }
    return deviceInfo->GetDeviceType();
}

std::string DmsUE::ConvertErrCodeToStr(int32_t errorCode)
{
    switch(errorCode) {
        case INVALID_PARAMETERS_ERR:
            return "invalid parameters";
        case INVALID_REMOTE_PARAMETERS_ERR:
            return "remote invalid parameters";
        case DMS_START_CONTROL_PERMISSION_DENIED:
            return "start control permission check failed";
        case NO_MISSION_INFO_FOR_MISSION_ID:
            return "failed to get the missionInfo of the specified missionId";
        case OPERATION_DEVICE_NOT_INITIATOR_OR_TARGET:
            return "the operation device must be the target device to be continued";
        case CONTINUE_ALREADY_IN_PROGRESS:
            return "the local continuation task is already in progress";
        case MISSION_FOR_CONTINUING_IS_NOT_ALIVE:
            return "the mission for continuing is not alive, try again after restart mission.";
        case CONTINUE_SEND_EVENT_FAILED:
            return "sending event failed during continuation";
        case CONTINUE_STATE_MACHINE_INVALID_STATE:
            return "state machine receving invalid state code";
        case CONTINUE_SESSION_SHUTDOWN:
            return "session shutdown during continuation";
        case CONTINUE_CALL_CONTINUE_ABILITY_FAILED:
            return "calling ContinueAbility failed during continuation";
        case CONTINUE_CALL_START_ABILITY_FAILED:
            return "calling StartAbility failed during continuation";
        case CONTINUE_SINK_ABILITY_TERMINATED:
            return "sink Ability abnormal termination during continuation";
        case DMS_CONNECT_APPLY_REJECT_FAILED:
            return "all connect manager reject connect apply";
        default:
            return "internal error";
    }
}
} // namespace DistributedSchedule
} // namespace OHOS