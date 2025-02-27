/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "mission/notification/dms_continue_recommend_manager.h"

#include <sys/prctl.h>

#include "bundle/bundle_manager_internal.h"
#include "dfx/dms_hianalytics_report.h"
#include "distributed_sched_utils.h"
#include "dtbschedmgr_device_info_storage.h"
#include "dtbschedmgr_log.h"
#include "mission/distributed_bm_storage.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "DMSContinueRecomMgr";
constexpr int32_t STATE_ACTIVE = 0;
constexpr int32_t STATE_INACTIVE = 1;
}

void DMSContinueRecomMgr::Init(int32_t currentAccountId)
{
    HILOGI("Init start");
    {
        std::unique_lock<std::mutex> lock(hasInitMutex_);
        if (hasInit_) {
            HILOGW("DMSContinueRecomMgr has inited");
            return;
        }
        hasInit_ = true;
    }
    if (eventHandler_ != nullptr) {
        HILOGI("Already inited, end.");
        return;
    }
    {
        accountId_ = currentAccountId;
        eventThread_ = std::thread(&DMSContinueRecomMgr::StartEvent, this);
        std::unique_lock<std::mutex> lock(eventMutex_);
        eventCon_.wait(lock, [this] {
            return eventHandler_ != nullptr;
        });
    }
    HILOGI("Init end");
}

void DMSContinueRecomMgr::StartEvent()
{
    HILOGI("StartEvent start");
    prctl(PR_SET_NAME, TAG.c_str());
    auto runner = AppExecFwk::EventRunner::Create(false);
    {
        std::lock_guard<std::mutex> lock(eventMutex_);
        eventHandler_ = std::make_shared<OHOS::AppExecFwk::EventHandler>(runner);
    }
    eventCon_.notify_one();
    CHECK_POINTER_RETURN(runner, "runner");
    runner->Run();
    HILOGI("StartEvent end");
}

DMSContinueRecomMgr::~DMSContinueRecomMgr()
{
    HILOGI("~DMSContinueRecomMgr, accountId: %{public}d.", accountId_);
    UnInit();
}

void DMSContinueRecomMgr::UnInit()
{
    HILOGI("UnInit start");
    {
        std::unique_lock<std::mutex> lock(hasInitMutex_);
        if (!hasInit_) {
            HILOGW("DMSContinueRecomMgr has uninited");
            return;
        }
        hasInit_ = false;
    }
    CHECK_POINTER_RETURN(eventHandler_, "eventHandler_");
    if (eventHandler_->GetEventRunner() != nullptr) {
        eventHandler_->GetEventRunner()->Stop();
        if (eventThread_.joinable()) {
            eventThread_.join();
        }
        eventHandler_ = nullptr;
    }
    HILOGI("UnInit end");
}

void DMSContinueRecomMgr::OnDeviceChanged()
{
    HILOGI("OnDeviceChanged called");
    int32_t missionId = GetCurrentMissionId();
    if (missionId <= 0) {
        HILOGW("GetCurrentMissionId failed, ret %{public}d", missionId);
        return;
    }
    OnMissionStatusChanged(missionId, MISSION_EVENT_FOCUSED);
}

void DMSContinueRecomMgr::OnMissionStatusChanged(int32_t missionId, MissionEventType type)
{
    MissionStatus status;
    int32_t ret = DmsContinueConditionMgr::GetInstance().GetMissionStatus(accountId_, missionId, status);
    if (ret != ERR_OK) {
        HILOGE("GetMissionStatus failed, ret: %{public}d, missionId %{public}d, type: %{public}s",
            ret, missionId, DmsContinueConditionMgr::GetInstance().TypeEnumToString(type).c_str());
        return;
    }

    auto feedfunc = [this, status, type]() {
        PublishContinueRecommend(status, type);
    };
    CHECK_POINTER_RETURN(eventHandler_, "eventHandler_");
    eventHandler_->PostTask(feedfunc);
}

void DMSContinueRecomMgr::PublishContinueRecommend(const MissionStatus& status, MissionEventType type)
{
    auto typeStr = DmsContinueConditionMgr::GetInstance().TypeEnumToString(type);
    HILOGI("start, missionId: %{public}d, type: %{public}s", status.missionId, typeStr.c_str());

    if (!DmsContinueConditionMgr::GetInstance().CheckSystemSendCondition() ||
        !DmsContinueConditionMgr::GetInstance().CheckMissionSendCondition(status, type)) {
        HILOGE("CheckBroadcastCondition %{public}s failed! status: %{public}s",
            typeStr.c_str(), status.ToString().c_str());
        return;
    }

    ContinueRecommendInfo info;
    if (!GetRecommendInfo(status, type, info)) {
        HILOGE("GetRecommendInfo failed, status: %{public}s", status.ToString().c_str());
        return;
    }

    int32_t ret = DmsHiAnalyticsReport::PublishRecommendInfo(info);
    if (ret != ERR_OK) {
        HILOGE("PublishRecommendInfo failed, ret: %{public}d, status: %{public}s", ret, status.ToString().c_str());
    }
    HILOGI("end, info: %{public}s", info.ToString().c_str());
    return;
}

bool DMSContinueRecomMgr::GetRecommendInfo(
    const MissionStatus& status, MissionEventType type, ContinueRecommendInfo& info)
{
    HILOGD("start, missionId: %{public}d", status.missionId);
    info.state_ = (type == MISSION_EVENT_FOCUSED || type == MISSION_EVENT_ACTIVE) ? STATE_ACTIVE : STATE_INACTIVE;
    info.srcBundleName_ = status.bundleName;
    info.userId_ = accountId_;

    AppExecFwk::AbilityInfo abilityInfo;
    int32_t result = BundleManagerInternal::GetLocalAbilityInfo(
        status.bundleName, status.moduleName, status.abilityName, abilityInfo);
    if (result != ERR_OK) {
        HILOGW("GetLocalAbilityInfo failed.");
        return false;
    }
    if (!abilityInfo.continueType.empty()) {
        info.continueType_ = abilityInfo.continueType[0];
    }

    std::map<std::string, DmsBundleInfo> availableList;
    bool ret = GetAvailableRecommendList(status.bundleName, availableList);
    if (ret && info.state_ == STATE_ACTIVE) {
        for (auto iter = availableList.begin(); iter != availableList.end(); iter++) {
            ContinueCandidate candidate;
            candidate.deviceId_ = iter->first;
            candidate.dstBundleName_ = iter->second.bundleName;
            info.candidates_.push_back(candidate);
        }
    }
    HILOGD("end");
    return true;
}

bool DMSContinueRecomMgr::GetAvailableRecommendList(const std::string& bundleName,
    std::map<std::string, DmsBundleInfo>& availableList)
{
    HILOGD("called, bundleName: %{public}s", bundleName.c_str());
    std::vector<std::string> networkIdList = DtbschedmgrDeviceInfoStorage::GetInstance().GetNetworkIdList();
    for (const std::string& networkId : networkIdList) {
        DmsBundleInfo sameBundleInfo;
        if (DmsBmStorage::GetInstance()->GetDistributedBundleInfo(networkId, bundleName, sameBundleInfo) &&
            sameBundleInfo.bundleName == bundleName) {
            availableList[networkId] = sameBundleInfo;
            continue;
        }

        HILOGW("get same bundle %{public}s on networkId %{public}s failed, try diff bundle.",
            bundleName.c_str(), GetAnonymStr(networkId).c_str());

        AppExecFwk::AppProvisionInfo appProvisionInfo;
        std::string localDeveloperId;
        if (BundleManagerInternal::GetAppProvisionInfo4CurrentUser(bundleName, appProvisionInfo)) {
            localDeveloperId = appProvisionInfo.developerId;
        }
        std::vector<DmsBundleInfo> bundleInfoList;
        if (!DmsBmStorage::GetInstance()->GetDistributeInfosByNetworkId(networkId, bundleInfoList)) {
            HILOGW("get bundle list on networkId %{public}s failed.", GetAnonymStr(networkId).c_str());
            continue;
        }
        for (const auto& diffBundleInfo : bundleInfoList) {
            if (diffBundleInfo.developerId == localDeveloperId &&
                IsContinuableWithDiffBundle(bundleName, diffBundleInfo)) {
                availableList[networkId] = diffBundleInfo;
                break;
            }
        }
    }
    return true;
}

bool DMSContinueRecomMgr::IsContinuableWithDiffBundle(const std::string& bundleName, const DmsBundleInfo& info)
{
    for (const auto& abilityInfo: info.dmsAbilityInfos) {
        auto contiName = abilityInfo.continueBundleName;
        if (std::find(contiName.begin(), contiName.end(), bundleName) != contiName.end()) {
            return true;
        }
    }
    return false;
}
}  // namespace DistributedSchedule
}  // namespace OHOS
