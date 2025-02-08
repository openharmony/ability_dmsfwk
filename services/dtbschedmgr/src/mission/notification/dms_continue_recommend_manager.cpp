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

#include "dfx/dms_hianalytics_report.h"
#include "distributed_sched_utils.h"
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
    HILOGI("");
    int32_t missionId = GetCurrentMissionId();
    if (missionId <= 0) {
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
    info.state_ =(type == MISSION_EVENT_FOCUSED || type == MISSION_EVENT_ACTIVE) ? STATE_ACTIVE : STATE_INACTIVE;
    info.srcBundleName_ = status.bundleName;

    std::map<std::string, DmsBundleInfo> availableList;
    bool ret = DmsBmStorage::GetInstance()->GetAvailableRecommendList(status.bundleName, availableList);
    if (!ret) {
        HILOGW("GetAvailableRecommendList failed or empty.");
        return false;
    }
    if (info.state_ == STATE_ACTIVE) {
        PackRecommendCandidates(availableList, info.candidates_);
    }
    HILOGD("end");
    return true;
}

void DMSContinueRecomMgr::PackRecommendCandidates(
    const std::map<std::string, DmsBundleInfo>& availableList, std::vector<ContinueCandidate>& candidates)
{
    for (auto iter = availableList.begin(); iter != availableList.end(); iter++) {
        ContinueCandidate candidate;
        candidate.deviceId_ = iter->first;
        candidate.dstBundleName_ = iter->second.bundleName;
        candidate.token_ = 0;
        candidates.push_back(candidate);
    }
    return;
}
}  // namespace DistributedSchedule
}  // namespace OHOS
