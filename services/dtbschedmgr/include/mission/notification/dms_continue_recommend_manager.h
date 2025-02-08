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

#ifndef OHOS_DMS_CONTINUE_RECOMMEND_MGR_H
#define OHOS_DMS_CONTINUE_RECOMMEND_MGR_H

#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <cstdint>

#include "event_handler.h"
#include "mission/distributed_bundle_info.h"
#include "mission/dms_continue_condition_manager.h"
#include "mission/notification/dms_continue_recommend_info.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
    constexpr int32_t DEFAULT_USER_ID = 100;
}

class DMSContinueRecomMgr {
public:
    DMSContinueRecomMgr() = default;
    ~DMSContinueRecomMgr();
    void Init(int32_t currentAccountId);
    void UnInit();

    void OnDeviceChanged();
    void OnMissionStatusChanged(int32_t missionId, MissionEventType type);
private:
    void StartEvent();
    void PublishContinueRecommend(const MissionStatus& status, MissionEventType type);
    bool GetRecommendInfo(const MissionStatus& status, MissionEventType type, ContinueRecommendInfo& info);
    void PackRecommendCandidates(const std::map<std::string, DmsBundleInfo>& availableList,
        std::vector<ContinueCandidate>& candidates);
private:
    int32_t accountId_ = DEFAULT_USER_ID;
    std::thread eventThread_;
    std::condition_variable eventCon_;
    std::mutex eventMutex_;
    std::shared_ptr<OHOS::AppExecFwk::EventHandler> eventHandler_;
};
}  // namespace DistributedSchedule
}  // namespace OHOS
#endif  // OHOS_DMS_CONTINUE_RECOMMEND_MGR_H
