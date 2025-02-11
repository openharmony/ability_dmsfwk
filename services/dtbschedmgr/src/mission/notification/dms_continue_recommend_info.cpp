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

#include "mission/notification/dms_continue_recommend_info.h"

#include "cJSON.h"
#include "distributed_sched_utils.h"
#include "dtbschedmgr_log.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "DmsContinueRecommendInfo";
}

std::string ContinueRecommendInfo::MarshalCandidates() const
{
    cJSON *rootValue = cJSON_CreateObject();
    if (rootValue == nullptr) {
        return "";
    }

    const auto candidatesSize = static_cast<int32_t>(candidates_.size());
    cJSON *candidates = cJSON_CreateArray();
    if (candidates == nullptr) {
        cJSON_Delete(rootValue);
        return "";
    }
    for (auto i = 0; i < candidatesSize; i++) {
        cJSON *candidateStr = cJSON_CreateString(MarshalCandidate(candidates_[i]).c_str());
        if (candidateStr == nullptr) {
            cJSON_Delete(rootValue);
            cJSON_Delete(candidates);
            return "";
        }
        cJSON_AddItemToArray(candidates, candidateStr);
    }
    cJSON_AddItemToObject(rootValue, "Candidates", candidates);

    char *data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        return "";
    }
    std::string jsonStr = std::string(data);
    cJSON_Delete(rootValue);
    cJSON_free(data);
    return jsonStr;
}

std::string ContinueRecommendInfo::MarshalCandidate(const ContinueCandidate& candidate) const
{
    cJSON *rootValue = cJSON_CreateObject();
    if (rootValue == nullptr) {
        return "";
    }
    cJSON_AddStringToObject(rootValue, "DeviceId", candidate.deviceId_.c_str());
    cJSON_AddStringToObject(rootValue, "DstBundleName", candidate.dstBundleName_.c_str());

    char *data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        return "";
    }

    std::string jsonStr = std::string(data);
    cJSON_Delete(rootValue);
    cJSON_free(data);
    return jsonStr;
}

std::string ContinueRecommendInfo::ToString() const
{
    std::string str =
        "State: " + std::to_string(state_) + ", " +
        "SrcBundleName: " + srcBundleName_ + ", "+
        "ContinueType: " + continueType_ + ", " +
        "UserId: " + userId_ + ", " +
        "Candidates: ";
    for (auto candidate: candidates_) {
        str += "\n{ DeviceId: " + GetAnonymStr(candidate.deviceId_) + ", " +
            "DstBundleName: " + candidate.dstBundleName_ + " }";
    }
    return str;
}
}  // namespace DistributedSchedule
}  // namespace OHOS
