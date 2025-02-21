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

#ifndef OHOS_DMS_CONTINUE_RECOMMEND_INFO_H
#define OHOS_DMS_CONTINUE_RECOMMEND_INFO_H

#include <string>

namespace OHOS {
namespace DistributedSchedule {
namespace {
constexpr int32_t STATE_INVALID = -1;
constexpr int32_t RECOMMEND_DEFAULT_USER_ID = 100;
}

struct ContinueCandidate {
    std::string deviceId_ = "";
    std::string dstBundleName_ = "";
};

class ContinueRecommendInfo {
public:
    ContinueRecommendInfo() = default;
    virtual ~ContinueRecommendInfo() = default;
    std::string MarshalCandidates() const;
    std::string ToString() const;
private:
    std::string MarshalCandidate(const ContinueCandidate& candidate) const;

public:
    int32_t state_ = STATE_INVALID;
    std::string srcBundleName_ = "";
    std::string continueType_ = "";
    int32_t userId_ = RECOMMEND_DEFAULT_USER_ID;
    std::vector<ContinueCandidate> candidates_ = {};
};
} // namespace DistributedSchedule
} // namespace OHOS
#endif // OHOS_DMS_CONTINUE_RECOMMEND_INFO_H
