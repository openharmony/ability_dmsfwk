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

#include "dfx/dms_hianalytics_report.h"

#include <string>

#ifdef SUPPORT_HIANALYTICS_SERVICE
#include "dtbschedmgr_log.h"
#include "ha_client_lite_api.h"
#endif

namespace OHOS {
namespace DistributedSchedule {
using namespace OHOS::HiviewDFX;
namespace {
#ifdef SUPPORT_HIANALYTICS_SERVICE
const std::string TAG = "DmsHiAnalyticsReport";

const std::string HA_INSTANCE_TAG = "$SceneDataShare";
const std::string HA_EVENT_ID = "$APP_RECOMMEND_CONTINUATION";
const std::string HA_KEY_STATUS = "Status";
const std::string HA_KEY_SOURCE_BUNDLE_NAME = "SourceBundleName";
const std::string HA_KEY_CONTINUE_TYPE = "ContinueType";
const std::string HA_KEY_USER_ID = "UserId";
const std::string HA_KEY_CANDIDATES = "Candidates";
#endif
}

int32_t DmsHiAnalyticsReport::PublishRecommendInfo(const ContinueRecommendInfo& info)
{
    int32_t result = ERR_OK;
#ifdef SUPPORT_HIANALYTICS_SERVICE
    std::unordered_map<std::string, std::string> properties;
    properties.emplace(HA_KEY_STATE, std::to_string(info.state_));
    properties.emplace(HA_KEY_SOURCE_BUNDLE_NAME, info.srcBundleName_);
    properties.emplace(HA_KEY_CONTINUE_TYPE, info.continueType_);
    properties.emplace(HA_KEY_USER_ID, info.userId_);
    properties.emplace(HA_KEY_CANDIDATES, info.MarshalCandidates());

    OHOS::HaCloud::HaResponseLite rsp = OHOS::HaCloud::HaClientLiteApi::OnEvent(
        HA_INSTANCE_TAG,
        OHOS::HaCloud::EventTypeLite::operation,
        HA_EVENT_ID,
        properties);
    HILOGI("OnEvent rsp: code: %{public}d, msg: %{public}s", rsp.code, rsp.message.c_str());
    result = rsp.code;
#endif
    return result;
}
}
}
