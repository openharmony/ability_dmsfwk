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

#include "array_wrapper.h"
#include "dtbschedmgr_device_info_storage.h"
#include "dtbschedmgr_log.h"
#ifdef SUPPORT_HIANALYTICS_SERVICE
#include "ha_client_lite_api.h"
#endif
#include "string_wrapper.h"
#include "want_params_wrapper.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
#ifdef SUPPORT_HIANALYTICS_SERVICE
const std::string TAG = "DmsHiAnalyticsReport";

const std::string HA_INSTANCE_TAG = "$SceneDataShare";
const std::string HA_RECOMMEND_EVENT_ID = "$APP_RECOMMEND_CONTINUATION";
const std::string HA_CONTINUATION_EVENT_ID = "$APP_CONTINUATION_EVENT";
const std::string HA_KEY_STATUS = "$Status";
const std::string HA_KEY_SRC_BUNDLE_NAME = "$SrcBundleName";
const std::string HA_KEY_DST_BUNDLE_NAME = "$DstBundleName";
const std::string HA_KEY_SRC_DEVICE_ID = "$SrcDeviceId";
const std::string HA_KEY_DST_DEVICE_ID = "$DstDeviceId";
const std::string HA_KEY_CONTINUE_TYPE = "$ContinueType";
const std::string HA_KEY_USER_ID = "$UserId";
const std::string HA_KEY_CANDIDATES = "$Candidates";
#endif
}

int32_t DmsHiAnalyticsReport::PublishRecommendInfo(const ContinueRecommendInfo& info)
{
    int32_t result = ERR_OK;
#ifdef SUPPORT_HIANALYTICS_SERVICE
    std::string localNetworkId;
    if (!DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(localNetworkId)) {
        HILOGE("PublishRecommendInfo get local deviceId failed!");
        return INVALID_REMOTE_PARAMETERS_ERR;
    }
    std::unordered_map<std::string, std::string> properties;
    properties.emplace(HA_KEY_STATUS, std::to_string(info.state_));
    properties.emplace(HA_KEY_SRC_BUNDLE_NAME, info.srcBundleName_);
    properties.emplace(HA_KEY_SRC_DEVICE_ID, localNetworkId);
    properties.emplace(HA_KEY_CONTINUE_TYPE, info.continueType_);
    properties.emplace(HA_KEY_USER_ID, std::to_string(info.userId_));

    sptr<AAFwk::Array> array = sptr<AAFwk::Array>::MakeSptr(info.candidates_.size(), AAFwk::g_IID_IWantParams);
    std::string candidateStr = "";
    if (array != nullptr) {
        for (size_t i = 0; i < info.candidates_.size(); i++) {
            AAFwk::WantParams candidateParam;
            candidateParam.SetParam(HA_KEY_DST_DEVICE_ID, AAFwk::String::Box(info.candidates_[i].deviceId_));
            candidateParam.SetParam(HA_KEY_DST_BUNDLE_NAME, AAFwk::String::Box(info.candidates_[i].dstBundleName_));
            array->Set(i, AAFwk::WantParamWrapper::Box(candidateParam));
        }
        candidateStr = array->ToString();
    }
    properties.emplace(HA_KEY_CANDIDATES, candidateStr);

    OHOS::HaCloud::HaResponseLite rsp = OHOS::HaCloud::HaClientLiteApi::OnEvent(
        HA_INSTANCE_TAG,
        OHOS::HaCloud::EventTypeLite::operation,
        HA_RECOMMEND_EVENT_ID,
        properties);
    HILOGI("OnEvent rsp: code: %{public}d, msg: %{public}s", rsp.code, rsp.message.c_str());
    result = rsp.code;
#endif
    return result;
}

int32_t DmsHiAnalyticsReport::PublishContinueEvent(const DSchedContinueInfo& info)
{
    int32_t result = ERR_OK;
#ifdef SUPPORT_HIANALYTICS_SERVICE
    std::unordered_map<std::string, std::string> properties;
    properties.emplace(HA_KEY_SRC_DEVICE_ID, info.sourceDeviceId_);
    properties.emplace(HA_KEY_DST_DEVICE_ID, info.sinkDeviceId_);
    properties.emplace(HA_KEY_SRC_BUNDLE_NAME, info.sourceBundleName_);
    properties.emplace(HA_KEY_DST_BUNDLE_NAME, info.sinkBundleName_);
    properties.emplace(HA_KEY_CONTINUE_TYPE, info.continueType_);

    OHOS::HaCloud::HaResponseLite rsp = OHOS::HaCloud::HaClientLiteApi::OnEvent(
        HA_INSTANCE_TAG,
        OHOS::HaCloud::EventTypeLite::operation,
        HA_CONTINUATION_EVENT_ID,
        properties);
    HILOGI("OnEvent rsp: code: %{public}d, msg: %{public}s", rsp.code, rsp.message.c_str());
    result = rsp.code;
#endif
    return result;
}
}
}
