/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "mission/param/param_common_event.h"

#include <common_event_data.h>
#include <common_event_manager.h>
#include <common_event_support.h>
#include <memory>
#include <unistd.h>
#include <iosfwd>
#include <sstream>

#include "dtbschedmgr_log.h"
#include "common_event_subscriber.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "ParamManager";
const int32_t RETRY_SUBSCRIBER = 3;
const int32_t TEN_BIT_SIZE = 10;
const std::string EVENT_INFO_TYPE = "type";
const std::string EVENT_INFO_SUBTYPE = "subtype";
const std::string CONTINUATION_SERVICE_DATA_PATH =
    "/data/service/el1/public/update/param_service/install/system/etc/ContinuationService/generic/";
const std::string CONTINUATION_SERVICE_DATA_FILE_NAME = "disable_continuation_service_applist.json";
constexpr char VERSION_CODE_KEY[] = "versionCode";
}

ParamCommonEvent::ParamCommonEvent()
{
    HILOGI("ParamCommonEvent ParamCommonEvent");
    handleEventFunc_["usual.event.DUE_SA_CFG_UPDATED"] = &ParamCommonEvent::HandleParamUpdate;
    eventHandles_["usual.event.DUE_SA_CFG_UPDATED"] =
        [this](const OHOS::AAFwk::Want &want) { this->HandleParamUpdate(want); };
}

ParamCommonEvent::~ParamCommonEvent()
{
    UnSubscriberEvent();
}

void ParamCommonEvent::SubscriberEvent()
{
    HILOGI("SubscriberEvent start.");
    if (subscriber_) {
        HILOGI("Common Event is already subscribered!");
        return;
    }
    EventFwk::MatchingSkills matchingSkills;
    for (auto &event : handleEventFunc_) {
        HILOGI("Add event: %{public}s", event.first.c_str());
        matchingSkills.AddEvent(event.first);
    }
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    subscriber_ = std::make_shared<ParamCommonEventSubscriber>(subscribeInfo, *this);

    int32_t retry = RETRY_SUBSCRIBER;
    do {
        bool subscribeResult = EventFwk::CommonEventManager::SubscribeCommonEvent(subscriber_);
        if (subscribeResult) {
            HILOGI("SubscriberEvent success.");
            return;
        } else {
            HILOGI("SubscriberEvent failed, retry %{public}d", retry);
            retry--;
            sleep(1);
        }
    } while (retry);

    HILOGI("SubscriberEvent failed.");
}

void ParamCommonEvent::UnSubscriberEvent()
{
    HILOGI("UnSubscriberEvent start.");
    eventHandles_.clear();
    handleEventFunc_.clear();
    if (subscriber_) {
        bool subscribeResult = EventFwk::CommonEventManager::UnSubscribeCommonEvent(subscriber_);
        HILOGI("subscribeResult = %{public}d", subscribeResult);
        subscriber_ = nullptr;
    }
    HILOGI("UnSubscriberEvent end.");
}

void ParamCommonEvent::OnReceiveEvent(const AAFwk::Want &want)
{
    std::string action = want.GetAction();
    auto it = eventHandles_.find(action);
    if (it == eventHandles_.end()) {
        HILOGI("Ignore event: %{public}s", action.c_str());
        return;
    }
    HILOGI("Handle event: %{public}s", action.c_str());
    it->second(want);
}

void ParamCommonEvent::HandleParamUpdate(const AAFwk::Want &want) const
{
    std::string action = want.GetAction();
    std::string type = want.GetStringParam(EVENT_INFO_TYPE);
    std::string subtype = want.GetStringParam(EVENT_INFO_SUBTYPE);
    HILOGI("recive param update event: %{public}s ,%{public}s ,%{public}s ", action.c_str(), type.c_str(),
        subtype.c_str());
    UpdateBlacklist();
}

static std::string Trim(const std::string &value)
{
    size_t left = 0;
    while (left < value.size() && isspace(static_cast<unsigned char>(value[left])) != 0) {
        ++left;
    }
    size_t right = value.size();
    while (right > left && isspace(static_cast<unsigned char>(value[right - 1])) != 0) {
        --right;
    }
    return value.substr(left, right - left);
}

static bool ParseUint32(const std::string &value, uint32_t &result)
{
    std::string trimValue = Trim(value);
    if (trimValue.empty()) {
        return false;
    }
    uint64_t acc = 0;
    for (const char ch : trimValue) {
        if (isdigit(static_cast<unsigned char>(ch)) == 0) {
            return false;
        }
        uint32_t digit = static_cast<uint32_t>(ch - '0');
        if (acc > (std::numeric_limits<uint32_t>::max() - digit) / TEN_BIT_SIZE) {
            return false;
        }
        acc = acc * TEN_BIT_SIZE + digit;
    }
    result = static_cast<uint32_t>(acc);
    return true;
}

static bool ParseVersionRange(const std::string &rule, std::pair<uint32_t, uint32_t> &range)
{
    std::string trimRule = Trim(rule);
    if (trimRule.empty()) {
        return false;
    }
    size_t splitPos = trimRule.find('-');
    if (splitPos == std::string::npos) {
        uint32_t versionCode = 0;
        if (!ParseUint32(trimRule, versionCode)) {
            return false;
        }
        range = {versionCode, versionCode};
        return true;
    }

    uint32_t startCode = 0;
    uint32_t endCode = 0;
    if (!ParseUint32(trimRule.substr(0, splitPos), startCode) ||
        !ParseUint32(trimRule.substr(splitPos + 1), endCode)) {
        return false;
    }
    if (startCode <= endCode) {
        range = {startCode, endCode};
    } else {
        range = {endCode, startCode};
    }
    return true;
}

bool ParamCommonEvent::UpdateBlacklist() const
{
    HILOGI("UpdateBlacklist");
    std::string filePath = CONTINUATION_SERVICE_DATA_PATH + CONTINUATION_SERVICE_DATA_FILE_NAME;
    std::ifstream file(filePath);
    if (!file.good()) {
        HILOGE("Verify is not good,verifyFile:%{public}s", filePath.c_str());
        return false;
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string jsonText = buffer.str();
    HILOGI("UpdateBlacklist, file context:%{public}s", jsonText.c_str());
    if (jsonText.empty()) {
        HILOGE("file is empty.");
        return false;
    }

    cJSON *root = cJSON_Parse(jsonText.c_str());
    if (root == nullptr || !cJSON_IsObject(root)) {
        HILOGE("Parse controllist json failed.");
        if (root != nullptr) {
            cJSON_Delete(root);
        }
        return false;
    }

    bool ret =  UpdateBlacklistInner(root);
    cJSON_Delete(root);
    return ret;
}

bool ParamCommonEvent::UpdateBlacklistInner(cJSON *root) const
{
    if (root == nullptr || !cJSON_IsObject(root)) {
        HILOGE("UpdateBlacklistInner invalid root.");
        return false;
    }
    std::unordered_map<std::string, std::vector<std::pair<uint32_t, uint32_t>>> tempBlackList;
    for (cJSON *bundleItem = root->child; bundleItem != nullptr; bundleItem = bundleItem->next) {
        if (bundleItem->string == nullptr || !cJSON_IsObject(bundleItem)) {
            continue;
        }
        cJSON *versionCodeArray = cJSON_GetObjectItemCaseSensitive(bundleItem, VERSION_CODE_KEY);
        if (versionCodeArray == nullptr || !cJSON_IsArray(versionCodeArray)) {
            continue;
        }

        std::vector<std::pair<uint32_t, uint32_t>> versionRanges;
        cJSON *versionRuleItem = nullptr;
        cJSON_ArrayForEach(versionRuleItem, versionCodeArray) {
            if (!cJSON_IsString(versionRuleItem) || versionRuleItem->valuestring == nullptr) {
                continue;
            }
            std::pair<uint32_t, uint32_t> range;
            if (ParseVersionRange(versionRuleItem->valuestring, range)) {
                versionRanges.push_back(range);
            }
        }
        if (!versionRanges.empty()) {
            tempBlackList[std::string(bundleItem->string)] = std::move(versionRanges);
        }
    }

    blackListMap_ = std::move(tempBlackList);
    HILOGI("Update controllist success, bundle size: %{public}zu.", blackListMap_.size());
    return true;
}

bool ParamCommonEvent::CheckBlacklist(std::string bundleName, uint32_t versionCode)
{
    HILOGI("CheckBlacklist, versionCode: %{public}d", versionCode);
    auto bundleIter = blackListMap_.find(bundleName);
    if (bundleIter == blackListMap_.end()) {
        HILOGI("CheckBlacklist, bundleIter == blackListMap_.end()");
        return false;
    }

    for (const auto &range : bundleIter->second) {
        if (versionCode >= range.first && versionCode <= range.second) {
            HILOGI("Hit controllist, bundleName: %{public}s, versionCode: %{public}u.",
                bundleName.c_str(), versionCode);
            return true;
        }
    }
    HILOGI("CheckBlacklist end");
    return false;
}
} // namespace DistributedSchedule
} // namespace OHOS
