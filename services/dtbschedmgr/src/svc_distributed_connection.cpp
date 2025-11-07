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

#include "svc_distributed_connection.h"

#include <chrono>
#include <iomanip>
#include <thread>
#include <map>

#include "ability_manager_client.h"
#include "common_event_manager.h"
#include "common_event_subscribe_info.h"
#include "cJSON.h"
#include "device_manager.h"
#include "distributed_extension_proxy.h"
#include "distributed_sched_utils.h"
#include "dtbschedmgr_log.h"
#include "file_ex.h"
#include "hisysevent.h"
#include "locale_config.h"
#include "locale_info.h"
#include "notification_bundle_option.h"
#include "notification_constant.h"
#include "notification_helper.h"
#include "notification_request.h"
#include "want_agent_helper.h"
#include "want_agent_info.h"
#include "string_wrapper.h"

namespace OHOS {
namespace DistributedSchedule {
const std::string TAG = "SvcDistributedConnection";
constexpr int WAIT_TIME = 3;
constexpr int32_t TIME_OUT_CLOSE = 10 * 1000 * 1000;  // 10s;
constexpr int32_t TIME_OUT_NOTIFICATION = 10 * 1000;

constexpr const char* DMS_LANGUAGE_MAP_PATH = "system/etc/dmsfwk/resources/base/profile/dms_language_map.json";
constexpr const char* DMS_DEFAULT_LANGUAGE_FILE_PATH = "zh_CN";
constexpr const char* DMS_LANGUAGE_FILEPATH_PREFIX = "system/etc/dmsfwk/resources/";
constexpr const char* DMS_LANGUAGE_FILEPATH_SUFFIX = "/element/string.json";
constexpr const char* DMS_ZHTW_LANGUAGE_FILE_PATH = "zh_TW";
constexpr const char* DMS_ZHHANT_LANGUAGE_FILE_PATH = "zh-Hant";  // The language type is Traditional Chinese
constexpr const char* DMS_ZHTW_REGION = "TW";

constexpr const char* KEY_LANGUAGE_MAP = "dms_language_map";
constexpr const char* KEY_SYSTEM_LANGUAGE = "system_language";
constexpr const char* KEY_FILE_PATH = "file_path";
constexpr const char* KEY_STRING = "string";
constexpr const char* KEY_NAME = "name";
constexpr const char* KEY_VALUE = "value";
constexpr const char* KEY_TAG_USING = "Using";
constexpr const char* KEY_TAG_BGS = "BackgroundService";
constexpr const char* KEY_TAG_EOS = "EOS";

const int MAX_RES_VEC_LEN = 100;
const std::string PKG_NAME = "DBinderBus_Dms_" + std::to_string(getprocpid());
const uint32_t DMS_UID = 5522;
const int32_t NOTIFICATION_BANNER_FLAG = 1 << 9;
static std::string g_sysLanguage = "";
static std::string g_sysRegion = "";
static std::mutex g_resourceMutex;
static std::map<std::string, std::string> g_resourceMap;

const std::string CONNECT_PROXY = "VALUE_ABILITY_COLLAB_TYPE_CONNECT_PROXY";
const std::string COLLABRATION_TYPE = "CollabrationType";
const std::string SOURCE_DELEGATEE = "SourceDelegatee";
using namespace std;
using namespace AAFwk;

void SvcDistributedConnection::OnAbilityConnectDone(const AppExecFwk::ElementName &element,
    const sptr<IRemoteObject> &remoteObject, int resultCode)
{
    HILOGI("called begin");
    if (remoteObject == nullptr) {
        HILOGE("Failed to ability connect done, remote is nullptr");
        return;
    }
    auto func = [this]() {
        HILOGI("close begin");
        usleep(TIME_OUT_CLOSE);
        while (isDelay_.load()) {
            isDelay_.store(false);
            usleep(TIME_OUT_CLOSE);
        }
        this->DisconnectDistributedExtAbility();
        HILOGI("close end");
    };
    std::thread task(func);
    task.detach();
    distributedProxy_ = iface_cast<IDExtension>(remoteObject);
    if (distributedProxy_ == nullptr) {
        HILOGE("Failed to ability connect done, distributedProxy_ is nullptr");
        return;
    }
    isConnected_.store(true);
    string bundleName = element.GetBundleName();
    HILOGI("bundleName:%{public}s, OnAbilityConnectDone, bundleNameIndexInfo:%{public}s", bundleName.c_str(),
        bundleNameIndexInfo_.c_str());
    if (bundleNameIndexInfo_.find(bundleName) == string::npos) {
        HILOGE("Current bundle name is wrong, bundleNameIndexInfo:%{public}s, bundleName:%{public}s",
            bundleNameIndexInfo_.c_str(), bundleName.c_str());
        return;
    }
    bundleName = bundleNameIndexInfo_;
    callConnected_(move(bundleName));
    HILOGI("called end");
}

void SvcDistributedConnection::OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int resultCode)
{
    HILOGI("called begin");
    isConnected_.store(false);
    string bundleName = element.GetBundleName();
    HILOGI("bundleName:%{public}s, OnAbilityDisconnectDone, bundleNameIndexInfo:%{public}s", bundleName.c_str(),
        bundleNameIndexInfo_.c_str());
    if (bundleNameIndexInfo_.find(bundleName) == string::npos) {
        HILOGE("Current bundle name is wrong, bundleNameIndexInfo:%{public}s, bundleName:%{public}s",
            bundleNameIndexInfo_.c_str(), bundleName.c_str());
        return;
    }
    bundleName = bundleNameIndexInfo_;
    HILOGI("called end, name: %{public}s", bundleNameIndexInfo_.c_str());
}

ErrCode SvcDistributedConnection::ConnectDExtAbility(AAFwk::Want &want, int32_t userId, bool isCleanCalled,
    const std::string& delegatee, bool &isDelay)
{
    HILOGI("SvcDistributedConnection::ConnectDExtAbility Called begin");
    if (isConnectCalled_.load()) {
        HILOGI("Connect distributed extension called before");
        isDelay_.store(true);
        HILOGI("Connect ability again, isDelay:%{public}d", isDelay_.load());
        auto proxy = GetDistributedExtProxy();
        if (proxy == nullptr) {
            HILOGE("Extension distribute proxy is empty");
            return INVALID_PARAMETERS_ERR;
        }
        AAFwk::WantParams wantParam;
        wantParam.SetParam(COLLABRATION_TYPE, String::Box(CONNECT_PROXY));
        wantParam.SetParam(SOURCE_DELEGATEE, String::Box(delegatee));
        proxy->TriggerOnCollaborate(wantParam);
        isDelay = true;
        return ERR_OK;
    }
    isCleanCalled_.store(isCleanCalled);
    std::unique_lock<std::mutex> lock(mutex_);
    ErrCode ret = AAFwk::AbilityManagerClient::GetInstance()->ConnectAbility(want, this, userId);
    if (ret == ERR_OK) {
        isConnectCalled_.store(true);
    }
    HILOGI("Called end, ret=%{public}d, userId=%{public}d.", ret, userId);
    return ret;
}

ErrCode SvcDistributedConnection::DisconnectDistributedExtAbility()
{
    HILOGI("called begin");
    std::unique_lock<std::mutex> lock(mutex_);
    isConnectCalled_.store(false);
    if (distributedProxy_ == nullptr) {
        HILOGE("distributedProxy is nullptr");
        return INVALID_PARAMETERS_ERR;
    }
    int32_t res = distributedProxy_->TriggerOnDestroy();
    if (res != ERR_OK) {
        HILOGE("destroy connect failed");
    }
    ErrCode ret = AppExecFwk::AbilityManagerClient::GetInstance()->DisconnectAbility(this);
    auto callback = [extConn {wptr(this)}] {
        auto extPtr = extConn.promote();
        if (!extPtr) {
            HILOGE("Dis connect failed");
            return false;
        }
        return extPtr->isConnected_.load() == false;
    };
    if (condition_.wait_for(lock, std::chrono::seconds(WAIT_TIME), callback)) {
        HILOGI("Wait until the connection ends");
    }
    HILOGI("called end, ret=%{public}d", ret);
    return ret;
}

bool SvcDistributedConnection::IsExtAbilityConnected()
{
    return isConnected_.load();
}

sptr<IDExtension> SvcDistributedConnection::GetDistributedExtProxy()
{
    return distributedProxy_;
}

void SvcDistributedConnection::SetCallback(function<void(const std::string &&)> callConnected)
{
    callConnected_ = callConnected;
}

static void UpdateResourceMap(const std::string &resourcePath)
{
    HILOGI("Reading resource string from json config.");

    std::string content;
    LoadStringFromFile(resourcePath, content);
    cJSON *json = cJSON_Parse(content.c_str());
    if (json == nullptr) {
        HILOGE("json nullptr.");
        return;
    }

    cJSON *resJson = cJSON_GetObjectItemCaseSensitive(json, KEY_STRING);
    if (resJson == nullptr || cJSON_GetArraySize(resJson) > MAX_RES_VEC_LEN) {
        HILOGE("fail to parse res json");
        cJSON_Delete(json);
        return;
    }

    {
        std::lock_guard<std::mutex> lock(g_resourceMutex);
        g_resourceMap.clear();
    }
    cJSON *resJsonEach = nullptr;
    cJSON_ArrayForEach(resJsonEach, resJson) {
        cJSON *key = cJSON_GetObjectItemCaseSensitive(resJsonEach, KEY_NAME);
        if (key == nullptr || !cJSON_IsString(key)) {
            HILOGE("json param not string");
            cJSON_Delete(json);
            return;
        }

        cJSON *value = cJSON_GetObjectItemCaseSensitive(resJsonEach, KEY_VALUE);
        if (value == nullptr || !cJSON_IsString(value)) {
            HILOGE("json param not string");
            cJSON_Delete(json);
            return;
        }

        std::lock_guard<std::mutex> lock(g_resourceMutex);
        g_resourceMap.insert(std::pair<std::string, std::string>(key->valuestring, value->valuestring));
    }
    cJSON_Delete(json);
}

static std::string GetLanguageFilePath(const std::string &sysLanguage, const std::string &sysRegion)
{
    HILOGI("Reading language file path from json config.");
    std::string content;
    std::string filePath = DMS_DEFAULT_LANGUAGE_FILE_PATH;
    LoadStringFromFile(DMS_LANGUAGE_MAP_PATH, content);
    cJSON *json = cJSON_Parse(content.c_str());
    if (json == nullptr) {
        HILOGE("json nullptr.");
        return filePath;
    }

    cJSON *resJson = cJSON_GetObjectItemCaseSensitive(json, KEY_LANGUAGE_MAP);
    if (resJson == nullptr || !cJSON_IsArray(resJson)) {
        HILOGE("fail to parse KEY_LANGUAGE_MAP");
        cJSON_Delete(json);
        return filePath;
    }

    if (sysLanguage == DMS_ZHHANT_LANGUAGE_FILE_PATH && sysRegion == DMS_ZHTW_REGION) {
        cJSON_Delete(json);
        HILOGI("file path is zh-TW");
        return DMS_ZHTW_LANGUAGE_FILE_PATH;
    }

    cJSON *resJsonEach = nullptr;
    cJSON_ArrayForEach(resJsonEach, resJson) {
        cJSON *key = cJSON_GetObjectItemCaseSensitive(resJsonEach, KEY_SYSTEM_LANGUAGE);
        if (key == nullptr || !cJSON_IsString(key)) {
            HILOGE("json param KEY_SYSTEM_LANGUAGE not string");
            continue;
        }
        if (key->valuestring != sysLanguage) {
            continue;
        }

        cJSON *value = cJSON_GetObjectItemCaseSensitive(resJsonEach, KEY_FILE_PATH);
        if (value == nullptr || !cJSON_IsString(value)) {
            HILOGE("json param KEY_FILE_PATH not string");
            cJSON_Delete(json);
            return filePath;
        }

        filePath = value->valuestring;
        break;
    }
    cJSON_Delete(json);
    HILOGI("file path %{public}s", GetAnonymStr(filePath).c_str());
    return filePath;
}

static void UpdateResourceMapByLanguage()
{
    std::string curSysLanguage = Global::I18n::LocaleConfig::GetSystemLanguage();
    std::string curSysRegion = Global::I18n::LocaleConfig::GetSystemRegion();
    if (g_sysLanguage == curSysLanguage && curSysRegion == g_sysRegion) {
        HILOGD("same language environment[%{public}s], region[%{public}s] ,no need to update resource map.",
            curSysLanguage.c_str(), curSysRegion.c_str());
        return;
    }

    HILOGI("current system language[%{public}s], region[%{public}s] changes, should update resource map",
        curSysLanguage.c_str(), curSysRegion.c_str());
    g_sysLanguage = curSysLanguage;
    g_sysRegion = curSysRegion;

    std::string filePath = DMS_LANGUAGE_FILEPATH_PREFIX +
                        GetLanguageFilePath(g_sysLanguage, g_sysRegion) +
                        DMS_LANGUAGE_FILEPATH_SUFFIX;
    UpdateResourceMap(filePath);
}

void SvcDistributedConnection::EndTaskFunction()
{
    HILOGI("End task function called");
    if (isConnected_.load()) {
        DisconnectDistributedExtAbility();
    }
}

static int64_t GetDeliveryTime()
{
    auto now = std::chrono::system_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch());
    return duration.count();
}

static void SetBasicOptions(Notification::NotificationRequest &request, AppExecFwk::ApplicationInfo &appInfo)
{
    request.SetCreatorUid(DMS_UID);
    request.SetOwnerUid(appInfo.uid);
    request.SetDeliveryTime(GetDeliveryTime());
    request.SetAutoDeletedTime(GetDeliveryTime() + TIME_OUT_NOTIFICATION);
    request.SetTapDismissed(true);
    request.SetSlotType(OHOS::Notification::NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    request.SetNotificationControlFlags(NOTIFICATION_BANNER_FLAG);
}

void SvcDistributedConnection::RegisterEventListener()
{
    HILOGI("Registering event listener for DMS_ACTION_END_TASK");
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent("DMS_ACTION_END_TASK");
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    auto subscriber = std::make_shared<EndTaskEventSubscriber>(subscribeInfo, this);
    if (!EventFwk::CommonEventManager::SubscribeCommonEvent(subscriber)) {
        HILOGE("Failed to subscribe to common event DMS_ACTION_END_TASK");
    }
}

static void SetEndTaskButton(Notification::NotificationRequest& request)
{
    auto want = std::make_shared<AAFwk::Want>();
    want->SetAction("DMS_ACTION_END_TASK");

    std::vector<std::shared_ptr<AAFwk::Want>> wants;
    wants.push_back(want);
    std::vector<AbilityRuntime::WantAgent::WantAgentConstant::Flags> flags;
    flags.push_back(AbilityRuntime::WantAgent::WantAgentConstant::Flags::CONSTANT_FLAG);
    AbilityRuntime::WantAgent::WantAgentInfo wantAgentInfo(
        0, AbilityRuntime::WantAgent::WantAgentConstant::OperationType::SEND_COMMON_EVENT,
        flags, wants, nullptr
    );

    auto wantAgent = AbilityRuntime::WantAgent::WantAgentHelper::GetWantAgent(wantAgentInfo);
    if (wantAgent == nullptr) {
        HILOGE("Failed to create WantAgent.");
        return;
    }

    std::lock_guard<std::mutex> lock(g_resourceMutex);
    std::string buttonName = g_resourceMap[KEY_TAG_EOS];
    std::shared_ptr<Notification::NotificationActionButton> actionButton =
        Notification::NotificationActionButton::Create(nullptr, buttonName, wantAgent);

    if (actionButton == nullptr) {
        HILOGE("Failed to create action button.");
        return;
    }
    request.AddActionButton(actionButton);
}

void SvcDistributedConnection::PublishDExtensionNotification(const std::string &deviceId,
    const std::string &bundleName, const int32_t userId,
    const std::string &networkId, AppExecFwk::BundleResourceInfo &bundleResourceInfo)
{
    HILOGI("SvcDistributedConnection::PublishDExtensionNotification called");
    UpdateResourceMapByLanguage();
    std::shared_ptr<Notification::NotificationNormalContent> normalContent =
        std::make_shared<Notification::NotificationNormalContent>();
    if (normalContent == nullptr) {
        HILOGE("Set notification normal content nullptr");
        return;
    }

    std::string deviceName;
    int32_t ret = DistributedHardware::DeviceManager::GetInstance().GetDeviceName(PKG_NAME, networkId, deviceName);
    if (ret != ERR_OK) {
        HILOGE("Failed to get device name, ret = %{public}d", ret);
        return;
    }
    normalContent->SetTitle(bundleResourceInfo.label);
    {
        std::lock_guard<std::mutex> lock(g_resourceMutex);
        normalContent->SetText(deviceName + g_resourceMap[KEY_TAG_USING] + bundleResourceInfo.label +
            g_resourceMap[KEY_TAG_BGS]);
    }

    std::shared_ptr<Notification::NotificationContent> content =
        std::make_shared<Notification::NotificationContent>(normalContent);
    if (content == nullptr) {
        HILOGE("Set notification content nullptr");
        return;
    }

    AppExecFwk::ApplicationInfo appInfo;
    auto bundleMgr_ = BundleManagerInternal::GetBundleManager();
    if (bundleMgr_ == nullptr) {
        HILOGE("Get bundle manager failed");
        return;
    }
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    if (!bundleMgr_->GetApplicationInfo(bundleName, AppExecFwk::ApplicationFlag::GET_BASIC_APPLICATION_INFO, userId,
        appInfo)) {
        HILOGE("Get application info failed");
        return;
    }
    IPCSkeleton::SetCallingIdentity(identity);

    Notification::NotificationRequest request;
    SetBasicOptions(request, appInfo);
    request.SetContent(content);
    SetEndTaskButton(request);

    ret = Notification::NotificationHelper::PublishNotification(request);
    if (ret != 0) {
        HILOGE("Publish notification failed, ret = %{public}d", ret);
        return;
    }
}
}
}