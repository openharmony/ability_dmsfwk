/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "distributed_ability_manager_service.h"

#include <chrono>
#include <thread>

#include "ability_manager_client.h"
#include "base/continuationmgr_log.h"
#include "base/parcel_helper.h"
#include "bundlemgr/bundle_mgr_interface.h"
#include "bundlemgr/bundle_mgr_proxy.h"
#include "continuation_manager/app_connection_stub.h"
#include "continuation_manager/app_device_callback_stub.h"
#include "continuation_manager/device_selection_notifier_proxy.h"
#include "continuation_manager/notifier_death_recipient.h"
#include "distributed_ability_manager_dumper.h"
#include "file_ex.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "os_account_manager.h"
#include "parameters.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "ContinuationManagerService";
const std::u16string HIPLAY_PANEL_INTERFACE_TOKEN = u"ohos.hiplay.panel";
const std::string TOKEN_KEY = "distributedsched.continuationmanager.token";
const std::string DEFAULT_TOKEN_VALUE = "0";
const std::string DMS_HIPLAY_ACTION = "ohos.ability.action.deviceSelect";
constexpr int32_t MAX_TOKEN_NUM = 100000000;
constexpr int32_t MAX_REGISTER_NUM = 600;
constexpr int32_t START_DEVICE_MANAGER_CODE = 1;
constexpr int32_t UPDATE_CONNECT_STATUS_CODE = 2;
}

IMPLEMENT_SINGLE_INSTANCE(DistributedAbilityManagerService);
const bool REGISTER_RESULT = SystemAbility::MakeAndRegisterAbility(&DistributedAbilityManagerService::GetInstance());

DistributedAbilityManagerService::DistributedAbilityManagerService() : SystemAbility(CONTINUATION_MANAGER_SA_ID, true)
{
}

void DistributedAbilityManagerService::OnStart()
{
    HILOGI("begin");
    {
        std::lock_guard<std::mutex> tokenLock(tokenMutex_);
        std::string tokenStr = system::GetParameter(TOKEN_KEY, DEFAULT_TOKEN_VALUE);
        if (!tokenStr.empty()) {
            token_.store(std::stoi(tokenStr));
        }
    }
    notifierDeathRecipient_ = sptr<IRemoteObject::DeathRecipient>(new NotifierDeathRecipient());
    if (continuationHandler_ == nullptr) {
        continuationHandler_ = std::make_shared<ffrt::queue>("ContinuationMgr");
    }
    Publish(this);
}

void DistributedAbilityManagerService::OnStop()
{
    HILOGI("begin");
}

int32_t DistributedAbilityManagerService::Dump(int32_t fd, const std::vector<std::u16string>& args)
{
    std::vector<std::string> argsInStr8;
    for (const auto& arg : args) {
        argsInStr8.emplace_back(Str16ToStr8(arg));
    }
    std::string result;
    DistributedAbilityManagerDumper::Dump(argsInStr8, result);
    if (!SaveStringToFd(fd, result)) {
        HILOGE("save to fd failed");
        return DMS_WRITE_FILE_FAILED_ERR;
    }
    return ERR_OK;
}

void DistributedAbilityManagerService::DumpAppRegisterInfo(std::string& info)
{
    std::lock_guard<std::mutex> autoLock(tokenMapMutex_);
    info += "application register infos:\n";
    info += "  ";
    if (!tokenMap_.empty()) {
        for (const auto& tokenMap : tokenMap_) {
            info += "accessToken: ";
            info += std::to_string(tokenMap.first);
            std::vector<int32_t> tokenVec = tokenMap.second;
            DumpNotifierLocked(tokenVec, info);
            info += "\n";
            info += "  ";
        }
    } else {
        info += "  <none info>\n";
    }
}

void DistributedAbilityManagerService::DumpNotifierLocked(const std::vector<int32_t>& tokenVec, std::string& info)
{
    std::lock_guard<std::mutex> callbackMapLock(callbackMapMutex_);
    for (const auto& token : tokenVec) {
        info += ", ";
        info += "token: ";
        info += std::to_string(token);
        if (callbackMap_.find(token) == callbackMap_.end()) {
            continue;
        }
        if (callbackMap_[token] == nullptr) {
            HILOGE("this ptr is null");
            return;
        }
        if (!callbackMap_[token]->IsNotifierMapEmpty()) {
            info += ", ";
            info += "cbType: ";
            if (callbackMap_[token]->GetNotifier(EVENT_CONNECT) != nullptr) {
                info += " ";
                info += EVENT_CONNECT;
            }
            if (callbackMap_[token]->GetNotifier(EVENT_DISCONNECT) != nullptr) {
                info += " ";
                info += EVENT_DISCONNECT;
            }
        }
    }
}

int32_t DistributedAbilityManagerService::Register(
    const std::shared_ptr<ContinuationExtraParams>& continuationExtraParams, int32_t& token)
{
    HILOGD("called");
    if (continuationExtraParams != nullptr) {
        ContinuationMode continuationMode = continuationExtraParams->GetContinuationMode();
        if (!IsContinuationModeValid(continuationMode)) {
            return INVALID_CONTINUATION_MODE;
        }
    }
    uint32_t accessToken = IPCSkeleton::GetCallingTokenID();
    if (IsExceededRegisterMaxNum(accessToken)) {
        return REGISTER_EXCEED_MAX_TIMES;
    }
    int32_t tToken = -1;
    {
        std::lock_guard<std::mutex> tokenLock(tokenMutex_);
        tToken = token_.load();
        if (++tToken > MAX_TOKEN_NUM) {
            tToken = 1;
        }
        token_.store(tToken);
        // save at parameters
        system::SetParameter(TOKEN_KEY, std::to_string(tToken));
    }
    // update tokenMap_
    {
        std::lock_guard<std::mutex> tokenMapLock(tokenMapMutex_);
        tokenMap_[accessToken].emplace_back(tToken);
    }
    token = tToken;
    return ERR_OK;
}

int32_t DistributedAbilityManagerService::Unregister(int32_t token)
{
    HILOGD("called");
    uint32_t accessToken = IPCSkeleton::GetCallingTokenID();
    if (!IsTokenRegistered(accessToken, token)) {
        return TOKEN_HAS_NOT_REGISTERED;
    }
    // remove death recipient and update callbackMap_ by token
    {
        std::lock_guard<std::mutex> callbackMapLock(callbackMapMutex_);
        if (IsNotifierRegistered(token)) {
            callbackMap_[token]->RemoveDeathRecipient(notifierDeathRecipient_);
            callbackMap_.erase(token);
        }
    }
    // update tokenMap_ by token
    {
        std::lock_guard<std::mutex> tokenMapLock(tokenMapMutex_);
        for (auto iter = tokenMap_.begin(); iter != tokenMap_.end();) {
            iter->second.erase(std::remove_if(iter->second.begin(), iter->second.end(),
                [token](int32_t n) { return n == token; }), iter->second.end());
            if (iter->second.empty()) {
                tokenMap_.erase(iter++);
                break;
            } else {
                iter++;
            }
        }
    }
    // disconnect to app when third-party app called unregister
    (void)HandleDisconnectAbility();
    return ERR_OK;
}

int32_t DistributedAbilityManagerService::RegisterDeviceSelectionCallback(
    int32_t token, const std::string& cbType, const sptr<IRemoteObject>& notifier)
{
    HILOGD("called");
    if (cbType != EVENT_CONNECT && cbType != EVENT_DISCONNECT) {
        HILOGE("type: %{public}s not support!", cbType.c_str());
        return UNKNOWN_CALLBACK_TYPE;
    }
    uint32_t accessToken = IPCSkeleton::GetCallingTokenID();
    if (!IsTokenRegistered(accessToken, token)) {
        return TOKEN_HAS_NOT_REGISTERED;
    }
    if (IsNotifierRegisteredLocked(token, cbType)) {
        return CALLBACK_HAS_REGISTERED;
    }
    {
        std::lock_guard<std::mutex> callbackMapLock(callbackMapMutex_);
        auto iter = callbackMap_.find(token);
        if (iter != callbackMap_.end()) { // registered at least once
            if (iter->second == nullptr) {
                return ERR_NULL_OBJECT;
            }
            iter->second->SetNotifier(cbType, notifier);
        } else { // never registered
            std::unique_ptr<NotifierInfo> notifierInfo = std::make_unique<NotifierInfo>();
            notifierInfo->SetNotifier(cbType, notifier);
            callbackMap_[token] = std::move(notifierInfo);
            notifier->AddDeathRecipient(notifierDeathRecipient_);
        }
        HILOGD("token register success");
    }
    return ERR_OK;
}

int32_t DistributedAbilityManagerService::UnregisterDeviceSelectionCallback(int32_t token, const std::string& cbType)
{
    HILOGD("called");
    if (cbType != EVENT_CONNECT && cbType != EVENT_DISCONNECT) {
        HILOGE("type: %{public}s not support!", cbType.c_str());
        return UNKNOWN_CALLBACK_TYPE;
    }
    uint32_t accessToken = IPCSkeleton::GetCallingTokenID();
    if (!IsTokenRegistered(accessToken, token)) {
        return TOKEN_HAS_NOT_REGISTERED;
    }
    if (!IsNotifierRegisteredLocked(token, cbType)) {
        return CALLBACK_HAS_NOT_REGISTERED;
    }
    {
        std::lock_guard<std::mutex> callbackMapLock(callbackMapMutex_);
        auto iter = callbackMap_.find(token);
        if (iter != callbackMap_.end()) {
            iter->second->RemoveDeathRecipient(notifierDeathRecipient_, cbType);
            iter->second->DeleteNotifier(cbType);
            if (iter->second->IsNotifierMapEmpty()) {
                callbackMap_.erase(iter);
            }
        }
    }
    HILOGD("token unregister success");
    return ERR_OK;
}

int32_t DistributedAbilityManagerService::UpdateConnectStatus(int32_t token, const std::string& deviceId,
    const DeviceConnectStatus& deviceConnectStatus)
{
    HILOGD("called");
    if (deviceId.empty()) {
        HILOGE("deviceId is empty");
        return ERR_NULL_OBJECT;
    }
    if (!IsConnectStatusValid(deviceConnectStatus)) {
        return INVALID_CONNECT_STATUS;
    }
    uint32_t accessToken = IPCSkeleton::GetCallingTokenID();
    if (!IsTokenRegistered(accessToken, token)) {
        return TOKEN_HAS_NOT_REGISTERED;
    }
    {
        std::lock_guard<std::mutex> callbackMapLock(callbackMapMutex_);
        if (!IsNotifierRegistered(token)) {
            return CALLBACK_HAS_NOT_REGISTERED;
        }
        std::shared_ptr<ConnectStatusInfo> connectStatusInfo =
            std::make_shared<ConnectStatusInfo>(deviceId, deviceConnectStatus);
        callbackMap_[token]->SetConnectStatusInfo(connectStatusInfo);
    }
    // sendRequest status(token, connectStatusInfo) to app by app proxy when appProxy_ is not null.
    {
        std::lock_guard<std::mutex> appProxyLock(appProxyMutex_);
        if (appProxy_ != nullptr) {
            HandleUpdateConnectStatus(token, deviceId, deviceConnectStatus);
        }
    }
    return ERR_OK;
}

int32_t DistributedAbilityManagerService::StartDeviceManager(
    int32_t token, const std::shared_ptr<ContinuationExtraParams>& continuationExtraParams)
{
    HILOGD("called");
    if (continuationExtraParams != nullptr) {
        ContinuationMode continuationMode = continuationExtraParams->GetContinuationMode();
        if (!IsContinuationModeValid(continuationMode)) {
            return INVALID_CONTINUATION_MODE;
        }
    }
    uint32_t accessToken = IPCSkeleton::GetCallingTokenID();
    if (!IsTokenRegistered(accessToken, token)) {
        return TOKEN_HAS_NOT_REGISTERED;
    }
    {
        std::lock_guard<std::mutex> callbackMapLock(callbackMapMutex_);
        if (!IsNotifierRegistered(token)) {
            return CALLBACK_HAS_NOT_REGISTERED;
        }
    }
    // 1. connect to app and get the app proxy if appProxy_ is null, otherwise start device manager directly.
    {
        std::lock_guard<std::mutex> appProxyLock(appProxyMutex_);
        if (appProxy_ != nullptr) {
            HandleStartDeviceManager(token, continuationExtraParams);
            return ERR_OK;
        }
    }
    int32_t errCode = ConnectAbility(token, continuationExtraParams);
    if (errCode != ERR_OK) {
        HILOGE("token connect to app failed");
        return CONNECT_ABILITY_FAILED;
    }
    // 2. sendRequest data(token, filter, dmsStub, connectStatusInfo) to app by app proxy when connect callback.
    return ERR_OK;
}

int32_t DistributedAbilityManagerService::ConnectAbility(int32_t token,
    const std::shared_ptr<ContinuationExtraParams>& continuationExtraParams)
{
    AAFwk::Want want;
    want.SetAction(DMS_HIPLAY_ACTION);
    int32_t activeAccountId = -1;
#ifdef OS_ACCOUNT_PART
    std::vector<int32_t> ids;
    int32_t ret = AccountSA::OsAccountManager::QueryActiveOsAccountIds(ids);
    if (ret != ERR_OK || ids.empty()) {
        return INVALID_PARAMETERS_ERR;
    }
    activeAccountId = ids[0];
#endif
    AppExecFwk::ExtensionAbilityInfo extensionInfo;
    if (!QueryExtensionAbilityInfo(activeAccountId, want, extensionInfo)) {
        HILOGE("QueryExtensionAbilityInfo failed");
        return CONNECT_ABILITY_FAILED;
    }
    if (connect_ == nullptr) {
        connect_ = new AppConnectionStub(token, continuationExtraParams);
    }
    int32_t errCode = AAFwk::AbilityManagerClient::GetInstance()->Connect();
    if (errCode != ERR_OK) {
        HILOGE("connect ability manager server failed, errCode=%{public}d", errCode);
        return errCode;
    }
    errCode = AAFwk::AbilityManagerClient::GetInstance()->ConnectAbility(want,
        iface_cast<AAFwk::IAbilityConnection>(connect_), this, activeAccountId);
    if (errCode != ERR_OK) {
        HILOGE("ConnectAbility failed");
        connect_ = nullptr;
        return CONNECT_ABILITY_FAILED;
    }
    return ERR_OK;
}

bool DistributedAbilityManagerService::QueryExtensionAbilityInfo(const int32_t& activeAccountId,
    const AAFwk::Want& want, AppExecFwk::ExtensionAbilityInfo& extensionInfo)
{
    auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgrProxy == nullptr) {
        HILOGE("get samgr failed");
        return false;
    }
    sptr<IRemoteObject> bmsProxy = samgrProxy->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (bmsProxy == nullptr) {
        HILOGE("get bms from samgr failed");
        return false;
    }
    auto bundleMgr = iface_cast<AppExecFwk::IBundleMgr>(bmsProxy);
    if (bundleMgr == nullptr) {
        HILOGE("bms iface_cast failed");
        return false;
    }
    std::vector<AppExecFwk::ExtensionAbilityInfo> extensionInfos;
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    bundleMgr->QueryExtensionAbilityInfos(want, AppExecFwk::AbilityInfoFlag::GET_ABILITY_INFO_DEFAULT
        | AppExecFwk::AbilityInfoFlag::GET_ABILITY_INFO_WITH_PERMISSION, activeAccountId, extensionInfos);
    IPCSkeleton::SetCallingIdentity(identity);
    if (extensionInfos.empty()) {
        HILOGE("QueryExtensionAbilityInfo failed");
        return false;
    }
    extensionInfo = extensionInfos.front();
    if (extensionInfo.bundleName.empty() || extensionInfo.name.empty()) {
        HILOGE("ExtensionAbilityInfo is empty.");
        return false;
    }
    HILOGD("ExtensionAbilityInfo found, name=%{public}s.", extensionInfo.name.c_str());
    return true;
}

int32_t DistributedAbilityManagerService::DisconnectAbility()
{
    if (connect_ == nullptr) {
        return ERR_NULL_OBJECT;
    }
    int32_t errCode = AAFwk::AbilityManagerClient::GetInstance()->Connect();
    if (errCode != ERR_OK) {
        HILOGE("connect ability manager server failed, errCode=%{public}d", errCode);
        return errCode;
    }
    errCode = AAFwk::AbilityManagerClient::GetInstance()->DisconnectAbility(
        iface_cast<AAFwk::IAbilityConnection>(connect_));
    connect_ = nullptr;
    if (errCode != ERR_OK) {
        HILOGE("DisconnectAbility failed");
        return DISCONNECT_ABILITY_FAILED;
    }
    return ERR_OK;
}

int32_t DistributedAbilityManagerService::OnDeviceConnect(int32_t token,
    const std::vector<ContinuationResult>& continuationResults)
{
    // device connect callback to napi
    if (!HandleDisconnectAbility()) {
        return DISCONNECT_ABILITY_FAILED;
    }
    if (!IsNotifierRegisteredLocked(token, EVENT_CONNECT)) {
        return CALLBACK_HAS_NOT_REGISTERED;
    }
    {
        std::lock_guard<std::mutex> callbackMapLock(callbackMapMutex_);
        auto notifier = callbackMap_[token]->GetNotifier(EVENT_CONNECT);
        if (!HandleDeviceConnect(notifier, continuationResults)) {
            return INVALID_PARAMETERS_ERR;
        }
    }
    return ERR_OK;
}

int32_t DistributedAbilityManagerService::OnDeviceDisconnect(int32_t token,
    const std::vector<ContinuationResult>& continuationResults)
{
    // device disconnect callback to napi
    if (!HandleDisconnectAbility()) {
        return DISCONNECT_ABILITY_FAILED;
    }
    if (!IsNotifierRegisteredLocked(token, EVENT_DISCONNECT)) {
        return CALLBACK_HAS_NOT_REGISTERED;
    }
    {
        std::lock_guard<std::mutex> callbackMapLock(callbackMapMutex_);
        auto notifier = callbackMap_[token]->GetNotifier(EVENT_DISCONNECT);
        if (!HandleDeviceDisconnect(notifier, continuationResults)) {
            return INVALID_PARAMETERS_ERR;
        }
    }
    return ERR_OK;
}

int32_t DistributedAbilityManagerService::OnDeviceCancel()
{
    // disconnect to app when app close the window.
    if (!HandleDisconnectAbility()) {
        return DISCONNECT_ABILITY_FAILED;
    }
    return ERR_OK;
}

bool DistributedAbilityManagerService::HandleDisconnectAbility()
{
    if (continuationHandler_ == nullptr) {
        HILOGE("continuationHandler is null.");
        return false;
    }
    auto func = [this]() {
        HILOGD("HandleDisconnectAbility called.");
        int32_t errCode = DisconnectAbility();
        if (errCode != ERR_OK) {
            HILOGE("DisconnectAbility errCode: %{public}d.", errCode);
            return;
        }
    };
    continuationHandler_->submit(func);
    return true;
}

bool DistributedAbilityManagerService::IsExceededRegisterMaxNum(uint32_t accessToken)
{
    std::lock_guard<std::mutex> tokenMapLock(tokenMapMutex_);
    auto iter = tokenMap_.find(accessToken);
    if (iter != tokenMap_.end() && iter->second.size() >= MAX_REGISTER_NUM) {
        HILOGE("accessToken registered too much times");
        return true;
    }
    return false;
}

bool DistributedAbilityManagerService::IsContinuationModeValid(ContinuationMode continuationMode)
{
    if (static_cast<int32_t>(continuationMode) < static_cast<int32_t>(ContinuationMode::COLLABORATION_SINGLE) ||
        static_cast<int32_t>(continuationMode) > static_cast<int32_t>(ContinuationMode::COLLABORATION_MUTIPLE)) {
        HILOGE("continuationMode is invalid");
        return false;
    }
    return true;
}

bool DistributedAbilityManagerService::IsConnectStatusValid(DeviceConnectStatus deviceConnectStatus)
{
    if (static_cast<int32_t>(deviceConnectStatus) < static_cast<int32_t>(DeviceConnectStatus::IDLE) ||
        static_cast<int32_t>(deviceConnectStatus) > static_cast<int32_t>(DeviceConnectStatus::DISCONNECTING)) {
        HILOGE("deviceConnectStatus is invalid");
        return false;
    }
    return true;
}

bool DistributedAbilityManagerService::IsTokenRegistered(uint32_t accessToken, int32_t token)
{
    std::lock_guard<std::mutex> tokenMapLock(tokenMapMutex_);
    auto iter = tokenMap_.find(accessToken);
    if (iter == tokenMap_.end()) {
        HILOGE("accessToken %{public}u has not registered", accessToken);
        return false;
    }
    for (auto it = iter->second.begin(); it != iter->second.end(); it++) {
        if (*it == token) {
            return true;
        }
    }
    HILOGE("token has not registered");
    return false;
}

bool DistributedAbilityManagerService::IsNotifierRegistered(int32_t token)
{
    // must be in callbackMapLock scope
    auto iter = callbackMap_.find(token);
    if (iter == callbackMap_.end()) {
        HILOGE("never registered, token: %{public}d ", token);
        return false;
    }
    if (iter->second == nullptr) {
        HILOGE("notifierInfo is nullptr");
        return false;
    }
    return true;
}

bool DistributedAbilityManagerService::IsNotifierRegisteredLocked(int32_t token, const std::string& cbType)
{
    std::lock_guard<std::mutex> callbackMapLock(callbackMapMutex_);
    if (!IsNotifierRegistered(token)) {
        return false;
    }
    if (callbackMap_[token]->GetNotifier(cbType) != nullptr) {
        HILOGD("token and cbType:%{public}s has already registered", cbType.c_str());
        return true;
    }
    HILOGE("token and cbType:%{public}s has not registered", cbType.c_str());
    return false;
}

bool DistributedAbilityManagerService::HandleDeviceConnect(const sptr<IRemoteObject>& notifier,
    const std::vector<ContinuationResult>& continuationResults)
{
    if (continuationHandler_ == nullptr) {
        HILOGE("continuationHandler_ is nullptr");
        return false;
    }
    if (notifier == nullptr) {
        HILOGE("notifier is nullptr");
        return false;
    }
    auto func = [notifier, continuationResults]() {
        HILOGD("HandleDeviceConnect called.");
        auto proxy = std::make_unique<DeviceSelectionNotifierProxy>(notifier);
        proxy->OnDeviceConnect(continuationResults);
    };
    continuationHandler_->submit(func);
    return true;
}

bool DistributedAbilityManagerService::HandleDeviceDisconnect(const sptr<IRemoteObject>& notifier,
    const std::vector<ContinuationResult>& continuationResults)
{
    if (continuationHandler_ == nullptr) {
        HILOGE("continuationHandler_ is nullptr");
        return false;
    }
    if (notifier == nullptr) {
        HILOGE("notifier is nullptr");
        return false;
    }
    auto func = [notifier, continuationResults]() {
        HILOGD("HandleDeviceDisconnect called.");
        auto proxy = std::make_unique<DeviceSelectionNotifierProxy>(notifier);
        proxy->OnDeviceDisconnect(continuationResults);
    };
    continuationHandler_->submit(func);
    return true;
}

void DistributedAbilityManagerService::ScheduleStartDeviceManager(const sptr<IRemoteObject>& appProxy, int32_t token,
    const std::shared_ptr<ContinuationExtraParams>& continuationExtraParams)
{
    std::lock_guard<std::mutex> appProxyLock(appProxyMutex_);
    appProxy_ = appProxy;
    if (appProxy_ == nullptr) {
        return;
    }
    HandleStartDeviceManager(token, continuationExtraParams);
}

void DistributedAbilityManagerService::HandleStartDeviceManager(int32_t token,
    const std::shared_ptr<ContinuationExtraParams>& continuationExtraParams)
{
    if (continuationHandler_ == nullptr) {
        HILOGE("continuationHandler_ is nullptr");
        return;
    }
    auto func = [this, token, continuationExtraParams, appProxy = appProxy_]() {
        HILOGD("HandleStartDeviceManager called.");
        MessageParcel data;
        if (!data.WriteInterfaceToken(HIPLAY_PANEL_INTERFACE_TOKEN)) {
            HILOGE("WriteInterfaceToken failed");
            return;
        }
        PARCEL_WRITE_HELPER_NORET(data, Int32, token);
        if (continuationExtraParams == nullptr) {
            PARCEL_WRITE_HELPER_NORET(data, Int32, VALUE_NULL);
        } else {
            PARCEL_WRITE_HELPER_NORET(data, Int32, VALUE_OBJECT);
            PARCEL_WRITE_HELPER_NORET(data, Parcelable, continuationExtraParams.get());
        }
        sptr<AppDeviceCallbackStub> callback(new AppDeviceCallbackStub());
        PARCEL_WRITE_HELPER_NORET(data, RemoteObject, callback);
        // query whether the connect status needs to be send
        {
            std::lock_guard<std::mutex> callbackMapLock(callbackMapMutex_);
            if (IsNotifierRegistered(token)) {
                std::shared_ptr<ConnectStatusInfo> connectStatusInfo = callbackMap_[token]->GetConnectStatusInfo();
                if (connectStatusInfo == nullptr) {
                    PARCEL_WRITE_HELPER_NORET(data, Int32, VALUE_NULL);
                } else {
                    PARCEL_WRITE_HELPER_NORET(data, Int32, VALUE_OBJECT);
                    // use u16string, because send to app
                    PARCEL_WRITE_HELPER_NORET(data, String16, Str8ToStr16(connectStatusInfo->GetDeviceId()));
                    PARCEL_WRITE_HELPER_NORET(data, Int32,
                        static_cast<int32_t>(connectStatusInfo->GetDeviceConnectStatus()));
                }
            } else {
                PARCEL_WRITE_HELPER_NORET(data, Int32, VALUE_NULL);
            }
        }
        MessageParcel reply;
        MessageOption option;
        if (appProxy == nullptr) {
            HILOGE("appProxy is nullptr");
            return;
        }
        int32_t result = appProxy->SendRequest(START_DEVICE_MANAGER_CODE, data, reply, option);
        HILOGD("result is %{public}d", result);
    };
    continuationHandler_->submit(func);
}

void DistributedAbilityManagerService::HandleUpdateConnectStatus(int32_t token, std::string deviceId,
    const DeviceConnectStatus& deviceConnectStatus)
{
    if (continuationHandler_ == nullptr) {
        HILOGE("continuationHandler_ is nullptr");
        return;
    }
    auto func = [this, token, deviceId, deviceConnectStatus, appProxy = appProxy_]() {
        HILOGD("HandleUpdateConnectStatus called.");
        MessageParcel data;
        if (!data.WriteInterfaceToken(HIPLAY_PANEL_INTERFACE_TOKEN)) {
            HILOGE("WriteInterfaceToken failed");
            return;
        }
        PARCEL_WRITE_HELPER_NORET(data, Int32, token);
        // use u16string, because send to app
        PARCEL_WRITE_HELPER_NORET(data, String16, Str8ToStr16(deviceId));
        PARCEL_WRITE_HELPER_NORET(data, Int32, static_cast<int32_t>(deviceConnectStatus));
        MessageParcel reply;
        MessageOption option;
        int32_t result = appProxy->SendRequest(UPDATE_CONNECT_STATUS_CODE, data, reply, option);
        HILOGD("result is %{public}d", result);
    };
    continuationHandler_->submit(func);
}

bool DistributedAbilityManagerService::QueryTokenByNotifier(const sptr<IRemoteObject>& notifier, int32_t& token)
{
    std::lock_guard<std::mutex> callbackMapLock(callbackMapMutex_);
    for (auto iter = callbackMap_.begin(); iter != callbackMap_.end(); iter++) {
        if (iter->second == nullptr) {
            return false;
        }
        if (iter->second->QueryNotifier(notifier)) {
            token = iter->first;
            return true;
        }
    }
    return false;
}

void DistributedAbilityManagerService::ProcessNotifierDied(const sptr<IRemoteObject>& notifier)
{
    // update cache when third-party app died
    if (notifier == nullptr) {
        return;
    }
    HandleNotifierDied(notifier);
}

void DistributedAbilityManagerService::HandleNotifierDied(const sptr<IRemoteObject>& notifier)
{
    if (continuationHandler_ == nullptr) {
        HILOGE("continuationHandler_ is nullptr");
        return;
    }
    auto func = [this, notifier] () {
        HILOGD("HandleNotifierDied called.");
        // query token in callbackMap_ by notifier
        int32_t token = -1;
        if (!QueryTokenByNotifier(notifier, token)) {
            HILOGE("QueryTokenByNotifier failed");
            return;
        }
        // remove death recipient and update callbackMap_ by token
        {
            std::lock_guard<std::mutex> callbackMapLock(callbackMapMutex_);
            if (IsNotifierRegistered(token)) {
                callbackMap_[token]->RemoveDeathRecipient(notifierDeathRecipient_);
                callbackMap_.erase(token);
            }
        }
        // update tokenMap_ by token
        {
            std::lock_guard<std::mutex> tokenMapLock(tokenMapMutex_);
            for (auto iter = tokenMap_.begin(); iter != tokenMap_.end();) {
                iter->second.erase(std::remove_if(iter->second.begin(), iter->second.end(),
                    [token](int32_t n) { return n == token; }), iter->second.end());
                if (iter->second.empty()) {
                    tokenMap_.erase(iter++);
                    break;
                } else {
                    iter++;
                }
            }
        }
        // disconnect to app when third-party app died
        (void)HandleDisconnectAbility();
    };
    continuationHandler_->submit(func);
}
} // namespace DistributedSchedule
} // namespace OHOS