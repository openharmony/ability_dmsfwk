/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "remote_intent_manager.h"

#include <algorithm>
#include <vector>
#include "distributed_intent_error_code.h"
#include "ability_manager_client.h"
#include "dtbschedmgr_device_info_storage.h"
#include "dtbschedmgr_log.h"
#include "distributed_sched_utils.h"
#include "distributed_sched_permission.h"
#include "nlohmann/json.hpp"
#include "distributed_want_v2.h"
#include "parcel.h"
#include "iremote_object.h"
#include "single_instance.h"
#include "distributed_intent_dsoftbus_adapter.h"
#include "distributed_sched_types.h"
#ifdef SUPPORT_DISTRIBUTED_MISSION_MANAGER
#include "mission/dsched_sync_e2e.h"
#include "distributed_sched_service.h"
#endif
#include "intent_permission_checker.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "RemoteIntentManager";
const std::u16string INTENT_RESULT_CALLBACK_TOKEN = u"ohos.distributedschedule.IRemoteIntentResultCallback";
constexpr int32_t ON_INTENT_RESULT = 1;
constexpr int32_t ON_LINK_DISCONNECTED = 2;
constexpr size_t INTENT_DATA_MAX_SIZE = 100 * 1024 * 1024;
constexpr int64_t CALLBACK_TIMEOUT_MS = 30000;
const std::string MODULE_NAME_PARAM = "moduleName";
const std::string INSIGHT_INTENT_USER_ID = "ohos.insightIntent.userId";
}

IMPLEMENT_SINGLE_INSTANCE(RemoteIntentManager);

RemoteIntentManager::RemoteIntentManager()
{
    HILOGI("RemoteIntentManager construct");
}

RemoteIntentManager::~RemoteIntentManager()
{
    HILOGI("RemoteIntentManager destruct");
}

int32_t RemoteIntentManager::PrepareCallerContext(const std::string& localDeviceId,
    const std::string& dstDeviceId, const IntentCallerInfo& intentCallerInfo,
    CallerInfo& callerInfo, IDistributedSched::AccountInfo& accountInfo)
{
    auto& checker = IntentPermissionChecker::GetInstance();
    checker.SetCallerExtraInfo(callerInfo, intentCallerInfo);
    int32_t ret = checker.GetCallerInfo(localDeviceId,
        intentCallerInfo.callerUid, intentCallerInfo.accessToken, callerInfo);
    if (ret != ERR_DI_OK) {
        HILOGE("GetCallerInfo failed, ret=%{public}d", ret);
        return ERR_DI_SYSTEM_WORK_ABNORMALLY;
    }
#ifdef SUPPORT_DISTRIBUTED_MISSION_MANAGER
    CHECK_MDM_CONTROL_BY_TOKEN(callerInfo.accessToken, 0, COLLABORATION_SERVICE);
#endif
    ret = checker.GetAccountInfo(dstDeviceId, callerInfo, accountInfo);
    if (ret != ERR_DI_OK) {
        HILOGE("GetAccountInfo failed, ret=%{public}d", ret);
        return ERR_DI_SYSTEM_WORK_ABNORMALLY;
    }
    return ERR_DI_OK;
}

int32_t RemoteIntentManager::SendIntentToRemote(const std::string& dstDeviceId,
    const OHOS::AAFwk::Want& want, const IntentContext& ctx, int32_t& socketFd)
{
    std::string data;
    int32_t ret = SerializeIntentData(want, ctx, data);
    if (ret != ERR_DI_OK) {
        HILOGE("SerializeIntentData failed, ret=%{public}d", ret);
        return ERR_DI_SERIALIZE_FAILED;
    }
    socketFd = -1;
    ret = DistributedIntentDsoftbusAdapter::GetInstance().BindIntentSession(dstDeviceId, socketFd);
    if (ret != ERR_DI_OK) {
        HILOGE("BindIntentSession failed, ret=%{public}d", ret);
        return ret;
    }
    ret = DistributedIntentDsoftbusAdapter::GetInstance().SendIntentDataBySession(
        socketFd, IntentDataType::INTENT_DATA_TYPE_EXECUTE, data);
    if (ret != ERR_DI_OK) {
        HILOGE("SendIntentDataBySession failed, ret=%{public}d", ret);
        return ret;
    }
    return ERR_DI_OK;
}

void RemoteIntentManager::RegisterResultCallback(uint64_t requestCode,
    const std::string& deviceId, const sptr<IRemoteObject>& callback)
{
    if (callback == nullptr) {
        return;
    }
    CleanupExpiredCallbacks();
    std::lock_guard<std::mutex> lock(connectMutex_);
    CallbackEntry entry;
    entry.callback = callback;
    entry.timestamp = std::chrono::steady_clock::now();
    entry.deviceId = deviceId;
    requestCodeCallbackMap_[requestCode] = entry;
}

int32_t RemoteIntentManager::StartRemoteIntent(const OHOS::AAFwk::Want& want,
    const IntentCallerInfo& intentCallerInfo, const sptr<IRemoteObject>& resultCallback)
{
    HILOGI("StartRemoteIntent start");
    std::string dstDeviceId = want.GetElement().GetDeviceID();
    if (dstDeviceId.empty()) {
        HILOGE("dstDeviceId is empty");
        return ERR_DI_INVALID_PARAMETER;
    }
    std::string localDeviceId;
    if (!DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(localDeviceId)) {
        HILOGE("GetLocalDeviceId failed");
        return ERR_DI_SYSTEM_WORK_ABNORMALLY;
    }
    if (localDeviceId.empty() || localDeviceId == dstDeviceId) {
        HILOGE("Invalid deviceId, local same as dst or local empty");
        return ERR_DI_INVALID_PARAMETER;
    }
    CallerInfo callerInfo;
    IDistributedSched::AccountInfo accountInfo;
    int32_t ret = PrepareCallerContext(localDeviceId, dstDeviceId,
        intentCallerInfo, callerInfo, accountInfo);
    if (ret != ERR_DI_OK) {
        return ret;
    }
    ret = IntentPermissionChecker::GetInstance().CheckCallerPermission(want, intentCallerInfo.accessToken);
    if (ret != ERR_DI_OK) {
        return ret;
    }
    IntentContext ctx;
    ctx.callerInfo = callerInfo;
    ctx.requestCode = intentCallerInfo.requestCode;
    ctx.accountInfo = accountInfo;
    int32_t socketFd = -1;
    ret = SendIntentToRemote(dstDeviceId, want, ctx, socketFd);
    if (ret != ERR_DI_OK) {
        return ret;
    }
    RegisterResultCallback(intentCallerInfo.requestCode, dstDeviceId, resultCallback);
    HILOGI("StartRemoteIntent success, socketFd=%{public}d, requestCode=%{public}" PRIu64,
        socketFd, intentCallerInfo.requestCode);
    return ERR_DI_OK;
}

int32_t RemoteIntentManager::SerializeIntentData(const OHOS::AAFwk::Want& want,
    const IntentContext& ctx, std::string& data, const std::string& resultMsg)
{
    DistributedWantV2 distributedWant(want);
    OHOS::Parcel parcel;
    if (!distributedWant.Marshalling(parcel)) {
        HILOGE("DistributedWant Marshalling failed");
        return ERR_DI_SERIALIZE_FAILED;
    }
    nlohmann::json root;
    root["wantData"] = ParcelToBase64Str(parcel);
    root["requestCode"] = ctx.requestCode;
    root["uid"] = ctx.callerInfo.uid;
    root["pid"] = ctx.callerInfo.pid;
    root["callerType"] = ctx.callerInfo.callerType;
    root["sourceDeviceId"] = ctx.callerInfo.sourceDeviceId;
    root["duid"] = ctx.callerInfo.duid;
    root["callerAppId"] = ctx.callerInfo.callerAppId;
    root["bundleNames"] = ctx.callerInfo.bundleNames;
    root["dmsVersion"] = ctx.callerInfo.dmsVersion;
    root["accessToken"] = ctx.callerInfo.accessToken;
    root["extraInfoJson"] = ctx.callerInfo.extraInfoJson;
    root["accountUserId"] = ctx.accountInfo.userId;
    root["accountActiveAccountId"] = ctx.accountInfo.activeAccountId;
    if (!resultMsg.empty()) {
        root["resultMsg"] = resultMsg;
    }
    data = root.dump();
    HILOGI("SerializeIntentData success, size=%{public}zu, requestCode=%{public}" PRIu64,
        data.size(), ctx.requestCode);
    return ERR_DI_OK;
}

int32_t RemoteIntentManager::DecodeWantFromJson(const nlohmann::json& root,
    OHOS::AAFwk::Want& want)
{
    if (!root.contains("wantData") || !root["wantData"].is_string()) {
        HILOGE("wantData not found or not string in json");
        return ERR_DI_INVALID_PARAMETER;
    }
    std::string wantData = root["wantData"].get<std::string>();
    if (wantData.empty()) {
        HILOGE("wantData is empty");
        return ERR_DI_INVALID_PARAMETER;
    }
    std::string decodedData = Base64Decode(wantData);
    if (decodedData.empty()) {
        HILOGE("Base64StrToParcel failed");
        return ERR_DI_INVALID_PARAMETER;
    }
    if (decodedData.size() > INTENT_DATA_MAX_SIZE) {
        HILOGE("wantData too large, size=%{public}zu", wantData.size());
        return ERR_DI_INVALID_PARAMETER;
    }
    OHOS::Parcel parcel;
    parcel.WriteBuffer(decodedData.data(), decodedData.size());
    DistributedWantV2* distributedWant = DistributedWantV2::Unmarshalling(parcel);
    if (distributedWant == nullptr) {
        HILOGE("distributed want Unmarshalling failed");
        return ERR_DI_INVALID_PARAMETER;
    }
    auto aafwkWant = distributedWant->ToWant();
    delete distributedWant;
    distributedWant = nullptr;
    if (aafwkWant == nullptr) {
        HILOGE("ToWant failed");
        return ERR_DI_INVALID_PARAMETER;
    }
    std::string srcModuldeName = aafwkWant->GetStringParam(MODULE_NAME_PARAM);
    if (!srcModuldeName.empty()) {
        aafwkWant->SetModuleName(srcModuldeName);
    }
    want = *aafwkWant;
    return ERR_DI_OK;
}

int32_t RemoteIntentManager::ParseCallerInfoFromJson(const nlohmann::json& root,
    CallerInfo& callerInfo)
{
    callerInfo.uid = root.value("uid", -1);
    callerInfo.pid = root.value("pid", -1);
    callerInfo.callerType = root.value("callerType", 0);
    callerInfo.sourceDeviceId = root.value("sourceDeviceId", "");
    callerInfo.duid = root.value("duid", -1);
    callerInfo.callerAppId = root.value("callerAppId", "");
    if (root.contains("bundleNames") && root["bundleNames"].is_array()) {
        root["bundleNames"].get_to<std::vector<std::string>>(callerInfo.bundleNames);
    }
    callerInfo.dmsVersion = root.value("dmsVersion", -1);
    callerInfo.accessToken = root.value("accessToken", 0u);
    if (root.contains("extraInfoJson") && root["extraInfoJson"].is_object()) {
        callerInfo.extraInfoJson = root["extraInfoJson"];
    }
    return ERR_DI_OK;
}

int32_t RemoteIntentManager::ValidateCallerInfo(const CallerInfo& callerInfo)
{
    if (callerInfo.accessToken == 0) {
        HILOGE("Invalid accessToken: zero");
        return ERR_DI_PERMISSION_DENIED;
    }
    if (callerInfo.sourceDeviceId.empty()) {
        HILOGE("srcDeviceId is empty in payload");
        return ERR_DI_PERMISSION_DENIED;
    }
    return ERR_DI_OK;
}

void RemoteIntentManager::ParseAccountInfoFromJson(const nlohmann::json& root,
    IDistributedSched::AccountInfo& accountInfo)
{
    accountInfo.userId = root.value("accountUserId", -1);
    accountInfo.activeAccountId = root.value("accountActiveAccountId", "");
}

int32_t RemoteIntentManager::DeserializeIntentData(const std::string& data,
    OHOS::AAFwk::Want& want, IntentContext& ctx, std::string& resultMsg)
{
    nlohmann::json root = nlohmann::json::parse(data, nullptr, false);
    if (!root.is_object()) {
        HILOGE("Invalid json data");
        return ERR_DI_INVALID_PARAMETER;
    }
    if (!root.contains("requestCode") || !root["requestCode"].is_number()) {
        HILOGE("requestCode not found or not number in json");
        return ERR_DI_INVALID_PARAMETER;
    }
    ctx.requestCode = root.value("requestCode", (uint64_t)0);
    int32_t ret = DecodeWantFromJson(root, want);
    if (ret != ERR_DI_OK) {
        HILOGE("DecodeWantFromJson failed, ret=%{public}d", ret);
        return ret;
    }
    ret = ParseCallerInfoFromJson(root, ctx.callerInfo);
    if (ret != ERR_DI_OK) {
        HILOGE("ParseCallerInfoFromJson failed, ret=%{public}d", ret);
        return ret;
    }
    ret = ValidateCallerInfo(ctx.callerInfo);
    if (ret != ERR_DI_OK) {
        HILOGE("ValidateCallerInfo failed, ret=%{public}d", ret);
        return ret;
    }
    ParseAccountInfoFromJson(root, ctx.accountInfo);
    if (root.contains("resultMsg") && root["resultMsg"].is_string()) {
        resultMsg = root.value("resultMsg", "");
    }
    HILOGI("DeserializeIntentData success");
    return ERR_DI_OK;
}

int32_t RemoteIntentManager::SerializeResultData(int32_t resultCode,
    const std::string& resultMsg, uint64_t requestCode, std::string& data)
{
    HILOGI("SerializeResultData start, requestCode=%{public}" PRIu64, requestCode);
    nlohmann::json root;
    root["requestCode"] = requestCode;
    root["result"] = resultCode;
    root["resultMsg"] = resultMsg;
    data = root.dump();
    HILOGI("SerializeResultData success, size=%{public}zu", data.size());
    return ERR_DI_OK;
}

void RemoteIntentManager::OnIntentDataReceived(const std::string& srcDeviceId,
    IntentDataType dataType, const std::string& data, int32_t socketFd)
{
    HILOGI("OnIntentDataReceived: srcDeviceId=%{public}s, dataType=%{public}d, socket=%{public}d",
        GetAnonymStr(srcDeviceId).c_str(), static_cast<int32_t>(dataType), socketFd);
    switch (dataType) {
        case IntentDataType::INTENT_DATA_TYPE_EXECUTE:
            HandleIntentExecute(srcDeviceId, data, socketFd);
            break;
        case IntentDataType::INTENT_DATA_TYPE_AMGR_RESULT:
        case IntentDataType::INTENT_DATA_TYPE_DMS_RESULT:
            HandleIntentResult(srcDeviceId, data, socketFd);
            break;
        case IntentDataType::INTENT_DATA_TYPE_EXECUTE_RESULT:
            HandleBusinessResult(srcDeviceId, data, socketFd);
            break;
        default:
            HILOGE("Unknown dataType=%{public}d", static_cast<int32_t>(dataType));
            break;
    }
}

int32_t RemoteIntentManager::ValidateExecuteRequest(const std::string& srcDeviceId,
    const AAFwk::Want& want, const IntentContext& ctx, const std::string& localDeviceId)
{
    if (srcDeviceId != ctx.callerInfo.sourceDeviceId) {
        HILOGE("Device ID mismatch: session=%{public}s, payload=%{public}s",
            GetAnonymStr(srcDeviceId).c_str(), GetAnonymStr(ctx.callerInfo.sourceDeviceId).c_str());
        return ERR_DI_PERMISSION_DENIED;
    }
    std::string targetDeviceId = want.GetElement().GetDeviceID();
    if (targetDeviceId.empty() || targetDeviceId != localDeviceId) {
        HILOGE("Target device is not local device");
        return ERR_DI_PERMISSION_DENIED;
    }
    return ERR_DI_OK;
}

int32_t RemoteIntentManager::DoExecuteIntent(AAFwk::Want& want,
    const std::string& srcDeviceId, const IntentContext& ctx, uint64_t dAccessToken)
{
    want.SetParam(INSIGHT_INTENT_USER_ID, ctx.accountInfo.userId);
    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->ExecuteIntentForDistributed(
        want, srcDeviceId, ctx.requestCode, dAccessToken);
    if (err != ERR_OK) {
        HILOGE("ExecuteIntent failed, err=%{public}d", err);
        return ERR_DI_EXECUTE_FAILED;
    }
    return ERR_DI_OK;
}

int32_t RemoteIntentManager::HandleIntentExecute(const std::string& srcDeviceId,
    const std::string& data, int32_t socketFd)
{
    HILOGI("HandleIntentExecute: srcDeviceId=%{public}s, socket=%{public}d",
        GetAnonymStr(srcDeviceId).c_str(), socketFd);
    AAFwk::Want want;
    IntentContext ctx;
    ctx.callerInfo.callerType = CALLER_TYPE_HARMONY;
    std::string ignoredResultMsg;
    int32_t ret = DeserializeIntentData(data, want, ctx, ignoredResultMsg);
    if (ret != ERR_DI_OK) {
        HILOGE("DeserializeIntentData failed, ret=%{public}d", ret);
        SendInnerResultBack(socketFd, ctx.requestCode, ERR_DI_SERIALIZE_FAILED,
            IntentDataType::INTENT_DATA_TYPE_DMS_RESULT);
        return ERR_DI_SERIALIZE_FAILED;
    }

    {
        std::lock_guard<std::mutex> lock(requestSocketMutex_);
        requestSocketMap_[{srcDeviceId, ctx.requestCode}] = socketFd;
        HILOGI("Record socket mapping: device=%{public}s, requestCode=%{public}" PRIu64
            ", socket=%{public}d", GetAnonymStr(srcDeviceId).c_str(), ctx.requestCode, socketFd);
    }

    std::string localDeviceId;
    if (!DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(localDeviceId)) {
        HILOGE("GetLocalDeviceId failed");
        SendInnerResultBack(socketFd, ctx.requestCode, ERR_DI_SYSTEM_WORK_ABNORMALLY,
            IntentDataType::INTENT_DATA_TYPE_DMS_RESULT);
        return ERR_DI_SYSTEM_WORK_ABNORMALLY;
    }
    ret = ValidateExecuteRequest(srcDeviceId, want, ctx, localDeviceId);
    if (ret != ERR_DI_OK) {
        HILOGE("ValidateExecuteRequest failed, ret=%{public}d", ret);
        SendInnerResultBack(socketFd, ctx.requestCode, ERR_DI_PERMISSION_DENIED,
            IntentDataType::INTENT_DATA_TYPE_DMS_RESULT);
        return ERR_DI_PERMISSION_DENIED;
    }
    ret = CheckAndExecuteIntent(want, srcDeviceId, ctx, localDeviceId, socketFd);
    if (ret != ERR_DI_OK) {
        HILOGE("CheckAndExecuteIntent failed, ret=%{public}d", ret);
        return ret;
    }
    HILOGI("HandleIntentExecute success, requestCode=%{public}" PRIu64, ctx.requestCode);
    return ERR_DI_OK;
}

int32_t RemoteIntentManager::CheckAndExecuteIntent(AAFwk::Want& want,
    const std::string& srcDeviceId, const IntentContext& ctx,
    const std::string& localDeviceId, int32_t socketFd)
{
    uint64_t dAccessToken = 0;
    int32_t ret = IntentPermissionChecker::GetInstance().CheckStartPermission(
        localDeviceId, want, ctx.callerInfo, ctx.accountInfo, dAccessToken);
    if (ret != ERR_OK) {
        HILOGE("CheckStartPermission failed, ret=%{public}d", ret);
        SendInnerResultBack(socketFd, ctx.requestCode, ERR_DI_PERMISSION_DENIED,
            IntentDataType::INTENT_DATA_TYPE_DMS_RESULT);
        return ERR_DI_PERMISSION_DENIED;
    }
    ret = DoExecuteIntent(want, srcDeviceId, ctx, dAccessToken);
    if (ret != ERR_DI_OK) {
        HILOGE("DoExecuteIntent failed, ret=%{public}d", ret);
        SendInnerResultBack(socketFd, ctx.requestCode, ret,
            IntentDataType::INTENT_DATA_TYPE_AMGR_RESULT);
        return ret;
    }
    return ERR_DI_OK;
}

int32_t RemoteIntentManager::HandleIntentResult(const std::string& srcDeviceId,
    const std::string& data, int32_t socketFd)
{
    HILOGI("HandleIntentResult: srcDeviceId=%{public}s, socket=%{public}d",
        GetAnonymStr(srcDeviceId).c_str(), socketFd);
    nlohmann::json root = nlohmann::json::parse(data, nullptr, false);
    if (!root.is_object()) {
        HILOGE("Invalid json data");
        return ERR_DI_SYSTEM_WORK_ABNORMALLY;
    }
    uint64_t requestCode = root.value("requestCode", (uint64_t)0);
    int32_t resultCode = root.value("result", 0);
    std::string resultMsg = root.value("resultMsg", "");
    sptr<IRemoteObject> callback;
    {
        std::lock_guard<std::mutex> lock(connectMutex_);
        auto it = requestCodeCallbackMap_.find(requestCode);
        if (it == requestCodeCallbackMap_.end() || it->second.callback == nullptr) {
            HILOGW("Callback not found for requestCode=%{public}" PRIu64, requestCode);
            return ERR_DI_SYSTEM_WORK_ABNORMALLY;
        }
        callback = it->second.callback;
        requestCodeCallbackMap_.erase(it);
    }
    int32_t ret = NotifyIntentResult(callback, requestCode, resultCode, resultMsg);
    HILOGI("HandleIntentResult done, ret=%{public}d", ret);
    DistributedIntentDsoftbusAdapter::GetInstance().UnbindIntentSession(socketFd);
    return ret;
}

int32_t RemoteIntentManager::HandleBusinessResult(const std::string& srcDeviceId,
    const std::string& data, int32_t socketFd)
{
    HILOGI("HandleBusinessResult: srcDeviceId=%{public}s, socket=%{public}d",
        GetAnonymStr(srcDeviceId).c_str(), socketFd);
    AAFwk::Want want;
    IntentContext ctx;
    std::string resultMsg;
    int32_t ret = DeserializeIntentData(data, want, ctx, resultMsg);
    if (ret != ERR_DI_OK) {
        HILOGE("DeserializeIntentData failed, ret=%{public}d", ret);
        return ret;
    }
    sptr<IRemoteObject> callback;
    {
        std::lock_guard<std::mutex> lock(connectMutex_);
        auto it = requestCodeCallbackMap_.find(ctx.requestCode);
        if (it == requestCodeCallbackMap_.end() || it->second.callback == nullptr) {
            HILOGW("Callback not found for requestCode=%{public}" PRIu64, ctx.requestCode);
            return ERR_DI_SYSTEM_WORK_ABNORMALLY;
        }
        if (it->second.deviceId != srcDeviceId) {
            HILOGE("Callback device mismatch: stored=%{public}s, incoming=%{public}s",
                GetAnonymStr(it->second.deviceId).c_str(), GetAnonymStr(srcDeviceId).c_str());
            return ERR_DI_PERMISSION_DENIED;
        }
        callback = it->second.callback;
        requestCodeCallbackMap_.erase(it);
    }
    ret = IntentPermissionChecker::GetInstance().CheckBusinessResultPermission(srcDeviceId, want, ctx);
    if (ret != ERR_DI_OK) {
        HILOGE("CheckBusinessResultPermission failed, ret=%{public}d", ret);
        NotifyIntentResult(callback, ctx.requestCode, ret, resultMsg);
        DistributedIntentDsoftbusAdapter::GetInstance().UnbindIntentSession(socketFd);
        return ret;
    }
    ret = NotifyIntentResult(callback, ctx.requestCode, 0, resultMsg);
    HILOGI("HandleBusinessResult done, ret=%{public}d, requestCode=%{public}" PRIu64, ret, ctx.requestCode);
    DistributedIntentDsoftbusAdapter::GetInstance().UnbindIntentSession(socketFd);
    return ret;
}

int32_t RemoteIntentManager::NotifyIntentResult(const sptr<IRemoteObject>& callback,
    uint64_t requestCode, int32_t resultCode, std::string& resultMsg)
{
    HILOGI("NotifyIntentResult: requestCode=%{public}" PRIu64 ", resultCode=%{public}d",
        requestCode, resultCode);
    if (callback == nullptr) {
        HILOGW("Callback is null");
        return ERR_DI_INVALID_PARAMETER;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(INTENT_RESULT_CALLBACK_TOKEN)) {
        HILOGE("Write interface token failed.");
        return ERR_DI_INVALID_PARAMETER;
    }
    if (!data.WriteUint64(requestCode)) {
        HILOGE("Write requestCode failed.");
        return ERR_DI_INVALID_PARAMETER;
    }
    if (!data.WriteInt32(resultCode)) {
        HILOGE("Write resultCode failed.");
        return ERR_DI_INVALID_PARAMETER;
    }
    if (!data.WriteString(resultMsg)) {
        HILOGE("Write resultMsg failed.");
        return ERR_DI_INVALID_PARAMETER;
    }
    MessageParcel reply;
    MessageOption option;
    int32_t ret = callback->SendRequest(ON_INTENT_RESULT, data, reply, option);
    if (ret != NO_ERROR) {
        HILOGE("SendRequest failed, ret=%{public}d", ret);
        return ret;
    }
    HILOGI("NotifyIntentResult success");
    return ERR_DI_OK;
}

int32_t RemoteIntentManager::SendInnerResultBack(int32_t socketFd, uint64_t requestCode,
    int32_t resultCode, IntentDataType dataType)
{
    HILOGI("SendInnerResultBack: socket=%{public}d, requestCode=%{public}" PRIu64
        ", resultCode=%{public}d", socketFd, requestCode, resultCode);
    std::string data;
    int32_t ret = SerializeResultData(resultCode, "", requestCode, data);
    if (ret != ERR_DI_OK) {
        HILOGE("SerializeResultData failed, ret=%{public}d", ret);
        return ERR_DI_SERIALIZE_FAILED;
    }
    if (socketFd < 0) {
        HILOGE("Invalid socketFd=%{public}d", socketFd);
        return ERR_DI_SOFTBUS_COMMUNICATION_FAILED;
    }
    ret = DistributedIntentDsoftbusAdapter::GetInstance().SendIntentDataBySession(socketFd, dataType, data);
    if (ret != ERR_DI_OK) {
        HILOGE("SendIntentDataBySession failed, ret=%{public}d", ret);
        return ERR_DI_SOFTBUS_COMMUNICATION_FAILED;
    }
    HILOGI("SendInnerResultBack success");
    return ERR_DI_OK;
}

void RemoteIntentManager::CleanupSocketMapping(const std::string& deviceId, int32_t socketFd)
{
    HILOGI("CleanupSocketMapping: deviceId=%{public}s, socket=%{public}d",
        GetAnonymStr(deviceId).c_str(), socketFd);
    std::lock_guard<std::mutex> lock(requestSocketMutex_);
    for (auto it = requestSocketMap_.begin(); it != requestSocketMap_.end();) {
        if (it->first.first == deviceId) {
            HILOGW("Cleanup mapping: device=%{public}s, requestCode=%{public}" PRIu64
                ", socket=%{public}d", GetAnonymStr(deviceId).c_str(), it->first.second, it->second);
            it = requestSocketMap_.erase(it);
        } else {
            ++it;
        }
    }
}

int32_t RemoteIntentManager::PrepareResultContext(const std::string& srcDeviceId,
    const std::string& localDeviceId, const IntentCallerInfo& intentCallerInfo, IntentContext& ctx)
{
    auto& checker = IntentPermissionChecker::GetInstance();
    int32_t ret = checker.GetCallerInfo(localDeviceId, intentCallerInfo.callerUid,
        intentCallerInfo.accessToken, ctx.callerInfo);
    if (ret != ERR_DI_OK) {
        HILOGE("GetCallerInfo failed, ret=%{public}d", ret);
        return ret;
    }
    checker.SetCallerExtraInfo(ctx.callerInfo, intentCallerInfo);
    ctx.requestCode = intentCallerInfo.requestCode;
    ret = checker.GetAccountInfo(srcDeviceId, ctx.callerInfo, ctx.accountInfo);
    if (ret != ERR_DI_OK) {
        HILOGE("GetAccountInfo failed, ret=%{public}d", ret);
        return ret;
    }
    return ERR_DI_OK;
}

int32_t RemoteIntentManager::SendResultToRemote(int32_t socketFd,
    const OHOS::AAFwk::Want& want, const IntentContext& ctx, const std::string& msg)
{
    std::string data;
    int32_t ret = SerializeIntentData(want, ctx, data, msg);
    if (ret != ERR_DI_OK) {
        HILOGE("SerializeIntentData failed, ret=%{public}d", ret);
        return ERR_DI_SERIALIZE_FAILED;
    }

    if (socketFd < 0) {
        HILOGE("Invalid socketFd=%{public}d", socketFd);
        return ERR_DI_SOFTBUS_COMMUNICATION_FAILED;
    }

    ret = DistributedIntentDsoftbusAdapter::GetInstance().SendIntentDataBySession(
        socketFd, IntentDataType::INTENT_DATA_TYPE_EXECUTE_RESULT, data);
    if (ret != ERR_DI_OK) {
        HILOGE("SendIntentDataBySession failed, ret=%{public}d, socket=%{public}d", ret, socketFd);
        return ERR_DI_SOFTBUS_COMMUNICATION_FAILED;
    }
    return ERR_DI_OK;
}

int32_t RemoteIntentManager::HandleSendIntentResult(const OHOS::AAFwk::Want& want,
    const IntentCallerInfo& intentCallerInfo, const std::string& msg)
{
    HILOGI("HandleSendIntentResult: requestCode=%{public}" PRIu64, intentCallerInfo.requestCode);
    std::string srcDeviceId = want.GetElement().GetDeviceID();
    
    int32_t socketFd = INVALID_SOCKET_FD;
    {
        std::lock_guard<std::mutex> lock(requestSocketMutex_);
        auto key = std::make_pair(srcDeviceId, intentCallerInfo.requestCode);
        auto it = requestSocketMap_.find(key);
        if (it == requestSocketMap_.end()) {
            HILOGW("Socket mapping not found for requestCode=%{public}" PRIu64
                ", srcDeviceId=%{public}s", intentCallerInfo.requestCode,
                GetAnonymStr(srcDeviceId).c_str());
            return ERR_DI_SYSTEM_WORK_ABNORMALLY;
        }
        socketFd = it->second;
        requestSocketMap_.erase(it);
        HILOGI("Found socket=%{public}d and cleaned mapping", socketFd);
    }

    std::string localDeviceId;
    if (!DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(localDeviceId)) {
        HILOGE("GetLocalDeviceId failed");
        return ERR_DI_SYSTEM_WORK_ABNORMALLY;
    }
    IntentContext ctx;
    int32_t ret = PrepareResultContext(srcDeviceId, localDeviceId, intentCallerInfo, ctx);
    if (ret != ERR_DI_OK) {
        HILOGE("PrepareResultContext failed, ret=%{public}d", ret);
        return ret;
    }
    ret = SendResultToRemote(socketFd, want, ctx, msg);
    if (ret != ERR_DI_OK) {
        HILOGE("SendResultToRemote failed, ret=%{public}d", ret);
        return ret;
    }
    HILOGI("HandleSendIntentResult done, requestCode=%{public}" PRIu64
        ", socket=%{public}d", intentCallerInfo.requestCode, socketFd);
    return ERR_DI_OK;
}

void RemoteIntentManager::CleanupExpiredCallbacks()
{
    auto now = std::chrono::steady_clock::now();
    std::vector<std::pair<uint64_t, std::string>> expiredEntries;
    {
        std::lock_guard<std::mutex> lock(connectMutex_);
        for (auto it = requestCodeCallbackMap_.begin(); it != requestCodeCallbackMap_.end();) {
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - it->second.timestamp).count();
            if (elapsed > CALLBACK_TIMEOUT_MS) {
                HILOGW("Callback expired, requestCode=%{public}" PRIu64 ", elapsed=%{public}lldms",
                    it->first, static_cast<long long>(elapsed));
                expiredEntries.emplace_back(it->first, it->second.deviceId);
                it = requestCodeCallbackMap_.erase(it);
            } else {
                ++it;
            }
        }
    }
    for (auto& [requestCode, deviceId] : expiredEntries) {
        int32_t socketFd = INVALID_SOCKET_FD;
        {
            std::lock_guard<std::mutex> lock(requestSocketMutex_);
            auto key = std::make_pair(deviceId, requestCode);
            auto it = requestSocketMap_.find(key);
            if (it != requestSocketMap_.end()) {
                socketFd = it->second;
                requestSocketMap_.erase(it);
            }
        }
        if (socketFd >= 0) {
            DistributedIntentDsoftbusAdapter::GetInstance().UnbindIntentSession(socketFd);
        }
    }
}

void RemoteIntentManager::NotifyLinkDisconnected(const std::string& deviceId, int32_t reason)
{
    HILOGI("NotifyLinkDisconnected: deviceId=%{public}s, reason=%{public}d",
        GetAnonymStr(deviceId).c_str(), reason);
    NotifyAllCallbacksDisconnected(deviceId, reason);
}

void RemoteIntentManager::NotifyAllCallbacksDisconnected(const std::string& deviceId, int32_t reason)
{
    std::vector<std::pair<uint64_t, sptr<IRemoteObject>>> disconnectedCallbacks;
    {
        std::lock_guard<std::mutex> lock(connectMutex_);
        for (auto it = requestCodeCallbackMap_.begin(); it != requestCodeCallbackMap_.end();) {
            if (it->second.deviceId == deviceId) {
            disconnectedCallbacks.emplace_back(it->first, it->second.callback);
            it = requestCodeCallbackMap_.erase(it);
            } else {
                ++it;
            }
        }
    }
    for (auto& [requestCode, callback] : disconnectedCallbacks) {
        if (callback != nullptr) {
            MessageParcel data;
            if (data.WriteInterfaceToken(INTENT_RESULT_CALLBACK_TOKEN)
                && data.WriteUint64(requestCode) && data.WriteInt32(reason)) {
                MessageParcel reply;
                MessageOption option;
                callback->SendRequest(ON_LINK_DISCONNECTED, data, reply, option);
            }
        }
    }
    HILOGI("NotifyAllCallbacksDisconnected done, notified=%{public}zu callbacks",
        disconnectedCallbacks.size());
}

} // namespace DistributedSchedule
} // namespace OHOS
