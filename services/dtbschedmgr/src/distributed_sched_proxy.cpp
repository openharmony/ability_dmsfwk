/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "distributed_sched_proxy.h"
#include "dfx/dms_hitrace_constants.h"
#include "distributed_want.h"
#include "dms_constant.h"
#include "dtbschedmgr_log.h"
#include "ipc_types.h"
#ifdef SUPPORT_DISTRIBUTED_MISSION_MANAGER
#include "mission/mission_info_converter.h"
#include "pixel_map.h"
#endif
#include "parcel_helper.h"
#include "string_ex.h"

namespace OHOS {
namespace DistributedSchedule {
using namespace std;
using namespace AAFwk;

namespace {
const std::string TAG = "DistributedSchedProxy";
const std::u16string DMS_PROXY_INTERFACE_TOKEN = u"ohos.distributedschedule.accessToken";
const std::string EXTRO_INFO_JSON_KEY_ACCESS_TOKEN = "accessTokenID";
const std::string EXTRO_INFO_JSON_KEY_REQUEST_CODE = "requestCode";
const std::string CMPT_PARAM_FREEINSTALL_BUNDLENAMES = "ohos.extra.param.key.allowedBundles";
const std::string DMS_VERSION_ID = "dmsVersion";
const std::string DMS_UID_SPEC_BUNDLE_NAME = "dmsCallerUidBundleName";
#ifdef SUPPORT_DISTRIBUTED_MISSION_MANAGER
constexpr int32_t WAIT_TIME = 15;
#endif
}

int32_t DistributedSchedProxy::StartRemoteAbility(const OHOS::AAFwk::Want& want,
    int32_t callerUid, int32_t requestCode, uint32_t accessToken)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        return ERR_NULL_OBJECT;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(DMS_PROXY_INTERFACE_TOKEN)) {
        return ERR_FLATTEN_OBJECT;
    }
    PARCEL_WRITE_HELPER(data, Parcelable, &want);
    PARCEL_WRITE_HELPER(data, Int32, callerUid);
    PARCEL_WRITE_HELPER(data, Int32, requestCode);
    PARCEL_WRITE_HELPER(data, Uint32, accessToken);
    MessageParcel msgReply;
    PARCEL_TRANSACT_SYNC_RET_INT(remote, static_cast<uint32_t>(IDSchedInterfaceCode::START_REMOTE_ABILITY),
        data, msgReply);
}

int32_t DistributedSchedProxy::StartAbilityFromRemote(const OHOS::AAFwk::Want& want,
    const OHOS::AppExecFwk::AbilityInfo& abilityInfo, int32_t requestCode,
    const CallerInfo& callerInfo, const AccountInfo& accountInfo)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        HILOGE("StartAbilityFromRemote remote service null");
        return ERR_NULL_OBJECT;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(DMS_PROXY_INTERFACE_TOKEN)) {
        return ERR_FLATTEN_OBJECT;
    }
    DistributedWant dstbWant(want);
    PARCEL_WRITE_HELPER(data, Parcelable, &dstbWant);
    AppExecFwk::CompatibleAbilityInfo compatibleAbilityInfo;
    abilityInfo.ConvertToCompatiableAbilityInfo(compatibleAbilityInfo);
    PARCEL_WRITE_HELPER(data, Parcelable, &compatibleAbilityInfo);
    PARCEL_WRITE_HELPER(data, Int32, requestCode);
    PARCEL_WRITE_HELPER(data, Int32, callerInfo.uid);
    PARCEL_WRITE_HELPER(data, String, callerInfo.sourceDeviceId);
    PARCEL_WRITE_HELPER(data, Int32, accountInfo.accountType);
    PARCEL_WRITE_HELPER(data, StringVector, accountInfo.groupIdList);
    PARCEL_WRITE_HELPER(data, String, callerInfo.callerAppId);
    nlohmann::json extraInfoJson;
    extraInfoJson[EXTRO_INFO_JSON_KEY_ACCESS_TOKEN] = callerInfo.accessToken;
    extraInfoJson[Constants::EXTRO_INFO_JSON_KEY_ACCOUNT_ID] = accountInfo.activeAccountId;
    extraInfoJson[Constants::EXTRO_INFO_JSON_KEY_USERID_ID] = accountInfo.userId;
    if (callerInfo.extraInfoJson.find(DMS_VERSION_ID) != callerInfo.extraInfoJson.end()) {
        extraInfoJson[DMS_VERSION_ID] = callerInfo.extraInfoJson[DMS_VERSION_ID];
    }
    std::string extraInfo = extraInfoJson.dump();
    PARCEL_WRITE_HELPER(data, String, extraInfo);
    MessageParcel reply;
    HITRACE_METER_NAME(TraceTag::DSCHED, TraceValue::REMOTE_PROCEDURE_CALL);
    PARCEL_TRANSACT_SYNC_RET_INT(remote, static_cast<uint32_t>(IDSchedInterfaceCode::START_ABILITY_FROM_REMOTE),
        data, reply);
}

int32_t DistributedSchedProxy::SendResultFromRemote(OHOS::AAFwk::Want& want, int32_t requestCode,
    const CallerInfo& callerInfo, const AccountInfo& accountInfo, int32_t resultCode)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        HILOGE("SendResultFromRemote remote service null");
        return ERR_NULL_OBJECT;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(DMS_PROXY_INTERFACE_TOKEN)) {
        return ERR_FLATTEN_OBJECT;
    }
    DistributedWant dstbWant(want);
    PARCEL_WRITE_HELPER(data, Parcelable, &dstbWant);
    PARCEL_WRITE_HELPER(data, Int32, requestCode);
    PARCEL_WRITE_HELPER(data, Int32, callerInfo.uid);
    PARCEL_WRITE_HELPER(data, String, callerInfo.sourceDeviceId);
    PARCEL_WRITE_HELPER(data, Int32, accountInfo.accountType);
    PARCEL_WRITE_HELPER(data, StringVector, accountInfo.groupIdList);
    PARCEL_WRITE_HELPER(data, String, callerInfo.callerAppId);
    PARCEL_WRITE_HELPER(data, Int32, resultCode);
    nlohmann::json extraInfoJson;
    extraInfoJson[Constants::EXTRO_INFO_JSON_KEY_ACCOUNT_ID] = accountInfo.activeAccountId;
    extraInfoJson[Constants::EXTRO_INFO_JSON_KEY_USERID_ID] = accountInfo.userId;
    extraInfoJson[Constants::EXTRO_INFO_JSON_KEY_CALLER_INFO_EX] = callerInfo.extraInfoJson.dump();
    std::string extraInfo = extraInfoJson.dump();
    PARCEL_WRITE_HELPER(data, String, extraInfo);
    MessageParcel reply;
    PARCEL_TRANSACT_SYNC_RET_INT(remote, static_cast<uint32_t>(IDSchedInterfaceCode::SEND_RESULT_FROM_REMOTE),
        data, reply);
}

int32_t DistributedSchedProxy::ContinueMission(const std::string& srcDeviceId, const std::string& dstDeviceId,
    int32_t missionId, const sptr<IRemoteObject>& callback, const OHOS::AAFwk::WantParams& wantParams)
{
    if (callback == nullptr) {
        HILOGE("ContinueMission callback null");
        return ERR_NULL_OBJECT;
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        HILOGE("ContinueMission remote service null");
        return ERR_NULL_OBJECT;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(DMS_PROXY_INTERFACE_TOKEN)) {
        return ERR_FLATTEN_OBJECT;
    }
    PARCEL_WRITE_HELPER(data, String, srcDeviceId);
    PARCEL_WRITE_HELPER(data, String, dstDeviceId);
    PARCEL_WRITE_HELPER(data, Int32, missionId);
    PARCEL_WRITE_HELPER(data, RemoteObject, callback);
    PARCEL_WRITE_HELPER(data, Parcelable, &wantParams);
    MessageParcel msgReply;
    PARCEL_TRANSACT_SYNC_RET_INT(remote, static_cast<uint32_t>(IDSchedInterfaceCode::CONTINUE_MISSION), data, msgReply);
}

int32_t DistributedSchedProxy::ContinueMission(const std::string& srcDeviceId, const std::string& dstDeviceId,
    const std::string& bundleName, const sptr<IRemoteObject>& callback, const OHOS::AAFwk::WantParams& wantParams)
{
    if (callback == nullptr) {
        HILOGE("ContinueMission callback null");
        return ERR_NULL_OBJECT;
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        HILOGE("ContinueMission remote service null");
        return ERR_NULL_OBJECT;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(DMS_PROXY_INTERFACE_TOKEN)) {
        return ERR_FLATTEN_OBJECT;
    }
    PARCEL_WRITE_HELPER(data, String, srcDeviceId);
    PARCEL_WRITE_HELPER(data, String, dstDeviceId);
    PARCEL_WRITE_HELPER(data, String, bundleName);
    PARCEL_WRITE_HELPER(data, RemoteObject, callback);
    PARCEL_WRITE_HELPER(data, Parcelable, &wantParams);
    MessageParcel msgReply;
    PARCEL_TRANSACT_SYNC_RET_INT(remote, static_cast<uint32_t>(IDSchedInterfaceCode::CONTINUE_MISSION_OF_BUNDLENAME),
        data, msgReply);
}

int32_t DistributedSchedProxy::StartContinuation(const OHOS::AAFwk::Want& want, int32_t missionId, int32_t callerUid,
    int32_t status, uint32_t accessToken)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        HILOGE("StartContinuation remote service null");
        return ERR_NULL_OBJECT;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(DMS_PROXY_INTERFACE_TOKEN)) {
        return ERR_FLATTEN_OBJECT;
    }
    PARCEL_WRITE_HELPER(data, Parcelable, &want);
    PARCEL_WRITE_HELPER(data, Int32, missionId);
    PARCEL_WRITE_HELPER(data, Int32, callerUid);
    PARCEL_WRITE_HELPER(data, Int32, status);
    PARCEL_WRITE_HELPER(data, Uint32, accessToken);
    MessageParcel msgReply;
    PARCEL_TRANSACT_SYNC_RET_INT(remote, static_cast<uint32_t>(IDSchedInterfaceCode::START_CONTINUATION),
        data, msgReply);
}

void DistributedSchedProxy::NotifyCompleteContinuation(const std::u16string& devId, int32_t sessionId, bool isSuccess)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        HILOGE("NotifyCompleteContinuation remote service null");
        return;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(DMS_PROXY_INTERFACE_TOKEN)) {
        return;
    }
    PARCEL_WRITE_HELPER_NORET(data, String16, devId);
    PARCEL_WRITE_HELPER_NORET(data, Int32, sessionId);
    PARCEL_WRITE_HELPER_NORET(data, Bool, isSuccess);
    MessageParcel reply;
    PARCEL_TRANSACT_SYNC_NORET(remote, static_cast<uint32_t>(IDSchedInterfaceCode::NOTIFY_COMPLETE_CONTINUATION),
        data, reply);
}

int32_t DistributedSchedProxy::NotifyDSchedEventResultFromRemote(const std::string type, int32_t dSchedEventResult)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        HILOGE("NotifyDSchedEventResultFromRemote remote service null");
        return ERR_NULL_OBJECT;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(DMS_PROXY_INTERFACE_TOKEN)) {
        return ERR_FLATTEN_OBJECT;
    }
    PARCEL_WRITE_HELPER(data, String, type);
    PARCEL_WRITE_HELPER(data, Int32, dSchedEventResult);
    MessageParcel reply;
    PARCEL_TRANSACT_SYNC_RET_INT(remote, static_cast<uint32_t>
    (IDSchedInterfaceCode::NOTIFY_DSCHED_EVENT_RESULT_FROM_REMOTE), data, reply);
}

int32_t DistributedSchedProxy::NotifyContinuationResultFromRemote(int32_t sessionId, bool isSuccess,
    const std::string dstInfo)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        HILOGE("NotifyContinuationResultFromRemote remote service null");
        return ERR_NULL_OBJECT;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(DMS_PROXY_INTERFACE_TOKEN)) {
        return ERR_FLATTEN_OBJECT;
    }
    PARCEL_WRITE_HELPER(data, Int32, sessionId);
    PARCEL_WRITE_HELPER(data, Bool, isSuccess);
    PARCEL_WRITE_HELPER(data, String, dstInfo);
    MessageParcel reply;
    PARCEL_TRANSACT_SYNC_RET_INT(remote, static_cast<uint32_t>
    (IDSchedInterfaceCode::NOTIFY_CONTINUATION_RESULT_FROM_REMOTE), data, reply);
}

int32_t DistributedSchedProxy::ConnectRemoteAbility(const OHOS::AAFwk::Want& want, const sptr<IRemoteObject>& connect,
    int32_t callerUid, int32_t callerPid, uint32_t accessToken)
{
    if (connect == nullptr) {
        HILOGE("ConnectRemoteAbility connect is null");
        return ERR_NULL_OBJECT;
    }

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        HILOGE("ConnectRemoteAbility remote is null");
        return ERR_NULL_OBJECT;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(DMS_PROXY_INTERFACE_TOKEN)) {
        return ERR_FLATTEN_OBJECT;
    }
    PARCEL_WRITE_HELPER(data, Parcelable, &want);
    PARCEL_WRITE_HELPER(data, RemoteObject, connect);
    PARCEL_WRITE_HELPER(data, Int32, callerUid);
    PARCEL_WRITE_HELPER(data, Int32, callerPid);
    PARCEL_WRITE_HELPER(data, Uint32, accessToken);
    MessageParcel reply;
    PARCEL_TRANSACT_SYNC_RET_INT(remote, static_cast<uint32_t>(IDSchedInterfaceCode::CONNECT_REMOTE_ABILITY),
        data, reply);
}

int32_t DistributedSchedProxy::DisconnectRemoteAbility(const sptr<IRemoteObject>& connect, int32_t callerUid,
    uint32_t accessToken)
{
    if (connect == nullptr) {
        HILOGE("DisconnectRemoteAbility connect is null");
        return ERR_NULL_OBJECT;
    }

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        HILOGE("DisconnectRemoteAbility remote is null");
        return ERR_NULL_OBJECT;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(DMS_PROXY_INTERFACE_TOKEN)) {
        return ERR_FLATTEN_OBJECT;
    }
    PARCEL_WRITE_HELPER(data, RemoteObject, connect);
    PARCEL_WRITE_HELPER(data, Int32, callerUid);
    PARCEL_WRITE_HELPER(data, Uint32, accessToken);
    MessageParcel reply;
    PARCEL_TRANSACT_SYNC_RET_INT(remote, static_cast<uint32_t>(IDSchedInterfaceCode::DISCONNECT_REMOTE_ABILITY),
        data, reply);
}

int32_t DistributedSchedProxy::ConnectAbilityFromRemote(const OHOS::AAFwk::Want& want,
    const AppExecFwk::AbilityInfo& abilityInfo, const sptr<IRemoteObject>& connect,
    const CallerInfo& callerInfo, const AccountInfo& accountInfo)
{
    if (connect == nullptr) {
        HILOGE("ConnectAbilityFromRemote connect is null");
        return ERR_NULL_OBJECT;
    }

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        HILOGE("ConnectAbilityFromRemote remote is null");
        return ERR_NULL_OBJECT;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(DMS_PROXY_INTERFACE_TOKEN)) {
        return ERR_FLATTEN_OBJECT;
    }
    DistributedWant dstbWant(want);
    PARCEL_WRITE_HELPER(data, Parcelable, &dstbWant);
    AppExecFwk::CompatibleAbilityInfo compatibleAbilityInfo;
    abilityInfo.ConvertToCompatiableAbilityInfo(compatibleAbilityInfo);
    PARCEL_WRITE_HELPER(data, Parcelable, &compatibleAbilityInfo);
    PARCEL_WRITE_HELPER(data, RemoteObject, connect);
    PARCEL_WRITE_HELPER(data, Int32, callerInfo.uid);
    PARCEL_WRITE_HELPER(data, Int32, callerInfo.pid);
    PARCEL_WRITE_HELPER(data, String, callerInfo.sourceDeviceId);
    PARCEL_WRITE_HELPER(data, Int32, accountInfo.accountType);
    PARCEL_WRITE_HELPER(data, StringVector, accountInfo.groupIdList);
    PARCEL_WRITE_HELPER(data, String, callerInfo.callerAppId);
    nlohmann::json extraInfoJson;
    extraInfoJson[EXTRO_INFO_JSON_KEY_ACCESS_TOKEN] = callerInfo.accessToken;
    extraInfoJson[Constants::EXTRO_INFO_JSON_KEY_ACCOUNT_ID] = accountInfo.activeAccountId;
    extraInfoJson[Constants::EXTRO_INFO_JSON_KEY_USERID_ID] = accountInfo.userId;
    if (callerInfo.extraInfoJson.find(DMS_VERSION_ID) != callerInfo.extraInfoJson.end()) {
        extraInfoJson[DMS_VERSION_ID] = callerInfo.extraInfoJson[DMS_VERSION_ID];
    }
    std::string extraInfo = extraInfoJson.dump();
    PARCEL_WRITE_HELPER(data, String, extraInfo);
    MessageParcel reply;
    HITRACE_METER_NAME(TraceTag::DSCHED, TraceValue::REMOTE_PROCEDURE_CALL);
    PARCEL_TRANSACT_SYNC_RET_INT(remote, static_cast<uint32_t>(IDSchedInterfaceCode::CONNECT_ABILITY_FROM_REMOTE),
        data, reply);
}

int32_t DistributedSchedProxy::DisconnectAbilityFromRemote(const sptr<IRemoteObject>& connect,
    int32_t uid, const std::string& sourceDeviceId)
{
    if (connect == nullptr) {
        HILOGE("DisconnectAbilityFromRemote connect is null");
        return ERR_NULL_OBJECT;
    }

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        HILOGE("DisconnectAbilityFromRemote remote is null");
        return ERR_NULL_OBJECT;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(DMS_PROXY_INTERFACE_TOKEN)) {
        return ERR_FLATTEN_OBJECT;
    }
    PARCEL_WRITE_HELPER(data, RemoteObject, connect);
    PARCEL_WRITE_HELPER(data, Int32, uid);
    PARCEL_WRITE_HELPER(data, String, sourceDeviceId);
    MessageParcel reply;
    HITRACE_METER_NAME(TraceTag::DSCHED, TraceValue::REMOTE_PROCEDURE_CALL);
    PARCEL_TRANSACT_SYNC_RET_INT(remote, static_cast<uint32_t>(IDSchedInterfaceCode::DISCONNECT_ABILITY_FROM_REMOTE),
        data, reply);
}

int32_t DistributedSchedProxy::NotifyProcessDiedFromRemote(const CallerInfo& callerInfo)
{
    HILOGD("DistributedSchedProxy::NotifyProcessDiedFromRemote called");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        HILOGE("NotifyProcessDiedFromRemote remote is null");
        return ERR_NULL_OBJECT;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(DMS_PROXY_INTERFACE_TOKEN)) {
        return ERR_FLATTEN_OBJECT;
    }
    PARCEL_WRITE_HELPER(data, Int32, callerInfo.uid);
    PARCEL_WRITE_HELPER(data, Int32, callerInfo.pid);
    PARCEL_WRITE_HELPER(data, String, callerInfo.sourceDeviceId);
    MessageParcel reply;
    PARCEL_TRANSACT_SYNC_RET_INT(remote, static_cast<uint32_t>(IDSchedInterfaceCode::NOTIFY_PROCESS_DIED_FROM_REMOTE),
        data, reply);
}

#ifdef SUPPORT_DISTRIBUTED_MISSION_MANAGER
int32_t DistributedSchedProxy::StartSyncRemoteMissions(const std::string& devId, bool fixConflict, int64_t tag,
    int32_t callingUid, uint32_t callingTokenId)
{
    HILOGI("called");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        HILOGE("remote system ability is null");
        return ERR_NULL_OBJECT;
    }

    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(DMS_PROXY_INTERFACE_TOKEN)) {
        return ERR_FLATTEN_OBJECT;
    }
    PARCEL_WRITE_HELPER(data, String16, Str8ToStr16(devId));
    PARCEL_WRITE_HELPER(data, Bool, fixConflict);
    PARCEL_WRITE_HELPER(data, Int64, tag);
    PARCEL_WRITE_HELPER(data, Int32, callingUid);
    PARCEL_WRITE_HELPER(data, Uint32, callingTokenId);
    PARCEL_TRANSACT_SYNC_RET_INT(remote, static_cast<uint32_t>(IDSchedInterfaceCode::START_SYNC_MISSIONS), data, reply);
}

int32_t DistributedSchedProxy::StartSyncMissionsFromRemote(const CallerInfo& callerInfo,
    std::vector<DstbMissionInfo>& missionInfos)
{
    HILOGI("called");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        HILOGE("remote service is null");
        return ERR_NULL_OBJECT;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option { MessageOption::TF_SYNC, WAIT_TIME };
    if (!data.WriteInterfaceToken(DMS_PROXY_INTERFACE_TOKEN)) {
        return ERR_FLATTEN_OBJECT;
    }
    if (!CallerInfoMarshalling(callerInfo, data)) {
        return ERR_FLATTEN_OBJECT;
    }
    int32_t error = remote->SendRequest(static_cast<uint32_t>(IDSchedInterfaceCode::START_SYNC_MISSIONS_FROM_REMOTE),
        data, reply, option);
    if (error != ERR_NONE) {
        HILOGW("fail, error: %{public}d", error);
        return error;
    }
    int32_t version = reply.ReadInt32();
    HILOGD("version : %{public}d", version);
    return DstbMissionInfo::ReadDstbMissionInfosFromParcel(reply, missionInfos) ? ERR_NONE : ERR_FLATTEN_OBJECT;
}

int32_t DistributedSchedProxy::StopSyncRemoteMissions(const std::string& devId, int32_t callingUid)
{
    HILOGI("called");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        HILOGE("remote system ability is null");
        return ERR_NULL_OBJECT;
    }
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(DMS_PROXY_INTERFACE_TOKEN)) {
        return ERR_FLATTEN_OBJECT;
    }
    PARCEL_WRITE_HELPER(data, String16, Str8ToStr16(devId));
    PARCEL_WRITE_HELPER(data, Int32, callingUid);
    PARCEL_TRANSACT_SYNC_RET_INT(remote, static_cast<uint32_t>(IDSchedInterfaceCode::STOP_SYNC_MISSIONS), data, reply);
}

int32_t DistributedSchedProxy::StopSyncMissionsFromRemote(const CallerInfo& callerInfo)
{
    HILOGI("called");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        HILOGE("remote service is null");
        return ERR_NULL_OBJECT;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option { MessageOption::TF_SYNC, WAIT_TIME };
    if (!data.WriteInterfaceToken(DMS_PROXY_INTERFACE_TOKEN)) {
        return ERR_FLATTEN_OBJECT;
    }
    if (!CallerInfoMarshalling(callerInfo, data)) {
        return ERR_FLATTEN_OBJECT;
    }
    int32_t error = remote->SendRequest(static_cast<uint32_t>(IDSchedInterfaceCode::STOP_SYNC_MISSIONS_FROM_REMOTE),
        data, reply, option);
    if (error != ERR_NONE) {
        HILOGW("sendRequest fail, error: %{public}d", error);
        return error;
    }
    return reply.ReadInt32();
}

int32_t DistributedSchedProxy::RegisterMissionListener(const std::u16string& devId,
    const sptr<IRemoteObject>& obj, int32_t callingUid)
{
    HILOGI("RegisterMissionListener called");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        HILOGE("remote system ability is null");
        return ERR_NULL_OBJECT;
    }
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(DMS_PROXY_INTERFACE_TOKEN)) {
        return ERR_FLATTEN_OBJECT;
    }
    PARCEL_WRITE_HELPER(data, String16, devId);
    PARCEL_WRITE_HELPER(data, RemoteObject, obj);
    PARCEL_WRITE_HELPER(data, Int32, callingUid);
    PARCEL_TRANSACT_SYNC_RET_INT(remote, static_cast<uint32_t>(IDSchedInterfaceCode::REGISTER_MISSION_LISTENER),
        data, reply);
}

int32_t DistributedSchedProxy::RegisterDSchedEventListener(const DSchedEventType& type,
    const sptr<IRemoteObject>& obj)
{
    HILOGI("RegisterDSchedEventListener called");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        HILOGE("remote system ability is null");
        return ERR_NULL_OBJECT;
    }
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(DMS_PROXY_INTERFACE_TOKEN)) {
        return ERR_FLATTEN_OBJECT;
    }
    PARCEL_WRITE_HELPER(data, Uint8, type);
    PARCEL_WRITE_HELPER(data, RemoteObject, obj);
    PARCEL_TRANSACT_SYNC_RET_INT(remote, static_cast<uint32_t>(IDSchedInterfaceCode::REGISTER_DSCHED_EVENT_LISTENER),
        data, reply);
}

int32_t DistributedSchedProxy::UnRegisterDSchedEventListener(const DSchedEventType& type,
    const sptr<IRemoteObject>& obj)
{
    HILOGI("UnRegisterDSchedEventListener called");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        HILOGE("remote system ability is null");
        return ERR_NULL_OBJECT;
    }
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(DMS_PROXY_INTERFACE_TOKEN)) {
        return ERR_FLATTEN_OBJECT;
    }
    PARCEL_WRITE_HELPER(data, Uint8, type);
    PARCEL_WRITE_HELPER(data, RemoteObject, obj);
    PARCEL_TRANSACT_SYNC_RET_INT(remote, static_cast<uint32_t>(IDSchedInterfaceCode::UNREGISTER_DSCHED_EVENT_LISTENER),
        data, reply);
}

int32_t DistributedSchedProxy::RegisterOnListener(const std::string& type,
    const sptr<IRemoteObject>& obj, int32_t callingUid)
{
    HILOGI("RegisterOnListener called");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        HILOGE("remote system ability is null");
        return ERR_NULL_OBJECT;
    }
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(DMS_PROXY_INTERFACE_TOKEN)) {
        return ERR_FLATTEN_OBJECT;
    }
    PARCEL_WRITE_HELPER(data, String, type);
    PARCEL_WRITE_HELPER(data, RemoteObject, obj);
    PARCEL_WRITE_HELPER(data, Int32, callingUid);
    PARCEL_TRANSACT_SYNC_RET_INT(remote, static_cast<uint32_t>(IDSchedInterfaceCode::REGISTER_ON_LISTENER),
        data, reply);
}

int32_t DistributedSchedProxy::RegisterOffListener(const std::string& type,
    const sptr<IRemoteObject>& obj, int32_t callingUid)
{
    HILOGI("RegisterOffListener called");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        HILOGE("remote system ability is null");
        return ERR_NULL_OBJECT;
    }
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(DMS_PROXY_INTERFACE_TOKEN)) {
        return ERR_FLATTEN_OBJECT;
    }
    PARCEL_WRITE_HELPER(data, String, type);
    PARCEL_WRITE_HELPER(data, RemoteObject, obj);
    PARCEL_WRITE_HELPER(data, Int32, callingUid);
    PARCEL_TRANSACT_SYNC_RET_INT(remote, static_cast<uint32_t>(IDSchedInterfaceCode::REGISTER_OFF_LISTENER),
        data, reply);
}

int32_t DistributedSchedProxy::UnRegisterMissionListener(const std::u16string& devId,
    const sptr<IRemoteObject>& obj)
{
    HILOGI("UnRegisterMissionListener called");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        HILOGE("remote system ability is null");
        return ERR_NULL_OBJECT;
    }
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(DMS_PROXY_INTERFACE_TOKEN)) {
        return ERR_FLATTEN_OBJECT;
    }
    PARCEL_WRITE_HELPER(data, String16, devId);
    PARCEL_WRITE_HELPER(data, RemoteObject, obj);
    PARCEL_TRANSACT_SYNC_RET_INT(remote, static_cast<uint32_t>(IDSchedInterfaceCode::UNREGISTER_MISSION_LISTENER),
        data, reply);
}

int32_t DistributedSchedProxy::GetMissionInfos(const std::string& deviceId, int32_t numMissions,
    std::vector<AAFwk::MissionInfo>& missionInfos)
{
    HILOGI("called");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        HILOGE("remote system ability is null");
        return ERR_NULL_OBJECT;
    }

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(DMS_PROXY_INTERFACE_TOKEN)) {
        return ERR_FLATTEN_OBJECT;
    }
    PARCEL_WRITE_HELPER(data, String16, Str8ToStr16(deviceId));
    PARCEL_WRITE_HELPER(data, Int32, numMissions);
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(IDSchedInterfaceCode::GET_MISSION_INFOS), data, reply,
        option);
    if (ret != ERR_NONE) {
        HILOGW("sendRequest fail, error: %{public}d", ret);
        return ret;
    }
    return MissionInfoConverter::ReadMissionInfosFromParcel(reply, missionInfos) ? ERR_NONE : ERR_FLATTEN_OBJECT;
}

int32_t DistributedSchedProxy::NotifyMissionsChangedFromRemote(const std::vector<DstbMissionInfo>& missionInfos,
    const CallerInfo& callerInfo)
{
    HILOGI("NotifyMissionsChangedFromRemote is called");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        HILOGE("NotifyMissionsChangedFromRemote remote service is null");
        return ERR_NULL_OBJECT;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(DMS_PROXY_INTERFACE_TOKEN)) {
        return ERR_FLATTEN_OBJECT;
    }
    PARCEL_WRITE_HELPER(data, Int32, callerInfo.dmsVersion);
    if (!DstbMissionInfo::WriteDstbMissionInfosToParcel(data, missionInfos)) {
        return ERR_FLATTEN_OBJECT;
    }
    PARCEL_WRITE_HELPER(data, String, callerInfo.sourceDeviceId);
    PARCEL_WRITE_HELPER(data, Int32, callerInfo.uid);
    PARCEL_WRITE_HELPER(data, Int32, callerInfo.pid);
    PARCEL_WRITE_HELPER(data, Int32, callerInfo.dmsVersion);
    MessageParcel reply;
    MessageOption option { MessageOption::TF_SYNC, WAIT_TIME };
    int32_t error = remote->SendRequest(static_cast<uint32_t>
        (IDSchedInterfaceCode::NOTIFY_MISSIONS_CHANGED_FROM_REMOTE), data, reply, option);
    if (error != ERR_NONE) {
        HILOGE("%{public}s transact failed, error: %{public}d", __func__, error);
        return error;
    }
    int32_t result = reply.ReadInt32();
    HILOGD("%{public}s get result from server data = %{public}d", __func__, result);
    return result;
}

int32_t DistributedSchedProxy::GetRemoteMissionSnapshotInfo(const std::string& networkId, int32_t missionId,
    std::unique_ptr<MissionSnapshot>& missionSnapshot)
{
    if (networkId.empty()) {
        HILOGE("networkId is null");
        return ERR_NULL_OBJECT;
    }
    if (missionId < 0) {
        HILOGE("missionId is invalid");
        return INVALID_PARAMETERS_ERR;
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        HILOGE("remote is null");
        return ERR_NULL_OBJECT;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(DMS_PROXY_INTERFACE_TOKEN)) {
        return ERR_FLATTEN_OBJECT;
    }
    PARCEL_WRITE_HELPER(data, String, networkId);
    PARCEL_WRITE_HELPER(data, Int32, missionId);
    MessageParcel reply;
    MessageOption option;
    int32_t error = remote->SendRequest(static_cast<uint32_t>(IDSchedInterfaceCode::GET_REMOTE_MISSION_SNAPSHOT_INFO),
        data, reply, option);
    if (error != ERR_NONE) {
        HILOGE("transact failed, error: %{public}d", error);
        return error;
    }
    std::unique_ptr<MissionSnapshot> missionSnapshotPtr(reply.ReadParcelable<MissionSnapshot>());
    missionSnapshot = std::move(missionSnapshotPtr);
    return ERR_NONE;
}

int32_t DistributedSchedProxy::SetMissionContinueState(int32_t missionId, const AAFwk::ContinueState &state,
    int32_t callingUid)
{
    HILOGD("DistributedSchedProxy::SetMissionContinueState called");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        HILOGE("SetMissionContinueState remote is null");
        return ERR_NULL_OBJECT;
    }

    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(DMS_PROXY_INTERFACE_TOKEN)) {
        return ERR_FLATTEN_OBJECT;
    }
    PARCEL_WRITE_HELPER(data, Int32, missionId);
    PARCEL_WRITE_HELPER(data, Int32, static_cast<int32_t>(state));
    PARCEL_WRITE_HELPER(data, Int32, callingUid);
    PARCEL_TRANSACT_SYNC_RET_INT(remote, static_cast<uint32_t>(IDSchedInterfaceCode::SET_MISSION_CONTINUE_STATE),
        data, reply);
}
#endif

bool DistributedSchedProxy::CallerInfoMarshalling(const CallerInfo& callerInfo, MessageParcel& data)
{
    PARCEL_WRITE_HELPER_RET(data, Int32, callerInfo.uid, false);
    PARCEL_WRITE_HELPER_RET(data, Int32, callerInfo.pid, false);
    PARCEL_WRITE_HELPER_RET(data, Int32, callerInfo.callerType, false);
    PARCEL_WRITE_HELPER_RET(data, String, callerInfo.sourceDeviceId, false);
    PARCEL_WRITE_HELPER_RET(data, Int32, callerInfo.duid, false);
    PARCEL_WRITE_HELPER_RET(data, String, callerInfo.callerAppId, false);
    PARCEL_WRITE_HELPER_RET(data, Int32, callerInfo.dmsVersion, false);
    std::string extraInfo = callerInfo.extraInfoJson.dump();
    PARCEL_WRITE_HELPER(data, String, extraInfo);
    return true;
}

int32_t DistributedSchedProxy::StartRemoteAbilityByCall(const OHOS::AAFwk::Want& want,
    const sptr<IRemoteObject>& connect, int32_t callerUid, int32_t callerPid, uint32_t accessToken)
{
    if (connect == nullptr) {
        HILOGE("StartRemoteAbilityByCall connect is null");
        return ERR_NULL_OBJECT;
    }

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        HILOGE("StartRemoteAbilityByCall remote is null");
        return ERR_NULL_OBJECT;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(DMS_PROXY_INTERFACE_TOKEN)) {
        return ERR_FLATTEN_OBJECT;
    }
    PARCEL_WRITE_HELPER(data, Parcelable, &want);
    PARCEL_WRITE_HELPER(data, RemoteObject, connect);
    PARCEL_WRITE_HELPER(data, Int32, callerUid);
    PARCEL_WRITE_HELPER(data, Int32, callerPid);
    PARCEL_WRITE_HELPER(data, Uint32, accessToken);
    MessageParcel reply;
    PARCEL_TRANSACT_SYNC_RET_INT(remote, static_cast<uint32_t>(IDSchedInterfaceCode::START_REMOTE_ABILITY_BY_CALL),
        data, reply);
}

int32_t DistributedSchedProxy::ReleaseRemoteAbility(const sptr<IRemoteObject>& connect,
    const AppExecFwk::ElementName &element)
{
    if (connect == nullptr) {
        HILOGE("ReleaseRemoteAbility connect is null");
        return ERR_NULL_OBJECT;
    }

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        HILOGE("ReleaseRemoteAbility remote is null");
        return ERR_NULL_OBJECT;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(DMS_PROXY_INTERFACE_TOKEN)) {
        return ERR_FLATTEN_OBJECT;
    }
    PARCEL_WRITE_HELPER(data, RemoteObject, connect);
    if (!data.WriteParcelable(&element)) {
        HILOGE("ReleaseRemoteAbility write element error.");
        return ERR_INVALID_VALUE;
    }
    MessageParcel reply;
    PARCEL_TRANSACT_SYNC_RET_INT(remote, static_cast<uint32_t>(IDSchedInterfaceCode::RELEASE_REMOTE_ABILITY),
        data, reply);
}

int32_t DistributedSchedProxy::StartAbilityByCallFromRemote(const OHOS::AAFwk::Want& want,
    const sptr<IRemoteObject>& connect, const CallerInfo& callerInfo, const AccountInfo& accountInfo)
{
    if (connect == nullptr) {
        HILOGE("StartAbilityByCallFromRemote connect is null");
        return ERR_NULL_OBJECT;
    }

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        HILOGE("StartAbilityByCallFromRemote remote is null");
        return ERR_NULL_OBJECT;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(DMS_PROXY_INTERFACE_TOKEN)) {
        return ERR_FLATTEN_OBJECT;
    }
    PARCEL_WRITE_HELPER(data, RemoteObject, connect);
    PARCEL_WRITE_HELPER(data, Int32, callerInfo.uid);
    PARCEL_WRITE_HELPER(data, Int32, callerInfo.pid);
    PARCEL_WRITE_HELPER(data, String, callerInfo.sourceDeviceId);
    PARCEL_WRITE_HELPER(data, Int32, accountInfo.accountType);
    PARCEL_WRITE_HELPER(data, StringVector, accountInfo.groupIdList);
    PARCEL_WRITE_HELPER(data, String, callerInfo.callerAppId);
    nlohmann::json extraInfoJson;
    extraInfoJson[EXTRO_INFO_JSON_KEY_ACCESS_TOKEN] = callerInfo.accessToken;
    extraInfoJson[Constants::EXTRO_INFO_JSON_KEY_ACCOUNT_ID] = accountInfo.activeAccountId;
    extraInfoJson[Constants::EXTRO_INFO_JSON_KEY_USERID_ID] = accountInfo.userId;
    if (callerInfo.extraInfoJson.find(DMS_VERSION_ID) != callerInfo.extraInfoJson.end()) {
        extraInfoJson[DMS_VERSION_ID] = callerInfo.extraInfoJson[DMS_VERSION_ID];
    }
    if (callerInfo.extraInfoJson.find(DMS_UID_SPEC_BUNDLE_NAME) != callerInfo.extraInfoJson.end()) {
        extraInfoJson[DMS_UID_SPEC_BUNDLE_NAME] = callerInfo.extraInfoJson[DMS_UID_SPEC_BUNDLE_NAME];
    }

    std::string extraInfo = extraInfoJson.dump();
    PARCEL_WRITE_HELPER(data, String, extraInfo);
    DistributedWant dstbWant(want);
    PARCEL_WRITE_HELPER(data, Parcelable, &dstbWant);
    MessageParcel reply;
    HITRACE_METER_NAME(TraceTag::DSCHED, TraceValue::REMOTE_PROCEDURE_CALL);
    PARCEL_TRANSACT_SYNC_RET_INT(remote, static_cast<uint32_t>
        (IDSchedInterfaceCode::START_ABILITY_BY_CALL_FROM_REMOTE), data, reply);
}

int32_t DistributedSchedProxy::ReleaseAbilityFromRemote(const sptr<IRemoteObject>& connect,
    const AppExecFwk::ElementName &element, const CallerInfo& callerInfo)
{
    if (connect == nullptr) {
        HILOGE("ReleaseAbilityFromRemote connect is null");
        return ERR_NULL_OBJECT;
    }

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        HILOGE("ReleaseAbilityFromRemote remote is null");
        return ERR_NULL_OBJECT;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(DMS_PROXY_INTERFACE_TOKEN)) {
        return ERR_FLATTEN_OBJECT;
    }
    PARCEL_WRITE_HELPER(data, RemoteObject, connect);
    if (!data.WriteParcelable(&element)) {
        HILOGE("ReleaseAbilityFromRemote write element error.");
        return ERR_INVALID_VALUE;
    }
    PARCEL_WRITE_HELPER(data, String, callerInfo.sourceDeviceId);
    std::string extraInfo = "";
    PARCEL_WRITE_HELPER(data, String, extraInfo);
    MessageParcel reply;
    HITRACE_METER_NAME(TraceTag::DSCHED, TraceValue::REMOTE_PROCEDURE_CALL);
    PARCEL_TRANSACT_SYNC_RET_INT(remote, static_cast<uint32_t>(IDSchedInterfaceCode::RELEASE_ABILITY_FROM_REMOTE),
        data, reply);
}

int32_t DistributedSchedProxy::StartRemoteFreeInstall(const OHOS::AAFwk::Want& want,
    int32_t callerUid, int32_t requestCode, uint32_t accessToken, const sptr<IRemoteObject>& callback)
{
    HILOGD("called.");
    if (callback == nullptr) {
        HILOGE("ContinueMission callback null");
        return ERR_NULL_OBJECT;
    }

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        HILOGE("remote callback null");
        return ERR_NULL_OBJECT;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(DMS_PROXY_INTERFACE_TOKEN)) {
        HILOGE("write interface token null");
        return ERR_FLATTEN_OBJECT;
    }

    PARCEL_WRITE_HELPER(data, Parcelable, &want);
    PARCEL_WRITE_HELPER(data, Int32, callerUid);
    PARCEL_WRITE_HELPER(data, Int32, requestCode);
    PARCEL_WRITE_HELPER(data, Uint32, accessToken);
    PARCEL_WRITE_HELPER(data, RemoteObject, callback);
    MessageParcel reply;
    PARCEL_TRANSACT_SYNC_RET_INT(remote, static_cast<uint32_t>(IDSchedInterfaceCode::START_REMOTE_FREE_INSTALL),
        data, reply);
}

int32_t DistributedSchedProxy::StartFreeInstallFromRemote(const FreeInstallInfo& info, int64_t taskId)
{
    HILOGD("called.");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        HILOGE("remote is null");
        return ERR_NULL_OBJECT;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(DMS_PROXY_INTERFACE_TOKEN)) {
        HILOGE("write interface token null");
        return ERR_FLATTEN_OBJECT;
    }

    DistributedWant dstbWant(info.want);
    PARCEL_WRITE_HELPER(data, Parcelable, &dstbWant);
    PARCEL_WRITE_HELPER(data, Int32, info.callerInfo.uid);
    PARCEL_WRITE_HELPER(data, String, info.callerInfo.sourceDeviceId);
    PARCEL_WRITE_HELPER(data, Int32, info.accountInfo.accountType);
    PARCEL_WRITE_HELPER(data, StringVector, info.accountInfo.groupIdList);
    PARCEL_WRITE_HELPER(data, String, info.callerInfo.callerAppId);
    PARCEL_WRITE_HELPER(data, Int64, taskId);
    DistributedWant cmpWant;
    cmpWant.SetParam(CMPT_PARAM_FREEINSTALL_BUNDLENAMES, info.callerInfo.bundleNames);
    PARCEL_WRITE_HELPER(data, Parcelable, &cmpWant);
    nlohmann::json extraInfoJson;
    extraInfoJson[EXTRO_INFO_JSON_KEY_ACCESS_TOKEN] = info.callerInfo.accessToken;
    extraInfoJson[EXTRO_INFO_JSON_KEY_REQUEST_CODE] = info.requestCode;
    extraInfoJson[Constants::EXTRO_INFO_JSON_KEY_ACCOUNT_ID] = info.accountInfo.activeAccountId;
    extraInfoJson[Constants::EXTRO_INFO_JSON_KEY_USERID_ID] = info.accountInfo.userId;
    if (info.callerInfo.extraInfoJson.find(DMS_VERSION_ID) != info.callerInfo.extraInfoJson.end()) {
        extraInfoJson[DMS_VERSION_ID] = info.callerInfo.extraInfoJson[DMS_VERSION_ID];
    }
    std::string extraInfo = extraInfoJson.dump();
    PARCEL_WRITE_HELPER(data, String, extraInfo);
    MessageParcel reply;
    HITRACE_METER_NAME(TraceTag::DSCHED, TraceValue::REMOTE_PROCEDURE_CALL);
    PARCEL_TRANSACT_SYNC_RET_INT(remote, static_cast<uint32_t>(IDSchedInterfaceCode::START_FREE_INSTALL_FROM_REMOTE),
        data, reply);
}

int32_t DistributedSchedProxy::NotifyCompleteFreeInstallFromRemote(int64_t taskId, int32_t resultCode)
{
    HILOGD("called.");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        HILOGE("remote is null");
        return ERR_NULL_OBJECT;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(DMS_PROXY_INTERFACE_TOKEN)) {
        HILOGE("write interface token null");
        return ERR_FLATTEN_OBJECT;
    }

    PARCEL_WRITE_HELPER(data, Int64, taskId);
    PARCEL_WRITE_HELPER(data, Int32, resultCode);
    MessageParcel reply;
    PARCEL_TRANSACT_SYNC_RET_INT(remote, static_cast<uint32_t>
        (IDSchedInterfaceCode::NOTIFY_COMPLETE_FREE_INSTALL_FROM_REMOTE), data, reply);
}

#ifdef SUPPORT_DISTRIBUTED_FORM_SHARE
int32_t DistributedSchedProxy::StartRemoteShareForm(
    const std::string& remoteDeviceId, const AppExecFwk::FormShareInfo& formShareInfo)
{
    HILOGD("SHAREFORM:: func call");
    if (remoteDeviceId.empty()) {
        HILOGE("input params deviceId is nullptr.");
        return INVALID_PARAMETERS_ERR;
    }

    auto remote = Remote();
    if (remote == nullptr) {
        HILOGE("fail to get dms remote.");
        return DMSPROXY_SERVICE_ERR;
    }

    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(DMS_PROXY_INTERFACE_TOKEN)) {
        HILOGE("WriteInterfaceToken failed");
        return ERR_FLATTEN_OBJECT;
    }

    PARCEL_WRITE_HELPER(data, String, remoteDeviceId);
    PARCEL_WRITE_HELPER(data, Parcelable, &formShareInfo);

    PARCEL_TRANSACT_SYNC_RET_INT(remote, static_cast<uint32_t>(IDSchedInterfaceCode::START_REMOTE_SHARE_FORM),
        data, reply);
}

int32_t DistributedSchedProxy::StartShareFormFromRemote(
    const std::string& remoteDeviceId, const AppExecFwk::FormShareInfo& formShareInfo)
{
    HILOGD("SHAREFORM:: func call");
    if (remoteDeviceId.empty()) {
        HILOGE("input params deviceId is nullptr.");
        return INVALID_PARAMETERS_ERR;
    }

    auto remote = Remote();
    if (remote == nullptr) {
        HILOGE("fail to get dms remote.");
        return DMSPROXY_SERVICE_ERR;
    }

    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(DMS_PROXY_INTERFACE_TOKEN)) {
        HILOGE("WriteInterfaceToken failed");
        return ERR_FLATTEN_OBJECT;
    }

    PARCEL_WRITE_HELPER(data, String, remoteDeviceId);
    PARCEL_WRITE_HELPER(data, Parcelable, &formShareInfo);

    PARCEL_TRANSACT_SYNC_RET_INT(remote, static_cast<uint32_t>(IDSchedInterfaceCode::START_SHARE_FORM_FROM_REMOTE),
        data, reply);
}
#endif

int32_t DistributedSchedProxy::NotifyStateChangedFromRemote(int32_t abilityState, int32_t connectToken,
    const AppExecFwk::ElementName& element)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        HILOGE("NotifyStateChangedFromRemote remote service null");
        return ERR_NULL_OBJECT;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(DMS_PROXY_INTERFACE_TOKEN)) {
        HILOGE("WriteInterfaceToken failed");
        return ERR_FLATTEN_OBJECT;
    }
    PARCEL_WRITE_HELPER(data, Int32, abilityState);
    PARCEL_WRITE_HELPER(data, Int32, connectToken);
    if (!data.WriteParcelable(&element)) {
        HILOGE("NotifyStateChangedFromRemote write element error.");
        return ERR_INVALID_VALUE;
    }
    MessageParcel reply;
    PARCEL_TRANSACT_SYNC_RET_INT(remote, static_cast<uint32_t>(IDSchedInterfaceCode::NOTIFY_STATE_CHANGED_FROM_REMOTE),
        data, reply);
}

int32_t DistributedSchedProxy::GetDistributedComponentList(std::vector<std::string>& distributedComponents)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        HILOGE("GetDistributedComponentList remote is null");
        return ERR_NULL_OBJECT;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(DMS_PROXY_INTERFACE_TOKEN)) {
        return ERR_FLATTEN_OBJECT;
    }
    MessageParcel reply;
    MessageOption option;
    int32_t error = remote->SendRequest(static_cast<uint32_t>(IDSchedInterfaceCode::GET_DISTRIBUTED_COMPONENT_LIST),
        data, reply, option);
    if (error != ERR_NONE) {
        HILOGE("GetDistributedComponentList SendRequest error = %{public}d", error);
        return error;
    }
    int32_t result = reply.ReadInt32();
    if (result != ERR_NONE) {
        HILOGE("GetDistributedComponentList result = %{public}d", result);
        return result;
    }
    PARCEL_READ_HELPER(reply, StringVector, &distributedComponents);
    return ERR_NONE;
}

int32_t DistributedSchedProxy::StopRemoteExtensionAbility(
    const OHOS::AAFwk::Want& want, int32_t callerUid, uint32_t accessToken, int32_t extensionType)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        HILOGE("StopRemoteExtensionAbility remote service null");
        return ERR_NULL_OBJECT;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(DMS_PROXY_INTERFACE_TOKEN)) {
        HILOGE("StopRemoteExtensionAbility WriteInterfaceToken failed");
        return ERR_FLATTEN_OBJECT;
    }
    PARCEL_WRITE_HELPER(data, Parcelable, &want);
    PARCEL_WRITE_HELPER(data, Int32, callerUid);
    PARCEL_WRITE_HELPER(data, Uint32, accessToken);
    PARCEL_WRITE_HELPER(data, Int32, extensionType);
    MessageParcel reply;
    PARCEL_TRANSACT_SYNC_RET_INT(remote, static_cast<uint32_t>(IDSchedInterfaceCode::STOP_REMOTE_EXTERNSION_ABILITY),
        data, reply);
}

int32_t DistributedSchedProxy::StopExtensionAbilityFromRemote(const OHOS::AAFwk::Want& want,
    const CallerInfo& callerInfo, const AccountInfo& accountInfo, int32_t extensionType)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        HILOGE("StopExtensionAbilityFromRemote remote service null");
        return ERR_NULL_OBJECT;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(DMS_PROXY_INTERFACE_TOKEN)) {
        HILOGE("StopExtensionAbilityFromRemote WriteInterfaceToken failed");
        return ERR_FLATTEN_OBJECT;
    }
    DistributedWant dstbWant(want);
    PARCEL_WRITE_HELPER(data, Parcelable, &dstbWant);
    PARCEL_WRITE_HELPER(data, Int32, extensionType);
    PARCEL_WRITE_HELPER(data, Int32, callerInfo.uid);
    PARCEL_WRITE_HELPER(data, String, callerInfo.sourceDeviceId);
    PARCEL_WRITE_HELPER(data, Int32, accountInfo.accountType);
    PARCEL_WRITE_HELPER(data, StringVector, accountInfo.groupIdList);
    PARCEL_WRITE_HELPER(data, String, callerInfo.callerAppId);
    nlohmann::json extraInfoJson;
    extraInfoJson[EXTRO_INFO_JSON_KEY_ACCESS_TOKEN] = callerInfo.accessToken;
    extraInfoJson[Constants::EXTRO_INFO_JSON_KEY_ACCOUNT_ID] = accountInfo.activeAccountId;
    extraInfoJson[Constants::EXTRO_INFO_JSON_KEY_USERID_ID] = accountInfo.userId;
    std::string extraInfo = extraInfoJson.dump();
    PARCEL_WRITE_HELPER(data, String, extraInfo);
    MessageParcel reply;
    PARCEL_TRANSACT_SYNC_RET_INT(remote, static_cast<uint32_t>
        (IDSchedInterfaceCode::STOP_EXTERNSION_ABILITY_FROM_REMOTE), data, reply);
}
} // namespace DistributedSchedule
} // namespace OHOS

