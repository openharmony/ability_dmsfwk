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

#include "distributed_sched_stub.h"

#include "ability_info.h"
#include "adapter/dnetwork_adapter.h"
#include "bundle/bundle_manager_internal.h"
#include "caller_info.h"
#include "datetime_ex.h"
#include "dfx/dms_continue_time_dumper.h"
#include "dfx/dms_hisysevent_report.h"
#include "dfx/dms_hitrace_chain.h"
#include "dfx/dms_hitrace_constants.h"
#include "distributed_want.h"
#include "distributed_sched_permission.h"
#include "dtbschedmgr_log.h"
#include "dtbschedmgr_device_info_storage.h"
#ifdef SUPPORT_DISTRIBUTED_MISSION_MANAGER
#include "image_source.h"
#include "mission/distributed_sched_mission_manager.h"
#include "mission/mission_info_converter.h"
#include "mission/snapshot_converter.h"
#include "napi_error_code.h"
#endif
#include "ipc_skeleton.h"
#include "message_parcel.h"
#include "parcel_helper.h"

namespace OHOS {
namespace DistributedSchedule {
using namespace std;
using namespace AAFwk;
using namespace AppExecFwk;

namespace {
constexpr int32_t HID_HAP = 10000; /* first hap user */
const std::string TAG = "DistributedSchedStub";
const std::u16string DMS_STUB_INTERFACE_TOKEN = u"ohos.distributedschedule.accessToken";
const std::string EXTRO_INFO_JSON_KEY_ACCESS_TOKEN = "accessTokenID";
const std::string EXTRO_INFO_JSON_KEY_REQUEST_CODE = "requestCode";
const std::string PERMISSION_DISTRIBUTED_DATASYNC = "ohos.permission.DISTRIBUTED_DATASYNC";
const std::string PARAM_FREEINSTALL_APPID = "ohos.freeinstall.params.callingAppId";
const std::string PARAM_FREEINSTALL_BUNDLENAMES = "ohos.freeinstall.params.callingBundleNames";
const std::string CMPT_PARAM_FREEINSTALL_BUNDLENAMES = "ohos.extra.param.key.allowedBundles";
const std::string DMS_VERSION_ID = "dmsVersion";
const int DEFAULT_REQUEST_CODE = -1;
}

DistributedSchedStub::DistributedSchedStub()
{
    InitExtendedLocalFuncsInner();
    InitLocalFuncsInner();
    InitRemoteFuncsInner();
}

DistributedSchedStub::~DistributedSchedStub()
{
    remoteFuncsMap_.clear();
    localFuncsMap_.clear();
}

void DistributedSchedStub::InitExtendedLocalFuncsInner()
{
    // request codes for mission manager
#ifdef SUPPORT_DISTRIBUTED_MISSION_MANAGER
    localFuncsMap_[static_cast<uint32_t>(IDSchedInterfaceCode::REGISTER_DSCHED_EVENT_LISTENER)] =
        &DistributedSchedStub::RegisterDSchedEventListenerInner;
    localFuncsMap_[static_cast<uint32_t>(IDSchedInterfaceCode::UNREGISTER_DSCHED_EVENT_LISTENER)] =
        &DistributedSchedStub::UnRegisterDSchedEventListenerInner;
#endif
}

void DistributedSchedStub::InitLocalFuncsInner()
{
    localFuncsMap_[static_cast<uint32_t>(IDSchedInterfaceCode::START_REMOTE_ABILITY)] =
        &DistributedSchedStub::StartRemoteAbilityInner;
    localFuncsMap_[static_cast<uint32_t>(IDSchedInterfaceCode::CONTINUE_MISSION)] =
        &DistributedSchedStub::ContinueMissionInner;
    localFuncsMap_[static_cast<uint32_t>(IDSchedInterfaceCode::CONTINUE_MISSION_OF_BUNDLENAME)] =
        &DistributedSchedStub::ContinueMissionOfBundleNameInner;
    localFuncsMap_[static_cast<uint32_t>(IDSchedInterfaceCode::START_CONTINUATION)] =
        &DistributedSchedStub::StartContinuationInner;
    localFuncsMap_[static_cast<uint32_t>(IDSchedInterfaceCode::NOTIFY_COMPLETE_CONTINUATION)] =
        &DistributedSchedStub::NotifyCompleteContinuationInner;
    localFuncsMap_[static_cast<uint32_t>(IDSchedInterfaceCode::CONNECT_REMOTE_ABILITY)] =
        &DistributedSchedStub::ConnectRemoteAbilityInner;
    localFuncsMap_[static_cast<uint32_t>(IDSchedInterfaceCode::DISCONNECT_REMOTE_ABILITY)] =
        &DistributedSchedStub::DisconnectRemoteAbilityInner;
    // request codes for mission manager
#ifdef SUPPORT_DISTRIBUTED_MISSION_MANAGER
    InitLocalMissionManagerInner();
#endif
    localFuncsMap_[static_cast<uint32_t>(IDSchedInterfaceCode::START_REMOTE_ABILITY_BY_CALL)] =
        &DistributedSchedStub::StartRemoteAbilityByCallInner;
    localFuncsMap_[static_cast<uint32_t>(IDSchedInterfaceCode::RELEASE_REMOTE_ABILITY)] =
        &DistributedSchedStub::ReleaseRemoteAbilityInner;
#ifdef SUPPORT_DISTRIBUTED_FORM_SHARE
    localFuncsMap_[static_cast<uint32_t>(IDSchedInterfaceCode::START_REMOTE_SHARE_FORM)] =
        &DistributedSchedStub::StartRemoteShareFormInner;
#endif
    localFuncsMap_[static_cast<uint32_t>(IDSchedInterfaceCode::GET_DISTRIBUTED_COMPONENT_LIST)] =
        &DistributedSchedStub::GetDistributedComponentListInner;
    localFuncsMap_[static_cast<uint32_t>(IDSchedInterfaceCode::START_REMOTE_FREE_INSTALL)] =
        &DistributedSchedStub::StartRemoteFreeInstallInner;
    localFuncsMap_[static_cast<uint32_t>(IDSchedInterfaceCode::STOP_REMOTE_EXTERNSION_ABILITY)] =
        &DistributedSchedStub::StopRemoteExtensionAbilityInner;
}

void DistributedSchedStub::InitLocalMissionManagerInner()
{
    localFuncsMap_[static_cast<uint32_t>(IDSchedInterfaceCode::GET_REMOTE_MISSION_SNAPSHOT_INFO)] =
        &DistributedSchedStub::GetRemoteMissionSnapshotInfoInner;
    localFuncsMap_[static_cast<uint32_t>(IDSchedInterfaceCode::REGISTER_MISSION_LISTENER)] =
        &DistributedSchedStub::RegisterMissionListenerInner;
    localFuncsMap_[static_cast<uint32_t>(IDSchedInterfaceCode::REGISTER_ON_LISTENER)] =
        &DistributedSchedStub::RegisterOnListenerInner;
    localFuncsMap_[static_cast<uint32_t>(IDSchedInterfaceCode::REGISTER_OFF_LISTENER)] =
        &DistributedSchedStub::RegisterOffListenerInner;
    localFuncsMap_[static_cast<uint32_t>(IDSchedInterfaceCode::UNREGISTER_MISSION_LISTENER)] =
        &DistributedSchedStub::UnRegisterMissionListenerInner;
    localFuncsMap_[static_cast<uint32_t>(IDSchedInterfaceCode::GET_MISSION_INFOS)] =
        &DistributedSchedStub::GetMissionInfosInner;
    localFuncsMap_[static_cast<uint32_t>(IDSchedInterfaceCode::START_SYNC_MISSIONS)] =
        &DistributedSchedStub::StartSyncRemoteMissionsInner;
    localFuncsMap_[static_cast<uint32_t>(IDSchedInterfaceCode::STOP_SYNC_MISSIONS)] =
        &DistributedSchedStub::StopSyncRemoteMissionsInner;
    localFuncsMap_[static_cast<uint32_t>(IDSchedInterfaceCode::SET_MISSION_CONTINUE_STATE)] =
        &DistributedSchedStub::SetMissionContinueStateInner;
}

void DistributedSchedStub::InitRemoteFuncsInner()
{
    remoteFuncsMap_[static_cast<uint32_t>(IDSchedInterfaceCode::START_ABILITY_FROM_REMOTE)] =
        &DistributedSchedStub::StartAbilityFromRemoteInner;
    remoteFuncsMap_[static_cast<uint32_t>(IDSchedInterfaceCode::SEND_RESULT_FROM_REMOTE)] =
        &DistributedSchedStub::SendResultFromRemoteInner;
    remoteFuncsMap_[static_cast<uint32_t>(IDSchedInterfaceCode::NOTIFY_CONTINUATION_RESULT_FROM_REMOTE)] =
        &DistributedSchedStub::NotifyContinuationResultFromRemoteInner;
    remoteFuncsMap_[static_cast<uint32_t>(IDSchedInterfaceCode::NOTIFY_DSCHED_EVENT_RESULT_FROM_REMOTE)] =
        &DistributedSchedStub::NotifyDSchedEventResultFromRemoteInner;
    remoteFuncsMap_[static_cast<uint32_t>(IDSchedInterfaceCode::CONNECT_ABILITY_FROM_REMOTE)] =
        &DistributedSchedStub::ConnectAbilityFromRemoteInner;
    remoteFuncsMap_[static_cast<uint32_t>(IDSchedInterfaceCode::DISCONNECT_ABILITY_FROM_REMOTE)] =
        &DistributedSchedStub::DisconnectAbilityFromRemoteInner;
    remoteFuncsMap_[static_cast<uint32_t>(IDSchedInterfaceCode::NOTIFY_PROCESS_DIED_FROM_REMOTE)] =
        &DistributedSchedStub::NotifyProcessDiedFromRemoteInner;
#ifdef SUPPORT_DISTRIBUTED_MISSION_MANAGER
    // request codes for mission manager
    remoteFuncsMap_[static_cast<uint32_t>(IDSchedInterfaceCode::START_SYNC_MISSIONS_FROM_REMOTE)] =
        &DistributedSchedStub::StartSyncMissionsFromRemoteInner;
    remoteFuncsMap_[static_cast<uint32_t>(IDSchedInterfaceCode::STOP_SYNC_MISSIONS_FROM_REMOTE)] =
        &DistributedSchedStub::StopSyncMissionsFromRemoteInner;
    remoteFuncsMap_[static_cast<uint32_t>(IDSchedInterfaceCode::NOTIFY_MISSIONS_CHANGED_FROM_REMOTE)] =
        &DistributedSchedStub::NotifyMissionsChangedFromRemoteInner;
#endif
    remoteFuncsMap_[static_cast<uint32_t>(IDSchedInterfaceCode::CONTINUE_MISSION)] =
        &DistributedSchedStub::ContinueMissionInner;
    remoteFuncsMap_[static_cast<uint32_t>(IDSchedInterfaceCode::CONTINUE_MISSION_OF_BUNDLENAME)] =
        &DistributedSchedStub::ContinueMissionOfBundleNameInner;
    remoteFuncsMap_[static_cast<uint32_t>(IDSchedInterfaceCode::START_ABILITY_BY_CALL_FROM_REMOTE)] =
        &DistributedSchedStub::StartAbilityByCallFromRemoteInner;
    remoteFuncsMap_[static_cast<uint32_t>(IDSchedInterfaceCode::RELEASE_ABILITY_FROM_REMOTE)] =
        &DistributedSchedStub::ReleaseAbilityFromRemoteInner;
    remoteFuncsMap_[static_cast<uint32_t>(IDSchedInterfaceCode::NOTIFY_STATE_CHANGED_FROM_REMOTE)] =
        &DistributedSchedStub::NotifyStateChangedFromRemoteInner;
#ifdef SUPPORT_DISTRIBUTED_FORM_SHARE
    remoteFuncsMap_[static_cast<uint32_t>(IDSchedInterfaceCode::START_SHARE_FORM_FROM_REMOTE)] =
        &DistributedSchedStub::StartShareFormFromRemoteInner;
#endif
    remoteFuncsMap_[static_cast<uint32_t>(IDSchedInterfaceCode::START_FREE_INSTALL_FROM_REMOTE)] =
        &DistributedSchedStub::StartFreeInstallFromRemoteInner;
    remoteFuncsMap_[static_cast<uint32_t>(IDSchedInterfaceCode::NOTIFY_COMPLETE_FREE_INSTALL_FROM_REMOTE)] =
        &DistributedSchedStub::NotifyCompleteFreeInstallFromRemoteInner;
    remoteFuncsMap_[static_cast<uint32_t>(IDSchedInterfaceCode::STOP_EXTERNSION_ABILITY_FROM_REMOTE)] =
        &DistributedSchedStub::StopExtensionAbilityFromRemoteInner;
}

int32_t DistributedSchedStub::OnRemoteRequest(uint32_t code,
    MessageParcel& data, MessageParcel& reply, MessageOption& option)
{
    bool IsLocalCalling = IPCSkeleton::IsLocalCalling();
    HILOGI("OnRemoteRequest, code = %{public}u, flags = %{public}d, IsLocalCalling = %{public}d.",
        code, option.GetFlags(), IsLocalCalling);

    const auto& funcsMap = IsLocalCalling ? localFuncsMap_ : remoteFuncsMap_;
    auto iter = funcsMap.find(code);
    if (iter != funcsMap.end()) {
        auto func = iter->second;
        if (!EnforceInterfaceToken(data)) {
            HILOGW("OnRemoteRequest interface token check failed!");
            return DMS_PERMISSION_DENIED;
        }
        if (func != nullptr) {
            return (this->*func)(data, reply);
        }
    }

    HILOGW("OnRemoteRequest default case, need check.");
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int32_t DistributedSchedStub::StartRemoteAbilityInner(MessageParcel& data, MessageParcel& reply)
{
    if (!DistributedSchedPermission::GetInstance().IsFoundationCall()) {
        return DMS_PERMISSION_DENIED;
    }
    DmsHiTraceChain hiTraceChain(TraceValue::START_REMOTE_ABILITY);
    HITRACE_METER_NAME(TraceTag::DSCHED, TraceValue::START_REMOTE_ABILITY);
    shared_ptr<AAFwk::Want> want(data.ReadParcelable<AAFwk::Want>());
    if (want == nullptr) {
        HILOGW("START_ABILITY want readParcelable failed!");
        return ERR_NULL_OBJECT;
    }
    int32_t callerUid = 0;
    PARCEL_READ_HELPER(data, Int32, callerUid);
    int32_t requestCode = 0;
    PARCEL_READ_HELPER(data, Int32, requestCode);
    uint32_t accessToken = 0;
    PARCEL_READ_HELPER(data, Uint32, accessToken);
    HILOGD("get callerUid = %d, AccessTokenID = %u", callerUid, accessToken);
    if (DistributedSchedPermission::GetInstance().CheckPermission(accessToken,
        PERMISSION_DISTRIBUTED_DATASYNC) != ERR_OK) {
        HILOGE("check data_sync permission failed!");
        return DMS_PERMISSION_DENIED;
    }
    DistributedSchedPermission::GetInstance().MarkUriPermission(*want, accessToken);
    int32_t result = StartRemoteAbility(*want, callerUid, requestCode, accessToken);
    ReportEvent(*want, BehaviorEvent::START_REMOTE_ABILITY, result, callerUid);
    HILOGI("StartRemoteAbilityInner result = %{public}d", result);
    PARCEL_WRITE_REPLY_NOERROR(reply, Int32, result);
}

void DistributedSchedStub::ReportEvent(const OHOS::AAFwk::Want& want, const std::string& eventName, int32_t result,
    int32_t callerUid)
{
    std::vector<std::string> bundleNames;
    if (!BundleManagerInternal::GetBundleNameListFromBms(callerUid, bundleNames)) {
        HILOGE("GetBundleNameListFromBms failed");
        return;
    }
    std::string srcBundleName = bundleNames.empty() ? std::string() : bundleNames.front();
    HILOGD("srcBundleName %{public}s", srcBundleName.c_str());
    AppExecFwk::BundleInfo localBundleInfo;
    if (BundleManagerInternal::GetLocalBundleInfo(srcBundleName, localBundleInfo) != ERR_OK) {
        HILOGE("get local bundle info failed");
        return;
    }
    HILOGD("version %{public}s", localBundleInfo.versionName.c_str());

    BehaviorEventParam eventParam = { EventCallingType::LOCAL, eventName, result, want.GetElement().GetBundleName(),
        want.GetElement().GetAbilityName(), callerUid, srcBundleName, localBundleInfo.versionName };
    DmsHiSysEventReport::ReportBehaviorEvent(eventParam);
    HILOGD("report event success!");
}

shared_ptr<AAFwk::Want> DistributedSchedStub::ReadDistributedWant(MessageParcel& data)
{
    shared_ptr<DistributedWant> dstbWant(data.ReadParcelable<DistributedWant>());
    shared_ptr<AAFwk::Want> want = nullptr;
    if (dstbWant != nullptr) {
        want = dstbWant->ToWant();
    }
    return want;
}

int32_t DistributedSchedStub::StartAbilityFromRemoteInner(MessageParcel& data, MessageParcel& reply)
{
    if (!CheckCallingUid()) {
        HILOGW("request DENIED!");
        return DMS_PERMISSION_DENIED;
    }
    shared_ptr<AAFwk::Want> want = ReadDistributedWant(data);
    if (want == nullptr) {
        HILOGW("want readParcelable failed!");
        return ERR_NULL_OBJECT;
    }
    unique_ptr<CompatibleAbilityInfo> cmpAbilityInfo(data.ReadParcelable<CompatibleAbilityInfo>());
    if (cmpAbilityInfo == nullptr) {
        HILOGW("AbilityInfo readParcelable failed!");
        return ERR_NULL_OBJECT;
    }
    AbilityInfo abilityInfo;
    cmpAbilityInfo->ConvertToAbilityInfo(abilityInfo);
    std::string package = abilityInfo.bundleName;
    std::string deviceId = abilityInfo.deviceId;
    int64_t begin = GetTickCount();
    int32_t requestCode = 0;
    PARCEL_READ_HELPER(data, Int32, requestCode);
    CallerInfo callerInfo;
    PARCEL_READ_HELPER(data, Int32, callerInfo.uid);
    PARCEL_READ_HELPER(data, String, callerInfo.sourceDeviceId);
    callerInfo.callerType = CALLER_TYPE_HARMONY;
    AccountInfo accountInfo;
    accountInfo.accountType = data.ReadInt32();
    PARCEL_READ_HELPER(data, StringVector, &accountInfo.groupIdList);
    callerInfo.callerAppId = data.ReadString();
    std::string extraInfo = data.ReadString();
    if (!extraInfo.empty()) {
        nlohmann::json extraInfoJson = nlohmann::json::parse(extraInfo, nullptr, false);
        if (!extraInfoJson.is_discarded()) {
            SaveExtraInfo(extraInfoJson, callerInfo);
            HILOGD("parse extra info");
        }
    }
    int32_t result = StartAbilityFromRemote(*want, abilityInfo, requestCode, callerInfo, accountInfo);
    BehaviorEventParam eventParam = { EventCallingType::REMOTE, BehaviorEvent::START_REMOTE_ABILITY, result,
        want->GetElement().GetBundleName(), want->GetElement().GetAbilityName(), callerInfo.uid };
    DmsHiSysEventReport::ReportBehaviorEvent(eventParam);
    HILOGI("result = %{public}d", result);
    PARCEL_WRITE_HELPER(reply, Int32, result);
    int64_t end = GetTickCount();
    PARCEL_WRITE_HELPER(reply, Int64, end - begin);
    PARCEL_WRITE_HELPER(reply, String, package);
    PARCEL_WRITE_HELPER(reply, String, deviceId);
    return ERR_NONE;
}

void DistributedSchedStub::SaveExtraInfo(const nlohmann::json& extraInfoJson, CallerInfo& callerInfo)
{
    if (extraInfoJson.find(EXTRO_INFO_JSON_KEY_ACCESS_TOKEN) != extraInfoJson.end() &&
        extraInfoJson[EXTRO_INFO_JSON_KEY_ACCESS_TOKEN].is_number_unsigned()) {
        uint32_t accessToken = extraInfoJson[EXTRO_INFO_JSON_KEY_ACCESS_TOKEN];
        callerInfo.accessToken = accessToken;
        HILOGD("parse extra info, accessTokenID = %u", accessToken);
    }
    if (extraInfoJson.find(DMS_VERSION_ID) != extraInfoJson.end() && extraInfoJson[DMS_VERSION_ID].is_string()) {
        std::string dmsVersion = extraInfoJson[DMS_VERSION_ID];
        callerInfo.extraInfoJson[DMS_VERSION_ID] = dmsVersion;
        HILOGD("save dms version");
    }
}

int32_t DistributedSchedStub::SendResultFromRemoteInner(MessageParcel& data, MessageParcel& reply)
{
    if (!CheckCallingUid()) {
        HILOGW("request DENIED!");
        return DMS_PERMISSION_DENIED;
    }
    shared_ptr<DistributedWant> dstbWant(data.ReadParcelable<DistributedWant>());
    shared_ptr<AAFwk::Want> want = nullptr;
    if (dstbWant != nullptr) {
        want = dstbWant->ToWant();
    }
    if (want == nullptr) {
        HILOGW("want readParcelable failed!");
        return ERR_NULL_OBJECT;
    }
    int64_t begin = GetTickCount();
    int32_t requestCode = 0;
    PARCEL_READ_HELPER(data, Int32, requestCode);
    CallerInfo callerInfo;
    PARCEL_READ_HELPER(data, Int32, callerInfo.uid);
    PARCEL_READ_HELPER(data, String, callerInfo.sourceDeviceId);
    callerInfo.callerType = CALLER_TYPE_HARMONY;
    AccountInfo accountInfo;
    accountInfo.accountType = data.ReadInt32();
    PARCEL_READ_HELPER(data, StringVector, &accountInfo.groupIdList);
    callerInfo.callerAppId = data.ReadString();
    int32_t resultCode = 0;
    PARCEL_READ_HELPER(data, Int32, resultCode);
    std::string extraInfo = data.ReadString();
    if (extraInfo.empty()) {
        HILOGD("extra info is empty!");
    }
    callerInfo.extraInfoJson = nlohmann::json::parse(extraInfo, nullptr, false);
    int32_t result = SendResultFromRemote(*want, requestCode, callerInfo, accountInfo, resultCode);
    HILOGI("result = %{public}d", result);
    PARCEL_WRITE_HELPER(reply, Int32, result);
    int64_t end = GetTickCount();
    PARCEL_WRITE_HELPER(reply, Int64, end - begin);
    return ERR_NONE;
}

int32_t DistributedSchedStub::ContinueMissionInner(MessageParcel& data, MessageParcel& reply)
{
    bool isLocalCalling = IPCSkeleton::IsLocalCalling();
    if ((isLocalCalling && !DistributedSchedPermission::GetInstance().IsFoundationCall()) ||
        (!isLocalCalling && !CheckCallingUid())) {
        HILOGE("check permission failed!");
        return DMS_PERMISSION_DENIED;
    }

    std::string srcDevId;
    std::string dstDevId;
    PARCEL_READ_HELPER(data, String, srcDevId);
    PARCEL_READ_HELPER(data, String, dstDevId);
    int32_t missionId = 0;
    PARCEL_READ_HELPER(data, Int32, missionId);
    sptr<IRemoteObject> callback = data.ReadRemoteObject();
    if (callback == nullptr) {
        HILOGW("read callback failed!");
        return ERR_NULL_OBJECT;
    }
    shared_ptr<AAFwk::WantParams> wantParams(data.ReadParcelable<AAFwk::WantParams>());
    if (wantParams == nullptr) {
        HILOGW("wantParams readParcelable failed!");
        return ERR_NULL_OBJECT;
    }
    int32_t result = ContinueMission(srcDevId, dstDevId, missionId, callback, *wantParams);
    HILOGI("result = %{public}d", result);
    PARCEL_WRITE_REPLY_NOERROR(reply, Int32, result);
}

int32_t DistributedSchedStub::ContinueMissionOfBundleNameInner(MessageParcel& data, MessageParcel& reply)
{
    bool isLocalCalling = IPCSkeleton::IsLocalCalling();
    if ((isLocalCalling && !DistributedSchedPermission::GetInstance().IsFoundationCall()) ||
        (!isLocalCalling && !CheckCallingUid())) {
        HILOGE("check permission failed!");
        return DMS_PERMISSION_DENIED;
    }

    std::string srcDevId;
    std::string dstDevId;
    std::string bundleName;
    PARCEL_READ_HELPER(data, String, srcDevId);
    PARCEL_READ_HELPER(data, String, dstDevId);
    PARCEL_READ_HELPER(data, String, bundleName);
    sptr<IRemoteObject> callback = data.ReadRemoteObject();
    if (callback == nullptr) {
        HILOGW("read callback failed!");
        return ERR_NULL_OBJECT;
    }
    shared_ptr<AAFwk::WantParams> wantParams(data.ReadParcelable<AAFwk::WantParams>());
    if (wantParams == nullptr) {
        HILOGW("wantParams readParcelable failed!");
        return ERR_NULL_OBJECT;
    }
    int32_t result = ContinueMission(srcDevId, dstDevId, bundleName, callback, *wantParams);
    HILOGI("result = %{public}d", result);
    PARCEL_WRITE_REPLY_NOERROR(reply, Int32, result);
}

int32_t DistributedSchedStub::StartContinuationInner(MessageParcel& data, MessageParcel& reply)
{
    int64_t saveDataEnd = GetTickCount();
    DmsContinueTime::GetInstance().SetSaveDataDurationEnd(saveDataEnd);
    
    if (!DistributedSchedPermission::GetInstance().IsFoundationCall()) {
        return DMS_PERMISSION_DENIED;
    }
    DmsHiTraceChain hiTraceChain(TraceValue::START_CONTINUATION);
    HITRACE_METER_NAME(TraceTag::DSCHED, TraceValue::START_CONTINUATION);
    shared_ptr<AAFwk::Want> want(data.ReadParcelable<AAFwk::Want>());
    if (want == nullptr) {
        HILOGW("want readParcelable failed!");
        return ERR_NULL_OBJECT;
    }
    int32_t missionId = data.ReadInt32();
    int32_t callerUid = data.ReadInt32();
    int32_t status = data.ReadInt32();
    uint32_t accessToken = 0;
    PARCEL_READ_HELPER(data, Uint32, accessToken);
    HILOGI("get AccessTokenID = %{public}u", accessToken);
    DistributedSchedPermission::GetInstance().MarkUriPermission(*want, accessToken);
    int32_t result = StartContinuation(*want, missionId, callerUid, status, accessToken);
    ReportEvent(*want, BehaviorEvent::START_CONTINUATION, result, callerUid);
    HILOGI("result = %{public}d", result);
    PARCEL_WRITE_REPLY_NOERROR(reply, Int32, result);
}

int32_t DistributedSchedStub::NotifyCompleteContinuationInner(MessageParcel& data,
    [[maybe_unused]] MessageParcel& reply)
{
    if (!DistributedSchedPermission::GetInstance().IsFoundationCall()) {
        HILOGE("check permission failed!");
        return DMS_PERMISSION_DENIED;
    }

    u16string devId = data.ReadString16();
    if (devId.empty()) {
        HILOGE("devId is empty!");
        return INVALID_PARAMETERS_ERR;
    }
    int32_t sessionId = 0;
    PARCEL_READ_HELPER(data, Int32, sessionId);
    bool continuationResult = false;
    PARCEL_READ_HELPER(data, Bool, continuationResult);
    NotifyCompleteContinuation(devId, sessionId, continuationResult);
    return ERR_OK;
}

int32_t DistributedSchedStub::NotifyDSchedEventResultFromRemoteInner(MessageParcel& data,
    [[maybe_unused]] MessageParcel& reply)
{
    if (!CheckCallingUid()) {
        HILOGW("request DENIED!");
        return DMS_PERMISSION_DENIED;
    }

    std::string type = "";
    PARCEL_READ_HELPER(data, String, type);
    int32_t dSchedEventResult = -1;
    PARCEL_READ_HELPER(data, Int32, dSchedEventResult);
    return NotifyDSchedEventResultFromRemote(type, dSchedEventResult);
}

int32_t DistributedSchedStub::NotifyContinuationResultFromRemoteInner(MessageParcel& data,
    [[maybe_unused]] MessageParcel& reply)
{
    if (!CheckCallingUid()) {
        HILOGW("request DENIED!");
        return DMS_PERMISSION_DENIED;
    }

    int32_t sessionId = 0;
    PARCEL_READ_HELPER(data, Int32, sessionId);
    bool continuationResult = false;
    PARCEL_READ_HELPER(data, Bool, continuationResult);
    std::string dstInfo;
    PARCEL_READ_HELPER(data, String, dstInfo);
    return NotifyContinuationResultFromRemote(sessionId, continuationResult, dstInfo);
}

int32_t DistributedSchedStub::ConnectRemoteAbilityInner(MessageParcel& data, MessageParcel& reply)
{
    if (!DistributedSchedPermission::GetInstance().IsFoundationCall()) {
        return DMS_PERMISSION_DENIED;
    }
    DmsHiTraceChain hiTraceChain(TraceValue::CONNECT_REMOTE_ABILITY);
    HITRACE_METER_NAME(TraceTag::DSCHED, TraceValue::CONNECT_REMOTE_ABILITY);
    shared_ptr<AAFwk::Want> want(data.ReadParcelable<AAFwk::Want>());
    if (want == nullptr) {
        HILOGW("want readParcelable failed!");
        return ERR_NULL_OBJECT;
    }
    sptr<IRemoteObject> connect = data.ReadRemoteObject();
    int32_t callerUid = 0;
    PARCEL_READ_HELPER(data, Int32, callerUid);
    int32_t callerPid = 0;
    PARCEL_READ_HELPER(data, Int32, callerPid);
    uint32_t accessToken = 0;
    PARCEL_READ_HELPER(data, Uint32, accessToken);
    HILOGD("get callerUid = %d, callerPid = %d, AccessTokenID = %u", callerUid, callerPid,
        accessToken);
    if (DistributedSchedPermission::GetInstance().CheckPermission(accessToken,
        PERMISSION_DISTRIBUTED_DATASYNC) != ERR_OK) {
        HILOGE("check data_sync permission failed!");
        return DMS_PERMISSION_DENIED;
    }
    int32_t result = ConnectRemoteAbility(*want, connect, callerUid, callerPid, accessToken);
    ReportEvent(*want, BehaviorEvent::CONNECT_REMOTE_ABILITY, result, callerUid);
    HILOGI("result = %{public}d", result);
    PARCEL_WRITE_REPLY_NOERROR(reply, Int32, result);
}

int32_t DistributedSchedStub::DisconnectRemoteAbilityInner(MessageParcel& data, MessageParcel& reply)
{
    if (!DistributedSchedPermission::GetInstance().IsFoundationCall()) {
        return DMS_PERMISSION_DENIED;
    }
    DmsHiTraceChain hiTraceChain(TraceValue::DISCONNECT_REMOTE_ABILITY);
    HITRACE_METER_NAME(TraceTag::DSCHED, TraceValue::DISCONNECT_REMOTE_ABILITY);
    sptr<IRemoteObject> connect = data.ReadRemoteObject();
    int32_t callerUid = 0;
    PARCEL_READ_HELPER(data, Int32, callerUid);
    uint32_t accessToken = 0;
    PARCEL_READ_HELPER(data, Uint32, accessToken);
    HILOGD("get callerUid = %d, AccessTokenID = %u", callerUid, accessToken);
    if (DistributedSchedPermission::GetInstance().CheckPermission(accessToken,
        PERMISSION_DISTRIBUTED_DATASYNC) != ERR_OK) {
        HILOGE("check data_sync permission failed!");
        return DMS_PERMISSION_DENIED;
    }
    int32_t result = DisconnectRemoteAbility(connect, callerUid, accessToken);
    BehaviorEventParam eventParam = { EventCallingType::LOCAL, BehaviorEvent::DISCONNECT_REMOTE_ABILITY, result };
    DmsHiSysEventReport::ReportBehaviorEvent(eventParam);
    HILOGI("result = %{public}d", result);
    PARCEL_WRITE_REPLY_NOERROR(reply, Int32, result);
}

int32_t DistributedSchedStub::ReadDataForConnect(MessageParcel& data, CallerInfo& callerInfo, AccountInfo& accountInfo)
{
    PARCEL_READ_HELPER(data, Int32, callerInfo.uid);
    PARCEL_READ_HELPER(data, Int32, callerInfo.pid);
    PARCEL_READ_HELPER(data, String, callerInfo.sourceDeviceId);
    callerInfo.callerType = CALLER_TYPE_HARMONY;
    accountInfo.accountType = data.ReadInt32();
    PARCEL_READ_HELPER(data, StringVector, &accountInfo.groupIdList);
    callerInfo.callerAppId = data.ReadString();
    return ERR_NONE;
}

int32_t DistributedSchedStub::ConnectAbilityFromRemoteInner(MessageParcel& data, MessageParcel& reply)
{
    if (!CheckCallingUid()) {
        HILOGW("request DENIED!");
        return DMS_PERMISSION_DENIED;
    }
    shared_ptr<AAFwk::Want> want = ReadDistributedWant(data);
    if (want == nullptr) {
        HILOGW("want readParcelable failed!");
        return ERR_NULL_OBJECT;
    }
    unique_ptr<CompatibleAbilityInfo> cmpAbilityInfo(data.ReadParcelable<CompatibleAbilityInfo>());
    if (cmpAbilityInfo == nullptr) {
        HILOGW("abilityInfo readParcelable failed!");
        return ERR_NULL_OBJECT;
    }
    AbilityInfo abilityInfo;
    cmpAbilityInfo->ConvertToAbilityInfo(abilityInfo);
    sptr<IRemoteObject> connect = data.ReadRemoteObject();
    CallerInfo callerInfo;
    AccountInfo accountInfo;
    int32_t result = ReadDataForConnect(data, callerInfo, accountInfo);
    if (result != ERR_NONE) {
        return result;
    }
    std::string extraInfo = data.ReadString();
    if (extraInfo.empty()) {
        HILOGD("extra info is empty!");
    }
    nlohmann::json extraInfoJson = nlohmann::json::parse(extraInfo, nullptr, false);
    if (!extraInfoJson.is_discarded()) {
        SaveExtraInfo(extraInfoJson, callerInfo);
        HILOGD("parse extra info");
    }
    std::string package = abilityInfo.bundleName;
    std::string deviceId = abilityInfo.deviceId;
    int64_t begin = GetTickCount();
    result = ConnectAbilityFromRemote(*want, abilityInfo, connect, callerInfo, accountInfo);
    BehaviorEventParam eventParam = { EventCallingType::REMOTE, BehaviorEvent::CONNECT_REMOTE_ABILITY, result,
        want->GetElement().GetBundleName(), want->GetElement().GetAbilityName(), callerInfo.uid };
    DmsHiSysEventReport::ReportBehaviorEvent(eventParam);
    HILOGW("result = %{public}d", result);
    int64_t end = GetTickCount();
    PARCEL_WRITE_HELPER(reply, Int32, result);
    PARCEL_WRITE_HELPER(reply, Int64, end - begin);
    PARCEL_WRITE_HELPER(reply, String, package);
    PARCEL_WRITE_HELPER(reply, String, deviceId);
    return ERR_NONE;
}

int32_t DistributedSchedStub::DisconnectAbilityFromRemoteInner(MessageParcel& data, MessageParcel& reply)
{
    if (!CheckCallingUid()) {
        HILOGW("request DENIED!");
        return DMS_PERMISSION_DENIED;
    }

    sptr<IRemoteObject> connect = data.ReadRemoteObject();
    int32_t uid = 0;
    PARCEL_READ_HELPER(data, Int32, uid);
    string sourceDeviceId;
    PARCEL_READ_HELPER(data, String, sourceDeviceId);
    int32_t result = DisconnectAbilityFromRemote(connect, uid, sourceDeviceId);
    BehaviorEventParam eventParam = { EventCallingType::REMOTE, BehaviorEvent::DISCONNECT_REMOTE_ABILITY, result };
    DmsHiSysEventReport::ReportBehaviorEvent(eventParam);
    HILOGI("result %{public}d", result);
    PARCEL_WRITE_REPLY_NOERROR(reply, Int32, result);
}

int32_t DistributedSchedStub::NotifyProcessDiedFromRemoteInner(MessageParcel& data, MessageParcel& reply)
{
    if (!CheckCallingUid()) {
        HILOGW("request DENIED!");
        return DMS_PERMISSION_DENIED;
    }

    int32_t uid = 0;
    PARCEL_READ_HELPER(data, Int32, uid);
    int32_t pid = 0;
    PARCEL_READ_HELPER(data, Int32, pid);
    string sourceDeviceId;
    PARCEL_READ_HELPER(data, String, sourceDeviceId);
    CallerInfo callerInfo;
    callerInfo.uid = uid;
    callerInfo.pid = pid;
    callerInfo.sourceDeviceId = sourceDeviceId;
    callerInfo.callerType = CALLER_TYPE_HARMONY;
    int32_t result = NotifyProcessDiedFromRemote(callerInfo);
    HILOGI("result %{public}d", result);
    PARCEL_WRITE_REPLY_NOERROR(reply, Int32, result);
}

bool DistributedSchedStub::CheckCallingUid()
{
    // never allow non-system uid for distributed request
    auto callingUid = IPCSkeleton::GetCallingUid();
    return callingUid < HID_HAP;
}

bool DistributedSchedStub::EnforceInterfaceToken(MessageParcel& data)
{
    u16string interfaceToken = data.ReadInterfaceToken();
    return interfaceToken == DMS_STUB_INTERFACE_TOKEN;
}

#ifdef SUPPORT_DISTRIBUTED_MISSION_MANAGER
int32_t DistributedSchedStub::GetMissionInfosInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGI("[PerformanceTest] called, IPC end = %{public}" PRId64, GetTickCount());
    if (!DistributedSchedPermission::GetInstance().IsFoundationCall() &&
        !DistributedSchedPermission::GetInstance().IsSceneBoardCall()) {
        return DMS_PERMISSION_DENIED;
    }
    std::u16string deviceId = data.ReadString16();
    int32_t numMissions = 0;
    PARCEL_READ_HELPER(data, Int32, numMissions);

    std::vector<MissionInfo> missionInfos;
    int32_t result = GetMissionInfos(Str16ToStr8(deviceId), numMissions, missionInfos);
    HILOGI("result = %{public}d", result);
    if (result == ERR_NONE) {
        result = MissionInfoConverter::WriteMissionInfosToParcel(reply, missionInfos) ? ERR_NONE : ERR_FLATTEN_OBJECT;
    }
    return result;
}

int32_t DistributedSchedStub::GetRemoteMissionSnapshotInfoInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGI("[PerformanceTest] called, IPC end = %{public}" PRId64, GetTickCount());
    if (!DistributedSchedPermission::GetInstance().IsFoundationCall() &&
        !DistributedSchedPermission::GetInstance().IsSceneBoardCall()) {
        return DMS_PERMISSION_DENIED;
    }
    string networkId = data.ReadString();
    if (networkId.empty()) {
        HILOGE("networkId is empty!");
        return ERR_FLATTEN_OBJECT;
    }
    int32_t missionId = 0;
    PARCEL_READ_HELPER(data, Int32, missionId);
    if (missionId < 0) {
        HILOGE("missionId is invalid");
        return INVALID_PARAMETERS_ERR;
    }
    std::unique_ptr<MissionSnapshot> missionSnapshotPtr = std::make_unique<MissionSnapshot>();
    int32_t errCode = GetRemoteMissionSnapshotInfo(networkId, missionId, missionSnapshotPtr);
    if (errCode != ERR_NONE) {
        HILOGE("get mission snapshot failed!");
        return ERR_NULL_OBJECT;
    }
    PARCEL_WRITE_HELPER(reply, Parcelable, missionSnapshotPtr.get());
    std::string uuid = DnetworkAdapter::GetInstance()->GetUuidByNetworkId(networkId);
    if (uuid.empty()) {
        HILOGE("uuid is empty!");
        return ERR_NULL_OBJECT;
    }
    std::unique_ptr<Snapshot> snapshotPtr = make_unique<Snapshot>();
    SnapshotConverter::ConvertToSnapshot(*missionSnapshotPtr, snapshotPtr);
    DistributedSchedMissionManager::GetInstance().EnqueueCachedSnapshotInfo(uuid,
        missionId, std::move(snapshotPtr));
    return ERR_NONE;
}

int32_t DistributedSchedStub::RegisterMissionListenerInner(MessageParcel& data, MessageParcel& reply)
{
    if (!DistributedSchedPermission::GetInstance().IsFoundationCall()) {
        return DMS_PERMISSION_DENIED;
    }
    HILOGI("[PerformanceTest] called, IPC end = %{public}" PRId64, GetTickCount());
    u16string devId = data.ReadString16();
    if (devId.empty()) {
        HILOGW("read deviceId failed!");
        return INVALID_PARAMETERS_ERR;
    }
    sptr<IRemoteObject> missionChangedListener = data.ReadRemoteObject();
    if (missionChangedListener == nullptr) {
        HILOGW("read IRemoteObject failed!");
        return ERR_FLATTEN_OBJECT;
    }
    int32_t result = RegisterMissionListener(devId, missionChangedListener);
    PARCEL_WRITE_REPLY_NOERROR(reply, Int32, result);
}

int32_t DistributedSchedStub::RegisterDSchedEventListenerInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGI("[PerformanceTest] called, IPC end = %{public}" PRId64, GetTickCount());
    string type = data.ReadString();
    if (type.empty()) {
        HILOGW("read type failed!");
        return ERR_FLATTEN_OBJECT;
    }
    sptr<IRemoteObject> dSchedEventListener = data.ReadRemoteObject();
    if (dSchedEventListener == nullptr) {
        HILOGW("read IRemoteObject failed!");
        return ERR_FLATTEN_OBJECT;
    }
    int32_t result = RegisterDSchedEventListener(type, dSchedEventListener);
    PARCEL_WRITE_REPLY_NOERROR(reply, Int32, result);
}

int32_t DistributedSchedStub::UnRegisterDSchedEventListenerInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGI("[PerformanceTest] called, IPC end = %{public}" PRId64, GetTickCount());
    string type = data.ReadString();
    if (type.empty()) {
        HILOGW("read type failed!");
        return ERR_FLATTEN_OBJECT;
    }
    sptr<IRemoteObject> dSchedEventListener = data.ReadRemoteObject();
    if (dSchedEventListener == nullptr) {
        HILOGW("read IRemoteObject failed!");
        return ERR_FLATTEN_OBJECT;
    }
    int32_t result = UnRegisterDSchedEventListener(type, dSchedEventListener);
    PARCEL_WRITE_REPLY_NOERROR(reply, Int32, result);
}

int32_t DistributedSchedStub::RegisterOnListenerInner(MessageParcel& data, MessageParcel& reply)
{
    if (!DistributedSchedPermission::GetInstance().IsFoundationCall()) {
        return DMS_PERMISSION_DENIED;
    }
    HILOGI("[PerformanceTest] called, IPC end = %{public}" PRId64, GetTickCount());
    string type = data.ReadString();
    if (type.empty()) {
        HILOGW("read type failed!");
        return ERR_FLATTEN_OBJECT;
    }
    sptr<IRemoteObject> onListener = data.ReadRemoteObject();
    if (onListener == nullptr) {
        HILOGW("read IRemoteObject failed!");
        return ERR_FLATTEN_OBJECT;
    }
    int32_t result = RegisterOnListener(type, onListener);
    PARCEL_WRITE_REPLY_NOERROR(reply, Int32, result);
}

int32_t DistributedSchedStub::RegisterOffListenerInner(MessageParcel& data, MessageParcel& reply)
{
    if (!DistributedSchedPermission::GetInstance().IsFoundationCall()) {
        return DMS_PERMISSION_DENIED;
    }
    HILOGI("[PerformanceTest] called, IPC end = %{public}" PRId64, GetTickCount());
    string type = data.ReadString();
    if (type.empty()) {
        HILOGW("read type failed!");
        return ERR_FLATTEN_OBJECT;
    }
    sptr<IRemoteObject> onListener = data.ReadRemoteObject();
    if (onListener == nullptr) {
        HILOGW("read IRemoteObject failed!");
        return ERR_FLATTEN_OBJECT;
    }
    int32_t result = RegisterOffListener(type, onListener);
    PARCEL_WRITE_REPLY_NOERROR(reply, Int32, result);
}

int32_t DistributedSchedStub::UnRegisterMissionListenerInner(MessageParcel& data, MessageParcel& reply)
{
    if (!DistributedSchedPermission::GetInstance().IsFoundationCall()) {
        return DMS_PERMISSION_DENIED;
    }
    HILOGI("[PerformanceTest] called, IPC end = %{public}" PRId64, GetTickCount());
    u16string devId = data.ReadString16();
    if (devId.empty()) {
        HILOGW("read deviceId failed!");
        return INVALID_PARAMETERS_ERR;
    }
    sptr<IRemoteObject> missionChangedListener = data.ReadRemoteObject();
    if (missionChangedListener == nullptr) {
        HILOGW("read IRemoteObject failed!");
        return ERR_FLATTEN_OBJECT;
    }
    int32_t result = UnRegisterMissionListener(devId, missionChangedListener);
    PARCEL_WRITE_REPLY_NOERROR(reply, Int32, result);
}

int32_t DistributedSchedStub::StartSyncMissionsFromRemoteInner(MessageParcel& data, MessageParcel& reply)
{
    if (!CheckCallingUid()) {
        HILOGW("request DENIED!");
        return DMS_PERMISSION_DENIED;
    }
    CallerInfo callerInfo;
    if (!CallerInfoUnmarshalling(callerInfo, data)) {
        HILOGW("read callerInfo failed!");
        return ERR_FLATTEN_OBJECT;
    }
    std::vector<DstbMissionInfo> missionInfos;
    if (StartSyncMissionsFromRemote(callerInfo, missionInfos) != ERR_NONE) {
        return ERR_FLATTEN_OBJECT;
    }
    if (!reply.WriteInt32(VERSION)) {
        return ERR_FLATTEN_OBJECT;
    }
    if (!DstbMissionInfo::WriteDstbMissionInfosToParcel(reply, missionInfos)) {
        HILOGE("write mission info failed!");
        return ERR_FLATTEN_OBJECT;
    }
    return ERR_NONE;
}

int32_t DistributedSchedStub::StopSyncRemoteMissionsInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGI("[PerformanceTest] called, IPC end = %{public}" PRId64, GetTickCount());
    if (!DistributedSchedPermission::GetInstance().IsFoundationCall()) {
        return DMS_PERMISSION_DENIED;
    }
    u16string devId = data.ReadString16();
    if (devId.empty()) {
        HILOGW("read deviceId failed!");
        return INVALID_PARAMETERS_ERR;
    }
    int32_t result = StopSyncRemoteMissions(Str16ToStr8(devId));
    PARCEL_WRITE_REPLY_NOERROR(reply, Int32, result);
}

int32_t DistributedSchedStub::StopSyncMissionsFromRemoteInner(MessageParcel& data, MessageParcel& reply)
{
    if (!CheckCallingUid()) {
        HILOGW("request DENIED!");
        return DMS_PERMISSION_DENIED;
    }
    CallerInfo callerInfo;
    if (!CallerInfoUnmarshalling(callerInfo, data)) {
        HILOGW("read callerInfo failed!");
        return ERR_FLATTEN_OBJECT;
    }
    int32_t result = StopSyncMissionsFromRemote(callerInfo);
    PARCEL_WRITE_REPLY_NOERROR(reply, Int32, result);
}

int32_t DistributedSchedStub::NotifyMissionsChangedFromRemoteInner(MessageParcel& data, MessageParcel& reply)
{
    if (!CheckCallingUid()) {
        HILOGW("request DENIED!");
        return DMS_PERMISSION_DENIED;
    }
    int32_t version = data.ReadInt32();
    HILOGD("version is %{public}d", version);
    std::vector<DstbMissionInfo> missionInfos;
    if (!DstbMissionInfo::ReadDstbMissionInfosFromParcel(data, missionInfos)) {
        return ERR_FLATTEN_OBJECT;
    }
    CallerInfo callerInfo;
    callerInfo.sourceDeviceId = data.ReadString();
    callerInfo.uid = data.ReadInt32();
    callerInfo.pid = data.ReadInt32();
    callerInfo.dmsVersion = data.ReadInt32();
    int32_t result = NotifyMissionsChangedFromRemote(missionInfos, callerInfo);
    PARCEL_WRITE_REPLY_NOERROR(reply, Int32, result);
}

int32_t DistributedSchedStub::StartSyncRemoteMissionsInner(MessageParcel& data, MessageParcel& reply)
{
    if (!DistributedSchedPermission::GetInstance().IsFoundationCall()) {
        return DMS_PERMISSION_DENIED;
    }
    HILOGI("[PerformanceTest], IPC end = %{public}" PRId64, GetTickCount());
    u16string devId = data.ReadString16();
    if (devId.empty()) {
        HILOGW("read deviceId failed!");
        return INVALID_PARAMETERS_ERR;
    }
    string deviceId = Str16ToStr8(devId);
    bool fixConflict = data.ReadBool();
    int64_t tag = data.ReadInt64();
    int32_t result = StartSyncRemoteMissions(deviceId, fixConflict, tag);
    PARCEL_WRITE_REPLY_NOERROR(reply, Int32, result);
}

int32_t DistributedSchedStub::SetMissionContinueStateInner(MessageParcel& data, MessageParcel& reply)
{
    if (!CheckCallingUid() && !DistributedSchedPermission::GetInstance().IsSceneBoardCall()) {
        HILOGW("request DENIED!");
        return DMS_PERMISSION_DENIED;
    }

    int32_t missionId = 0;
    PARCEL_READ_HELPER(data, Int32, missionId);
    int32_t state = 0;
    PARCEL_READ_HELPER(data, Int32, state);

    int32_t result = SetMissionContinueState(missionId, static_cast<AAFwk::ContinueState>(state));
    HILOGI("result %{public}d", result);
    PARCEL_WRITE_REPLY_NOERROR(reply, Int32, result);
}
#endif

bool DistributedSchedStub::CallerInfoUnmarshalling(CallerInfo& callerInfo, MessageParcel& data)
{
    int32_t uid = -1;
    PARCEL_READ_HELPER_RET(data, Int32, uid, false);
    int32_t pid = -1;
    PARCEL_READ_HELPER_RET(data, Int32, pid, false);
    int32_t callerType = CALLER_TYPE_NONE;
    PARCEL_READ_HELPER_RET(data, Int32, callerType, false);
    std::string sourceDeviceId;
    PARCEL_READ_HELPER_RET(data, String, sourceDeviceId, false);
    HILOGI("sourceDeviceId = %{public}s",
        DnetworkAdapter::AnonymizeNetworkId(sourceDeviceId).c_str());
    int32_t duid = -1;
    PARCEL_READ_HELPER_RET(data, Int32, duid, false);
    std::string callerAppId;
    PARCEL_READ_HELPER_RET(data, String, callerAppId, false);
    int32_t version = -1;
    PARCEL_READ_HELPER_RET(data, Int32, version, false);
    callerInfo.uid = uid;
    callerInfo.pid = pid;
    callerInfo.callerType = callerType;
    callerInfo.sourceDeviceId = sourceDeviceId;
    callerInfo.duid = duid;
    callerInfo.callerAppId = callerAppId;
    callerInfo.dmsVersion = version;
    return true;
}

int32_t DistributedSchedStub::StartRemoteAbilityByCallInner(MessageParcel& data, MessageParcel& reply)
{
    if (!DistributedSchedPermission::GetInstance().IsFoundationCall()) {
        return DMS_PERMISSION_DENIED;
    }
    DmsHiTraceChain hiTraceChain(TraceValue::START_REMOTE_ABILITY_BYCALL);
    HITRACE_METER_NAME(TraceTag::DSCHED, TraceValue::START_REMOTE_ABILITY_BYCALL);
    shared_ptr<AAFwk::Want> want(data.ReadParcelable<AAFwk::Want>());
    if (want == nullptr) {
        HILOGW("want readParcelable failed!");
        return ERR_NULL_OBJECT;
    }
    sptr<IRemoteObject> connect = data.ReadRemoteObject();
    int32_t callerUid = 0;
    PARCEL_READ_HELPER(data, Int32, callerUid);
    int32_t callerPid = 0;
    PARCEL_READ_HELPER(data, Int32, callerPid);
    uint32_t accessToken = 0;
    PARCEL_READ_HELPER(data, Uint32, accessToken);
    if (DistributedSchedPermission::GetInstance().CheckPermission(accessToken,
        PERMISSION_DISTRIBUTED_DATASYNC) != ERR_OK) {
        HILOGE("check data_sync permission failed!");
        return DMS_PERMISSION_DENIED;
    }
    int32_t result = StartRemoteAbilityByCall(*want, connect, callerUid, callerPid, accessToken);
    ReportEvent(*want, BehaviorEvent::START_REMOTE_ABILITY_BYCALL, result, callerUid);
    HILOGI("result = %{public}d", result);
    PARCEL_WRITE_REPLY_NOERROR(reply, Int32, result);
}

int32_t DistributedSchedStub::ReleaseRemoteAbilityInner(MessageParcel& data, MessageParcel& reply)
{
    if (!DistributedSchedPermission::GetInstance().IsFoundationCall()) {
        return DMS_PERMISSION_DENIED;
    }
    DmsHiTraceChain hiTraceChain(TraceValue::RELEASE_REMOTE_ABILITY);
    HITRACE_METER_NAME(TraceTag::DSCHED, TraceValue::RELEASE_REMOTE_ABILITY);
    sptr<IRemoteObject> connect = data.ReadRemoteObject();
    shared_ptr<AppExecFwk::ElementName> element(data.ReadParcelable<AppExecFwk::ElementName>());
    if (element == nullptr) {
        HILOGE("ReleaseRemoteAbilityInner receive element is nullptr");
        return ERR_INVALID_VALUE;
    }
    int32_t result = ReleaseRemoteAbility(connect, *element);
    BehaviorEventParam eventParam = { EventCallingType::LOCAL, BehaviorEvent::RELEASE_REMOTE_ABILITY, result,
        element->GetBundleName(), element->GetAbilityName() };
    DmsHiSysEventReport::ReportBehaviorEvent(eventParam);
    HILOGI("result = %{public}d", result);
    PARCEL_WRITE_REPLY_NOERROR(reply, Int32, result);
}

int32_t DistributedSchedStub::StartAbilityByCallFromRemoteInner(MessageParcel& data, MessageParcel& reply)
{
    if (!CheckCallingUid()) {
        HILOGW("request DENIED!");
        return DMS_PERMISSION_DENIED;
    }

    sptr<IRemoteObject> connect = data.ReadRemoteObject();
    CallerInfo callerInfo;
    PARCEL_READ_HELPER(data, Int32, callerInfo.uid);
    PARCEL_READ_HELPER(data, Int32, callerInfo.pid);
    PARCEL_READ_HELPER(data, String, callerInfo.sourceDeviceId);
    AccountInfo accountInfo;
    accountInfo.accountType = data.ReadInt32();
    PARCEL_READ_HELPER(data, StringVector, &accountInfo.groupIdList);
    callerInfo.callerAppId = data.ReadString();
    std::string extraInfo = data.ReadString();
    if (extraInfo.empty()) {
        HILOGW("read extraInfo failed!");
        return ERR_NULL_OBJECT;
    }
    nlohmann::json extraInfoJson = nlohmann::json::parse(extraInfo, nullptr, false);
    if (!extraInfoJson.is_discarded()) {
        SaveExtraInfo(extraInfoJson, callerInfo);
        HILOGD("parse extra info");
    }
    shared_ptr<DistributedWant> dstbWant(data.ReadParcelable<DistributedWant>());
    shared_ptr<AAFwk::Want> want = nullptr;
    if (dstbWant != nullptr) {
        want = dstbWant->ToWant();
    }
    if (want == nullptr) {
        HILOGW("want readParcelable failed!");
        return ERR_NULL_OBJECT;
    }
    int32_t result = StartAbilityByCallFromRemote(*want, connect, callerInfo, accountInfo);
    BehaviorEventParam eventParam = { EventCallingType::REMOTE, BehaviorEvent::START_REMOTE_ABILITY_BYCALL, result,
        want->GetElement().GetBundleName(), want->GetElement().GetAbilityName(), callerInfo.uid };
    DmsHiSysEventReport::ReportBehaviorEvent(eventParam);
    HILOGI("result = %{public}d", result);
    PARCEL_WRITE_HELPER(reply, Int32, result);
    return ERR_NONE;
}

int32_t DistributedSchedStub::ReleaseAbilityFromRemoteInner(MessageParcel& data, MessageParcel& reply)
{
    if (!CheckCallingUid()) {
        HILOGW("request DENIED!");
        return DMS_PERMISSION_DENIED;
    }

    sptr<IRemoteObject> connect = data.ReadRemoteObject();
    shared_ptr<AppExecFwk::ElementName> element(data.ReadParcelable<AppExecFwk::ElementName>());
    if (element == nullptr) {
        HILOGE("ReleaseAbilityFromRemoteInner receive element is nullptr");
        return ERR_INVALID_VALUE;
    }
    CallerInfo callerInfo;
    PARCEL_READ_HELPER(data, String, callerInfo.sourceDeviceId);
    std::string extraInfo;
    PARCEL_READ_HELPER(data, String, extraInfo);
    int32_t result = ReleaseAbilityFromRemote(connect, *element, callerInfo);
    BehaviorEventParam eventParam = { EventCallingType::REMOTE, BehaviorEvent::RELEASE_REMOTE_ABILITY, result,
        element->GetBundleName(), element->GetAbilityName() };
    DmsHiSysEventReport::ReportBehaviorEvent(eventParam);
    HILOGI("result %{public}d", result);
    PARCEL_WRITE_REPLY_NOERROR(reply, Int32, result);
}

#ifdef SUPPORT_DISTRIBUTED_FORM_SHARE
int32_t DistributedSchedStub::StartRemoteShareFormInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGD("SHAREFORM:: func call");
    if (!DistributedSchedPermission::GetInstance().IsFoundationCall()) {
        return DMS_PERMISSION_DENIED;
    }

    std::string deviceId = "";
    PARCEL_READ_HELPER(data, String, deviceId);
    shared_ptr<AppExecFwk::FormShareInfo> formShareInfo(data.ReadParcelable<AppExecFwk::FormShareInfo>());
    if (formShareInfo == nullptr) {
        HILOGW("SHARE_FORM readParcelable failed!");
        PARCEL_WRITE_REPLY_NOERROR(reply, Int32, static_cast<int32_t>(ERR_FLATTEN_OBJECT));
        return ERR_FLATTEN_OBJECT;
    }

    int32_t result = StartRemoteShareForm(deviceId, *formShareInfo);
    HILOGI("result = %{public}d", result);
    PARCEL_WRITE_REPLY_NOERROR(reply, Int32, result);
}

int32_t DistributedSchedStub::StartShareFormFromRemoteInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGD("SHAREFORM:: func call");
    if (!CheckCallingUid()) {
        HILOGW("request DENIED!");
        PARCEL_WRITE_REPLY_NOERROR(reply, Int32, static_cast<int32_t>(DMS_PERMISSION_DENIED));
        return DMS_PERMISSION_DENIED;
    }

    std::string deviceId = "";
    PARCEL_READ_HELPER(data, String, deviceId);
    shared_ptr<AppExecFwk::FormShareInfo> formShareInfo(data.ReadParcelable<AppExecFwk::FormShareInfo>());
    if (formShareInfo == nullptr) {
        HILOGW("SHARE_FORM readParcelable failed!");
        PARCEL_WRITE_REPLY_NOERROR(reply, Int32, static_cast<int32_t>(ERR_FLATTEN_OBJECT));
        return ERR_FLATTEN_OBJECT;
    }

    int32_t result = StartShareFormFromRemote(deviceId, *formShareInfo);
    HILOGI("result = %{public}d", result);
    PARCEL_WRITE_REPLY_NOERROR(reply, Int32, result);
}
#endif

int32_t DistributedSchedStub::GetDistributedComponentListInner(MessageParcel& data, MessageParcel& reply)
{
    if (!CheckCallingUid()) {
        HILOGW("request DENIED!");
        return DMS_PERMISSION_DENIED;
    }
    std::vector<std::string> distributedComponents;
    int32_t result = GetDistributedComponentList(distributedComponents);
    HILOGI("result = %{public}d", result);
    PARCEL_WRITE_HELPER(reply, Int32, result);
    PARCEL_WRITE_HELPER(reply, StringVector, distributedComponents);
    return ERR_NONE;
}

int32_t DistributedSchedStub::NotifyStateChangedFromRemoteInner(MessageParcel& data, MessageParcel& reply)
{
    if (!CheckCallingUid()) {
        HILOGW("request DENIED!");
        return DMS_PERMISSION_DENIED;
    }
    int32_t abilityState = 0;
    PARCEL_READ_HELPER(data, Int32, abilityState);
    int32_t connectToken = 0;
    PARCEL_READ_HELPER(data, Int32, connectToken);
    shared_ptr<AppExecFwk::ElementName> element(data.ReadParcelable<AppExecFwk::ElementName>());
    if (element == nullptr) {
        HILOGE("NotifyStateChangedFromRemoteInner receive element is nullptr");
        return ERR_INVALID_VALUE;
    }
    int32_t result = NotifyStateChangedFromRemote(abilityState, connectToken, *element);
    HILOGI("result = %{public}d", result);
    PARCEL_WRITE_HELPER(reply, Int32, result);
    return ERR_NONE;
}

int32_t DistributedSchedStub::StartRemoteFreeInstallInner(MessageParcel& data, MessageParcel& reply)
{
    if (!DistributedSchedPermission::GetInstance().IsFoundationCall()) {
        return DMS_PERMISSION_DENIED;
    }
    shared_ptr<AAFwk::Want> want(data.ReadParcelable<AAFwk::Want>());
    if (want == nullptr) {
        HILOGE("want readParcelable failed!");
        return ERR_NULL_OBJECT;
    }
    int32_t callerUid = 0;
    int32_t requestCode = 0;
    uint32_t accessToken = 0;
    PARCEL_READ_HELPER(data, Int32, callerUid);
    PARCEL_READ_HELPER(data, Int32, requestCode);
    PARCEL_READ_HELPER(data, Uint32, accessToken);
    sptr<IRemoteObject> callback = data.ReadRemoteObject();
    if (callback == nullptr) {
        HILOGE("read callback failed!");
        return ERR_NULL_OBJECT;
    }
    if (DistributedSchedPermission::GetInstance().CheckPermission(accessToken,
        PERMISSION_DISTRIBUTED_DATASYNC) != ERR_OK) {
        HILOGE("check data_sync permission failed!");
        return DMS_PERMISSION_DENIED;
    }
    int32_t result = StartRemoteFreeInstall(*want, callerUid, requestCode, accessToken, callback);
    HILOGI("result = %{public}d", result);
    PARCEL_WRITE_REPLY_NOERROR(reply, Int32, result);
    return ERR_NONE;
}

int32_t DistributedSchedStub::ReadDataForFreeInstall(MessageParcel& data, CallerInfo &callerInfo,
    AccountInfo &accountInfo, int64_t &taskId)
{
    callerInfo.callerType = CALLER_TYPE_HARMONY;
    PARCEL_READ_HELPER(data, Int32, callerInfo.uid);
    PARCEL_READ_HELPER(data, String, callerInfo.sourceDeviceId);
    accountInfo.accountType = data.ReadInt32();
    PARCEL_READ_HELPER(data, StringVector, &accountInfo.groupIdList);
    callerInfo.callerAppId = data.ReadString();
    PARCEL_READ_HELPER(data, Int64, taskId);
    return ERR_NONE;
}

int32_t DistributedSchedStub::StartFreeInstallFromRemoteInner(MessageParcel& data, MessageParcel& reply)
{
    if (!CheckCallingUid()) {
        HILOGW("request DENIED!");
        return DMS_PERMISSION_DENIED;
    }
    shared_ptr<AAFwk::Want> want = ReadDistributedWant(data);
    if (want == nullptr) {
        HILOGE("want readParcelable failed!");
        return ERR_NULL_OBJECT;
    }
    int64_t begin = GetTickCount();
    CallerInfo callerInfo = {.accessToken = 0};
    AccountInfo accountInfo = {};
    int64_t taskId = 0;
    int32_t result = ReadDataForFreeInstall(data, callerInfo, accountInfo, taskId);
    if (result != ERR_NONE) {
        return result;
    }
    shared_ptr<DistributedWant> cmpDstbWant(data.ReadParcelable<DistributedWant>());
    shared_ptr<AAFwk::Want> cmpWant = nullptr;
    if (cmpDstbWant != nullptr) {
        cmpWant = cmpDstbWant->ToWant();
    }
    std::string extraInfo = data.ReadString();
    if (extraInfo.empty()) {
        HILOGD("extra info is empty!");
    }
    nlohmann::json extraInfoJson = nlohmann::json::parse(extraInfo, nullptr, false);
    int32_t requestCode = DEFAULT_REQUEST_CODE;
    if (!extraInfoJson.is_discarded()) {
        SaveExtraInfo(extraInfoJson, callerInfo);
        if (extraInfoJson.find(EXTRO_INFO_JSON_KEY_REQUEST_CODE) != extraInfoJson.end() &&
            extraInfoJson[EXTRO_INFO_JSON_KEY_REQUEST_CODE].is_number_integer()) {
            requestCode = extraInfoJson[EXTRO_INFO_JSON_KEY_REQUEST_CODE];
            HILOGD("parse extra info, requestCode = %d", requestCode);
        }
    }
    FreeInstallInfo info = {
        .want = *want, .callerInfo = callerInfo, .accountInfo = accountInfo, .requestCode = requestCode};
    info.want.SetParam(PARAM_FREEINSTALL_APPID, callerInfo.callerAppId);
    info.want.SetParam(
        PARAM_FREEINSTALL_BUNDLENAMES, (*cmpWant).GetStringArrayParam(CMPT_PARAM_FREEINSTALL_BUNDLENAMES));
    result = StartFreeInstallFromRemote(info, taskId);
    HILOGI("result = %{public}d", result);
    PARCEL_WRITE_HELPER(reply, Int32, result);
    int64_t end = GetTickCount();
    PARCEL_WRITE_HELPER(reply, Int64, end - begin);
    return ERR_NONE;
}

int32_t DistributedSchedStub::NotifyCompleteFreeInstallFromRemoteInner(MessageParcel& data, MessageParcel& reply)
{
    if (!CheckCallingUid()) {
        HILOGW("request DENIED!");
        return DMS_PERMISSION_DENIED;
    }
    int64_t taskId = 0;
    int32_t resultCode = 0;
    PARCEL_READ_HELPER(data, Int64, taskId);
    PARCEL_READ_HELPER(data, Int32, resultCode);
    int32_t result = NotifyCompleteFreeInstallFromRemote(taskId, resultCode);
    HILOGI("result = %{public}d", result);
    PARCEL_WRITE_REPLY_NOERROR(reply, Int32, result);
}

int32_t DistributedSchedStub::StopRemoteExtensionAbilityInner(MessageParcel& data, MessageParcel& reply)
{
    if (!DistributedSchedPermission::GetInstance().IsFoundationCall()) {
        HILOGW("request DENIED!");
        return DMS_PERMISSION_DENIED;
    }
    shared_ptr<AAFwk::Want> want(data.ReadParcelable<AAFwk::Want>());
    if (want == nullptr) {
        HILOGW("Stop reomte extension ability want readParcelable failed!");
        return ERR_NULL_OBJECT;
    }
    int32_t callerUid = 0;
    PARCEL_READ_HELPER(data, Int32, callerUid);
    uint32_t accessToken = 0;
    PARCEL_READ_HELPER(data, Uint32, accessToken);
    int32_t serviceType = 0;
    PARCEL_READ_HELPER(data, Int32, serviceType);
    HILOGD("get callerUid = %{private}d, AccessTokenID = %{private}u", callerUid, accessToken);
    if (DistributedSchedPermission::GetInstance().CheckPermission(accessToken,
        PERMISSION_DISTRIBUTED_DATASYNC) != ERR_OK) {
        HILOGE("check data_sync permission failed!");
        return DMS_PERMISSION_DENIED;
    }
    auto result = StopRemoteExtensionAbility(*want, callerUid, accessToken, serviceType);
    HILOGD("StartRemoteAbilityInner result = %{public}d", result);
    PARCEL_WRITE_REPLY_NOERROR(reply, Int32, result);
}

int32_t DistributedSchedStub::StopExtensionAbilityFromRemoteInner(MessageParcel& data, MessageParcel& reply)
{
    if (!CheckCallingUid()) {
        HILOGW("request DENIED!");
        return DMS_PERMISSION_DENIED;
    }
    shared_ptr<DistributedWant> dstbWant(data.ReadParcelable<DistributedWant>());
    shared_ptr<AAFwk::Want> want = nullptr;
    if (dstbWant != nullptr) {
        want = dstbWant->ToWant();
    }
    if (want == nullptr) {
        HILOGW("want readParcelable failed!");
        return ERR_NULL_OBJECT;
    }
    int32_t serviceType = 0;
    PARCEL_READ_HELPER(data, Int32, serviceType);
    CallerInfo callerInfo;
    PARCEL_READ_HELPER(data, Int32, callerInfo.uid);
    PARCEL_READ_HELPER(data, String, callerInfo.sourceDeviceId);
    callerInfo.callerType = CALLER_TYPE_HARMONY;
    AccountInfo accountInfo;
    accountInfo.accountType = data.ReadInt32();
    PARCEL_READ_HELPER(data, StringVector, &accountInfo.groupIdList);
    callerInfo.callerAppId = data.ReadString();
    std::string extraInfo = data.ReadString();
    if (extraInfo.empty()) {
        HILOGD("extra info is empty!");
    }
    nlohmann::json extraInfoJson = nlohmann::json::parse(extraInfo, nullptr, false);
    if (!extraInfoJson.is_discarded() && extraInfoJson.find(EXTRO_INFO_JSON_KEY_ACCESS_TOKEN) != extraInfoJson.end() &&
        extraInfoJson[EXTRO_INFO_JSON_KEY_ACCESS_TOKEN].is_number_unsigned()) {
        uint32_t accessToken = extraInfoJson[EXTRO_INFO_JSON_KEY_ACCESS_TOKEN];
        callerInfo.accessToken = accessToken;
        HILOGD("parse extra info, accessTokenID = %{private}u", accessToken);
    }
    auto result = StopExtensionAbilityFromRemote(*want, callerInfo, accountInfo, serviceType);
    HILOGD("result = %{public}d", result);
    PARCEL_WRITE_HELPER(reply, Int32, result);
    return ERR_NONE;
}
} // namespace DistributedSchedule
} // namespace OHOS
