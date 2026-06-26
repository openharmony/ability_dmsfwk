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

#include "distributed_intent_service_stub.h"
#include "distributed_intent_error_code.h"
#include "distributed_intent_provider.h"
#include "dtbschedmgr_log.h"
#include "parcel.h"
#include "parcel_helper.h"
#include "string_ex.h"
#include "want.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "DistributedIntentServiceStub";
const std::u16string INTENT_SERVICE_INTERFACE_TOKEN = u"ohos.distributedschedule.accessToken";
}

IIntentProvider* DistributedIntentServiceStub::provider_ = nullptr;
std::mutex DistributedIntentServiceStub::providerMutex_;

void DistributedIntentServiceStub::SetProvider(IIntentProvider* provider)
{
    std::lock_guard<std::mutex> lock(providerMutex_);
    provider_ = provider;
}

IIntentProvider* DistributedIntentServiceStub::GetProvider()
{
    std::lock_guard<std::mutex> lock(providerMutex_);
    return provider_;
}

DistributedIntentServiceStub::DistributedIntentServiceStub()
{
    requestHandlers_[static_cast<uint32_t>(IDSchedInterfaceCode::START_REMOTE_INTENT)] =
        &DistributedIntentServiceStub::StartRemoteIntentInner;
    requestHandlers_[static_cast<uint32_t>(IDSchedInterfaceCode::SEND_INTENT_RESULT)] =
        &DistributedIntentServiceStub::SendIntentResultInner;
}

int32_t DistributedIntentServiceStub::OnRemoteRequest(
    uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option)
{
    std::u16string interfaceToken = data.ReadInterfaceToken();
    if (interfaceToken != INTENT_SERVICE_INTERFACE_TOKEN) {
        HILOGE("InterfaceToken verify failed");
        return ERR_TRANSACTION_FAILED;
    }
    auto it = requestHandlers_.find(code);
    if (it != requestHandlers_.end()) {
        return (this->*(it->second))(data, reply);
    }
    HILOGE("%{public}s unknown code=%{public}u", TAG.c_str(), code);
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int32_t DistributedIntentServiceStub::StartRemoteIntent(const OHOS::AAFwk::Want& want,
    const IntentCallerInfo& callerInfo, const sptr<IRemoteObject>& resultCallback)
{
    return ERR_DI_NOT_SYSTEM_APP;
}

int32_t DistributedIntentServiceStub::SendIntentResult(const OHOS::AAFwk::Want& want,
    const IntentCallerInfo& callerInfo, const std::string& resultMsg)
{
    return ERR_DI_NOT_SYSTEM_APP;
}

int32_t DistributedIntentServiceStub::StartRemoteIntentInner(MessageParcel& data, MessageParcel& reply)
{
    if (provider_ == nullptr || !provider_->IsFoundationCall()) {
        return ERR_DI_PERMISSION_DENIED;
    }

    std::shared_ptr<AAFwk::Want> want(data.ReadParcelable<AAFwk::Want>());
    if (want == nullptr) {
        HILOGE("Read want failed");
        return ERR_NULL_OBJECT;
    }
    provider_->RemoveRemoteObjectFromWant(want);
    std::string moduleName = data.ReadString();
    want->SetModuleName(moduleName);
    int32_t callerUid = 0;
    PARCEL_READ_HELPER(data, Int32, callerUid);
    uint64_t requestCode = 0;
    PARCEL_READ_HELPER(data, Uint64, requestCode);
    uint32_t accessToken = 0;
    PARCEL_READ_HELPER(data, Uint32, accessToken);
    uint32_t specifyTokenId = 0;
    PARCEL_READ_HELPER(data, Uint32, specifyTokenId);

    sptr<IRemoteObject> resultCallback = data.ReadRemoteObject();
    if (resultCallback == nullptr) {
        HILOGE("resultCallback is null");
        return ERR_NULL_OBJECT;
    }
    provider_->MarkUriPermission(*want, accessToken);

    IntentCallerInfo callerInfo;
    callerInfo.callerUid = callerUid;
    callerInfo.requestCode = requestCode;
    callerInfo.accessToken = accessToken;
    callerInfo.specifyTokenId = specifyTokenId;
    HILOGI("requestCode=%{public}" PRIu64 "", requestCode);

    int32_t result = StartRemoteIntent(*want, callerInfo, resultCallback);

    PARCEL_WRITE_REPLY_NOERROR(reply, Int32, result);
}

int32_t DistributedIntentServiceStub::SendIntentResultInner(MessageParcel& data, MessageParcel& reply)
{
    if (provider_ == nullptr || !provider_->IsFoundationCall()) {
        return ERR_DI_PERMISSION_DENIED;
    }

    std::shared_ptr<AAFwk::Want> want(data.ReadParcelable<AAFwk::Want>());
    if (want == nullptr) {
        HILOGE("Read want failed");
        return ERR_NULL_OBJECT;
    }

    int32_t callerUid = 0;
    PARCEL_READ_HELPER(data, Int32, callerUid);
    uint64_t requestCode = 0;
    PARCEL_READ_HELPER(data, Uint64, requestCode);
    uint32_t accessToken = 0;
    PARCEL_READ_HELPER(data, Uint32, accessToken);
    uint32_t specifyTokenId = 0;
    PARCEL_READ_HELPER(data, Uint32, specifyTokenId);

    std::string resultMsg = data.ReadString();

    IntentCallerInfo callerInfo;
    callerInfo.callerUid = callerUid;
    callerInfo.requestCode = requestCode;
    callerInfo.accessToken = accessToken;
    callerInfo.specifyTokenId = specifyTokenId;
    HILOGI("requestCode=%{public}" PRIu64, requestCode);

    int32_t result = SendIntentResult(*want, callerInfo, resultMsg);
    PARCEL_WRITE_REPLY_NOERROR(reply, Int32, result);
}

} // namespace DistributedSchedule
} // namespace OHOS
