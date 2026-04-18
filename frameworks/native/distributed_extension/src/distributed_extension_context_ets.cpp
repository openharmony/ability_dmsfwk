/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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
#include "distributed_extension_context_ets.h"

#include "ani_common_want.h"
#include "ani_common_util.h"
#include "distributed_extension.h"
#include "distributed_extension_error_utils.h"
#include "dtbschedmgr_log.h"
#include "ets_context_utils.h"
#include "ets_error_utils.h"
#include "ets_extension_context.h"
#include "remote_object_taihe_ani.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "DistributedExtensionContextETS";
constexpr const char *DISTRIBUTED_EXTENSION_CONTEXT_CLASS_NAME =
    "@ohos.application.DistributedExtensionContext.DistributedExtensionContext";
constexpr const char *CLEANER_CLASS_NAME = "@ohos.application.DistributedExtensionContext.Cleaner";
constexpr const int ANI_ALREADY_BINDED = 8;
constexpr const int FAILED_CODE = -1;
constexpr const char *SIGNATURE_CONNECT_SERVICE_EXTENSION =
    "C{@ohos.app.ability.Want.Want}C{ability.connectOptions.ConnectOptions}:l";
constexpr const char *SIGNATURE_DISCONNECT_SERVICE_EXTENSION = "lC{utils.AbilityUtils.AsyncCallbackWrapper}:";
constexpr int32_t ARGC_ONE = 1;
constexpr int32_t ARGC_TWO = 2;

std::recursive_mutex g_connectsLock;
int64_t g_serialNumber = 0;
static std::map<ETSConnectionKey, sptr<DistributedExtensionContextETSConnection>, ets_key_compare> g_connects;

int32_t InsertConnection(sptr<DistributedExtensionContextETSConnection> connection, const AAFwk::Want &want)
{
    std::lock_guard<std::recursive_mutex> lock(g_connectsLock);
    if (connection == nullptr) {
        HILOG_ERROR("null connection");
        return -1;
    }
    int32_t connectId = static_cast<int32_t>(g_serialNumber);
    ETSConnectionKey key;
    key.id = g_serialNumber;
    key.want = want;
    connection->SetConnectionId(key.id);
    g_connects.emplace(key, connection);
    g_serialNumber++;
    return connectId;
}

void RemoveConnection(int32_t connectId)
{
    std::lock_guard<std::recursive_mutex> lock(g_connectsLock);
    auto item = std::find_if(g_connects.begin(), g_connects.end(),
    [&connectId](const auto &obj) {
        return connectId == obj.first.id;
    });
    if (item != g_connects.end()) {
        HILOG_INFO("remove connection ability exist");
        if (item->second) {
            item->second->RemoveConnectionObject();
        }
        g_connects.erase(item);
    } else {
        HILOG_INFO("remove connection ability not exist");
    }
}
} // namespace

bool BindNativeMethods(ani_env *env, ani_class &cls)
{
    ani_status status = ANI_ERROR;
    std::array functions = {
        ani_native_function { "nativeConnectServiceExtensionAbility", SIGNATURE_CONNECT_SERVICE_EXTENSION,
            reinterpret_cast<void *>(DistributedExtensionContextETS::ConnectServiceExtensionAbility) },
        ani_native_function { "nativeDisconnectServiceExtensionAbility", SIGNATURE_DISCONNECT_SERVICE_EXTENSION,
            reinterpret_cast<void *>(DistributedExtensionContextETS::DisconnectServiceExtensionAbility) },
    };
    if ((status = env->Class_BindNativeMethods(cls, functions.data(), functions.size())) != ANI_OK
        && status != ANI_ALREADY_BINDED) {
        HILOG_ERROR("bind method status: %{public}d", status);
        return false;
    }
    ani_class cleanerCls = nullptr;
    status = env->FindClass(CLEANER_CLASS_NAME, &cleanerCls);
    if (status != ANI_OK || cleanerCls == nullptr) {
        HILOG_ERROR("Failed to find class, status: %{public}d", status);
        return false;
    }
    std::array CleanerMethods = {
        ani_native_function { "clean", nullptr, reinterpret_cast<void *>(DistributedExtensionContextETS::Finalizer) },
    };
    if ((status = env->Class_BindNativeMethods(cleanerCls, CleanerMethods.data(), CleanerMethods.size())) != ANI_OK
        && status != ANI_ALREADY_BINDED) {
        HILOG_ERROR("bind method status: %{public}d", status);
        return false;
    }
    return true;
}

ani_object CreateDistributedExtensionContextETS(ani_env *env, std::shared_ptr<DistributedExtensionContext> &context)
{
    HILOG_INFO("CreateDistributedExtensionContextETS call");
    if (env == nullptr || context == nullptr) {
        HILOG_ERROR("null env or context");
        return nullptr;
    }
    ani_class cls = nullptr;
    ani_status status = ANI_ERROR;
    if ((status = env->FindClass(DISTRIBUTED_EXTENSION_CONTEXT_CLASS_NAME, &cls)) != ANI_OK || cls == nullptr) {
        HILOG_ERROR("Failed to find class, status: %{public}d", status);
        return nullptr;
    }
    if (!BindNativeMethods(env, cls)) {
        HILOG_ERROR("Failed to BindNativeMethods");
        return nullptr;
    }
    ani_method method = nullptr;
    if ((status = env->Class_FindMethod(cls, "<ctor>", "l:", &method)) != ANI_OK || method == nullptr) {
        HILOG_ERROR("Failed to find constructor, status : %{public}d", status);
        return nullptr;
    }
    std::unique_ptr<DistributedExtensionContextETS> workContext = std::make_unique<DistributedExtensionContextETS>(
        context);
    if (workContext == nullptr) {
        HILOG_ERROR("Failed to create DistributedExtensionContextETS");
        return nullptr;
    }
    auto distributeContextPtr = new std::weak_ptr<DistributedExtensionContext>(workContext->GetAbilityContext());
    if (distributeContextPtr == nullptr) {
        HILOG_ERROR("distributeContextPtr is nullptr");
        return nullptr;
    }
    ani_object contextObj = nullptr;
    if ((status = env->Object_New(cls, method, &contextObj, (ani_long)workContext.release())) != ANI_OK ||
        contextObj == nullptr) {
        HILOG_ERROR("Failed to create object, status : %{public}d", status);
        delete distributeContextPtr;
        distributeContextPtr = nullptr;
        return nullptr;
    }
    if (!ContextUtil::SetNativeContextLong(env, contextObj, (ani_long)(distributeContextPtr))) {
        HILOG_ERROR("Failed to setNativeContextLong ");
        delete distributeContextPtr;
        distributeContextPtr = nullptr;
        return nullptr;
    }
    ContextUtil::CreateEtsBaseContext(env, cls, contextObj, context);
    CreateEtsExtensionContext(env, cls, contextObj, context, context->GetAbilityInfo());
    return contextObj;
}

void DistributedExtensionContextETS::Finalizer(ani_env *env, ani_object obj)
{
    HILOG_INFO("Finalizer");
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return;
    }
    ani_long nativeEtsContextPtr;
    if (env->Object_GetFieldByName_Long(obj, "nativeEtsContext", &nativeEtsContextPtr) != ANI_OK) {
        HILOG_ERROR("Failed to get nativeEtsContext");
        return;
    }
    if (nativeEtsContextPtr != 0) {
        delete reinterpret_cast<DistributedExtensionContextETS *>(nativeEtsContextPtr);
    }
}

DistributedExtensionContextETS *DistributedExtensionContextETS::GetEtsAbilityContext(ani_env *env, ani_object obj)
{
    HILOG_INFO("GetEtsAbilityContext");
    ani_class cls = nullptr;
    ani_long nativeContextLong = 0;
    ani_field contextField = nullptr;
    ani_status status = ANI_ERROR;
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return nullptr;
    }
    if ((status = env->FindClass(DISTRIBUTED_EXTENSION_CONTEXT_CLASS_NAME, &cls)) != ANI_OK) {
        HILOG_ERROR("Failed to find class, status: %{public}d", status);
        return nullptr;
    }
    if ((status = env->Class_FindField(cls, "nativeEtsContext", &contextField)) != ANI_OK) {
        HILOG_ERROR("Failed to find field, status: %{public}d", status);
        return nullptr;
    }
    if ((status = env->Object_GetField_Long(obj, contextField, &nativeContextLong)) != ANI_OK) {
        HILOG_ERROR("Failed to get field, status: %{public}d", status);
        return nullptr;
    }
    return reinterpret_cast<DistributedExtensionContextETS *>(nativeContextLong);
}

// static dispatcher
ani_long DistributedExtensionContextETS::ConnectServiceExtensionAbility(ani_env *env, ani_object aniObj,
    ani_object wantObj, ani_object connectOptionsObj)
{
    HILOG_INFO("ConnectServiceExtensionAbility");
    if (env == nullptr) {
        HILOG_ERROR("null env");
        EtsErrorUtil::ThrowError(env, ToInt32(DistributedErrorCode::ERROR_CODE_INNER),
            GetErrorMsg(DistributedErrorCode::ERROR_CODE_INNER));
        return FAILED_CODE;
    }
    auto etsContext = DistributedExtensionContextETS::GetEtsAbilityContext(env, aniObj);
    if (etsContext == nullptr) {
        HILOG_ERROR("null etsContext");
        EtsErrorUtil::ThrowError(env, ToInt32(DistributedErrorCode::ERROR_CODE_INNER),
            GetErrorMsg(DistributedErrorCode::ERROR_CODE_INNER));
        return FAILED_CODE;
    }
    return etsContext->OnConnectServiceExtensionAbility(env, aniObj, wantObj, connectOptionsObj);
}

// static dispatcher
void DistributedExtensionContextETS::DisconnectServiceExtensionAbility(ani_env *env, ani_object aniObj,
    ani_long connectId, ani_object callback)
{
    HILOG_INFO("DisconnectServiceExtensionAbility");
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return;
    }
    auto etsContext = DistributedExtensionContextETS::GetEtsAbilityContext(env, aniObj);
    if (etsContext == nullptr) {
        HILOG_ERROR("null etsContext");
        return;
    }
    etsContext->OnDisconnectServiceExtensionAbility(env, aniObj, connectId, callback);
}

ani_long DistributedExtensionContextETS::OnConnectServiceExtensionAbility(ani_env *env, ani_object aniObj,
    ani_object wantObj, ani_object connectOptionsObj)
{
    HILOG_INFO("OnConnectServiceExtensionAbility call");
    if (env == nullptr) {
        HILOG_ERROR("null env");
        EtsErrorUtil::ThrowError(env, ToInt32(DistributedErrorCode::ERROR_CODE_INNER),
            GetErrorMsg(DistributedErrorCode::ERROR_CODE_INNER));
        return FAILED_CODE;
    }
    AAFwk::Want want;
    if (!OHOS::AppExecFwk::UnwrapWant(env, wantObj, want)) {
        HILOG_ERROR("Failed to UnwrapWant");
        EtsErrorUtil::ThrowError(env, ToInt32(DistributedErrorCode::ERROR_CODE_INVALID_PARAM),
            GetErrorMsg(DistributedErrorCode::ERROR_CODE_INVALID_PARAM));
        return FAILED_CODE;
    }
    ani_vm *etsVm = nullptr;
    if (env->GetVM(&etsVm) != ANI_OK || etsVm == nullptr) {
        HILOG_ERROR("Failed to getVM");
        EtsErrorUtil::ThrowError(env, ToInt32(DistributedErrorCode::ERROR_CODE_INNER),
            GetErrorMsg(DistributedErrorCode::ERROR_CODE_INNER));
        return FAILED_CODE;
    }
    sptr<DistributedExtensionContextETSConnection> connection =
        sptr<DistributedExtensionContextETSConnection>::MakeSptr(etsVm);
    if (connection == nullptr) {
        HILOG_ERROR("Failed to create connection");
        EtsErrorUtil::ThrowError(env, ToInt32(DistributedErrorCode::ERROR_CODE_INNER),
            GetErrorMsg(DistributedErrorCode::ERROR_CODE_INNER));
        return FAILED_CODE;
    }
    connection->SetConnectionRef(connectOptionsObj);
    int32_t connectId = InsertConnection(connection, want);
    auto context = context_.lock();
    if (context == nullptr) {
        HILOG_ERROR("null context");
        RemoveConnection(connectId);
        EtsErrorUtil::ThrowError(env, ToInt32(DistributedErrorCode::ERROR_CODE_INVALID_CONTEXT),
            GetErrorMsg(DistributedErrorCode::ERROR_CODE_INVALID_CONTEXT));
        return FAILED_CODE;
    }
    auto result = context->ConnectAbility(want, connection);
    if (result != ERR_OK) {
        auto jsErrCode = GetJsErrorCodeByNativeError(result);
        connection->CallEtsFailed(ToInt32(jsErrCode));
        RemoveConnection(connectId);
    }
    return connectId;
}

void DistributedExtensionContextETS::OnDisconnectServiceExtensionAbility(ani_env *env, ani_object aniObj,
    ani_long connectId, ani_object callback)
{
    HILOG_INFO("OnDisconnectServiceExtensionAbility call");
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return;
    }
    auto context = context_.lock();
    ani_object errorObject = nullptr;
    if (context == nullptr) {
        HILOG_ERROR("null context");
        errorObject = EtsErrorUtil::CreateError(env,
            ToInt32(DistributedErrorCode::ERROR_CODE_INVALID_CONTEXT),
            GetErrorMsg(DistributedErrorCode::ERROR_CODE_INVALID_CONTEXT));
        AppExecFwk::AsyncCallback(env, callback, errorObject, nullptr);
        return;
    }
    sptr<DistributedExtensionContextETSConnection> connection = nullptr;
    AAFwk::Want want;
    {
        std::lock_guard<std::recursive_mutex> lock(g_connectsLock);
        auto iter = std::find_if(
            g_connects.begin(), g_connects.end(),
            [&connectId](const auto &obj) { return connectId == obj.first.id; });
        if (iter != g_connects.end()) {
            want = iter->first.want;
            connection = iter->second;
            g_connects.erase(iter);
        } else {
            HILOG_INFO("Failed to found connection");
        }
    }
    if (!connection) {
        errorObject = EtsErrorUtil::CreateError(env,
            ToInt32(DistributedErrorCode::ERROR_CODE_INVALID_CONTEXT),
            GetErrorMsg(DistributedErrorCode::ERROR_CODE_INVALID_CONTEXT));
        AppExecFwk::AsyncCallback(env, callback, errorObject, nullptr);
        return;
    }
    auto errcode = context->DisconnectAbility(want, connection);
    if (errcode == 0) {
        AppExecFwk::AsyncCallback(env, callback,
            EtsErrorUtil::CreateError(env, static_cast<int32_t>(DistributedErrorCode::ERROR_OK),
                GetErrorMsg(DistributedErrorCode::ERROR_OK)), nullptr);
    } else {
        auto jsErrCode = GetJsErrorCodeByNativeError(errcode);
        errorObject = EtsErrorUtil::CreateError(env, ToInt32(jsErrCode), GetErrorMsg(jsErrCode));
        AppExecFwk::AsyncCallback(env, callback, errorObject, nullptr);
    }
}

// --- DistributedExtensionContextETSConnection implementation ---

DistributedExtensionContextETSConnection::DistributedExtensionContextETSConnection(ani_vm *etsVm) : etsVm_(etsVm) {}

DistributedExtensionContextETSConnection::~DistributedExtensionContextETSConnection()
{
    RemoveConnectionObject();
}

void DistributedExtensionContextETSConnection::SetConnectionId(int32_t id)
{
    connectionId_ = id;
}

void DistributedExtensionContextETSConnection::RemoveConnectionObject()
{
    if (etsVm_ != nullptr && etsConnectionRef_ != nullptr) {
        ani_env *env = nullptr;
        if (etsVm_->GetEnv(ANI_VERSION_1, &env) == ANI_OK && env != nullptr) {
            env->GlobalReference_Delete(etsConnectionRef_);
            etsConnectionRef_ = nullptr;
        }
    }
}

void DistributedExtensionContextETSConnection::CallEtsFailed(int32_t errorCode)
{
    HILOG_INFO("CallEtsFailed");
    if (etsVm_ == nullptr) {
        HILOG_ERROR("null etsVm");
        return;
    }
    if (etsConnectionRef_ == nullptr) {
        HILOG_ERROR("null etsConnectionRef_");
        return;
    }
    ani_env *env = nullptr;
    ani_status status = ANI_OK;
    if ((status = etsVm_->GetEnv(ANI_VERSION_1, &env)) != ANI_OK || env == nullptr) {
        HILOG_ERROR("Failed to get env, status: %{public}d", status);
        return;
    }
    ani_ref funRef;
    if ((status = env->Object_GetPropertyByName_Ref(reinterpret_cast<ani_object>(etsConnectionRef_),
        "onFailed", &funRef)) != ANI_OK) {
        HILOG_ERROR("get onFailed failed status: %{public}d", status);
        return;
    }
    if (!AppExecFwk::IsValidProperty(env, funRef)) {
        HILOG_INFO("invalid onFailed property");
        return;
    }
    ani_object errorCodeObj = AppExecFwk::CreateInt(env, errorCode);
    if (errorCodeObj == nullptr) {
        HILOG_ERROR("null errorCodeObj");
        return;
    }
    ani_ref result;
    std::vector<ani_ref> argv = { errorCodeObj };
    if ((status = env->FunctionalObject_Call(reinterpret_cast<ani_fn_object>(funRef), ARGC_ONE, argv.data(),
        &result)) != ANI_OK) {
        HILOG_ERROR("Failed to call onFailed, status: %{public}d", status);
    }
}

void DistributedExtensionContextETSConnection::SetConnectionRef(ani_object connectOptionsObj)
{
    if (etsVm_ == nullptr) {
        HILOG_ERROR("etsVm_ is nullptr");
        return;
    }
    ani_env *env = nullptr;
    ani_status status = ANI_ERROR;
    if ((status = etsVm_->GetEnv(ANI_VERSION_1, &env)) != ANI_OK || env == nullptr) {
        HILOG_ERROR("status: %{public}d", status);
        return;
    }
    if ((status = env->GlobalReference_Create(connectOptionsObj, &etsConnectionRef_)) != ANI_OK) {
        HILOG_ERROR("status: %{public}d", status);
    }
}

void DistributedExtensionContextETSConnection::OnAbilityConnectDone(
    const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remoteObject, int32_t resultCode)
{
    HILOG_INFO("OnAbilityConnectDone");
    if (etsVm_ == nullptr || etsConnectionRef_ == nullptr) {
        HILOG_ERROR("null etsConnectionRef_ or etsVm");
        return;
    }
    bool isAttachThread = false;
    ani_env *env = AppExecFwk::AttachAniEnv(etsVm_, isAttachThread);
    if (env == nullptr) {
        HILOG_ERROR("GetEnv failed");
        return;
    }
    ani_ref refElement = AppExecFwk::WrapElementName(env, element);
    if (refElement == nullptr || remoteObject == nullptr) {
        HILOG_ERROR("null refElement or remoteObject");
        AppExecFwk::DetachAniEnv(etsVm_, isAttachThread);
        return;
    }
    ani_object refRemoteObject = ANI_ohos_rpc_CreateJsRemoteObject(env, remoteObject);
    if (refRemoteObject == nullptr) {
        HILOG_ERROR("null refRemoteObject");
        AppExecFwk::DetachAniEnv(etsVm_, isAttachThread);
        return;
    }
    ani_status status;
    ani_ref funRef;
    if ((status = env->Object_GetPropertyByName_Ref(reinterpret_cast<ani_object>(etsConnectionRef_),
        "onConnect", &funRef)) != ANI_OK || !AppExecFwk::IsValidProperty(env, funRef)) {
        HILOG_INFO("invalid onConnect callback");
        AppExecFwk::DetachAniEnv(etsVm_, isAttachThread);
        return;
    }
    ani_ref result;
    std::vector<ani_ref> argv = { refElement, refRemoteObject };
    if ((status = env->FunctionalObject_Call(reinterpret_cast<ani_fn_object>(funRef), ARGC_TWO, argv.data(),
        &result)) != ANI_OK) {
        HILOG_ERROR("Failed to call onConnect, status: %{public}d", status);
    }
    AppExecFwk::DetachAniEnv(etsVm_, isAttachThread);
}

void DistributedExtensionContextETSConnection::OnAbilityDisconnectDone(
    const AppExecFwk::ElementName &element, int32_t resultCode)
{
    HILOG_INFO("OnAbilityDisconnectDone");
    if (etsVm_ == nullptr || etsConnectionRef_ == nullptr) {
        HILOG_ERROR("null etsConnectionRef_ or etsVm");
        return;
    }
    bool isAttachThread = false;
    ani_env *env = AppExecFwk::AttachAniEnv(etsVm_, isAttachThread);
    if (env == nullptr) {
        HILOG_ERROR("GetEnv failed");
        return;
    }
    ani_ref refElement = AppExecFwk::WrapElementName(env, element);
    if (refElement == nullptr) {
        HILOG_ERROR("null refElement");
        AppExecFwk::DetachAniEnv(etsVm_, isAttachThread);
        return;
    }
    ani_status status;
    ani_ref funRef;
    if ((status = env->Object_GetPropertyByName_Ref(reinterpret_cast<ani_object>(etsConnectionRef_),
        "onDisconnect", &funRef)) != ANI_OK || !AppExecFwk::IsValidProperty(env, funRef)) {
        HILOG_INFO("invalid onDisconnect callback");
        AppExecFwk::DetachAniEnv(etsVm_, isAttachThread);
        return;
    }
    {
        std::lock_guard<std::recursive_mutex> lock(g_connectsLock);
        auto item = std::find_if(g_connects.begin(), g_connects.end(),
            [&element](const auto &obj) {
                return element.GetBundleName() == obj.first.want.GetBundle() &&
                       element.GetAbilityName() == obj.first.want.GetElement().GetAbilityName();
            });
        if (item != g_connects.end()) {
            if (item->second) { item->second->RemoveConnectionObject(); }
            g_connects.erase(item);
        }
    }
    ani_ref result;
    std::vector<ani_ref> argv = { refElement };
    if ((status = env->FunctionalObject_Call(reinterpret_cast<ani_fn_object>(funRef), ARGC_ONE, argv.data(),
        &result)) != ANI_OK) {
        HILOG_ERROR("Failed to call onDisconnect, status: %{public}d", status);
    }
    AppExecFwk::DetachAniEnv(etsVm_, isAttachThread);
}

} // namespace DistributedSchedule
} // namespace OHOS
