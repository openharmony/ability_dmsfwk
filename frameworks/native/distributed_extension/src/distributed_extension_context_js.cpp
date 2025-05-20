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

#include "distributed_extension_context_js.h"

#include "dtbschedmgr_log.h"
#include "js_data_struct_converter.h"
#include "js_error_utils.h"
#include "js_extension_context.h"
#include "js_runtime.h"
#include "js_runtime_utils.h"
#include "js_utils.h"
#include "napi/native_api.h"
#include "napi_common_start_options.h"
#include "napi_common_util.h"
#include "napi_common_want.h"
#include "napi_remote_object.h"
#include "start_options.h"

namespace OHOS {
namespace DistributedSchedule {
const std::string TAG = "DistributedExtensionContextJS";
using namespace AbilityRuntime;

constexpr int32_t INDEX_ZERO = 0;
constexpr int32_t INDEX_ONE = 1;
constexpr int32_t ERROR_CODE_ONE = 1;
constexpr int32_t ERROR_CODE_TWO = 2;
constexpr size_t ARGC_ONE = 1;
constexpr size_t ARGC_TWO = 2;

class DistributedExtensionContextJS final {
public:
    explicit DistributedExtensionContextJS(const std::shared_ptr<DistributedExtensionContext>& ct) : context(ct) {}
    ~DistributedExtensionContextJS() = default;

    static void Finalizer(napi_env env, void* data, void* hint);

    static napi_value ConnectAbility(napi_env env, napi_callback_info info)
    {
        GET_CB_INFO_AND_CALL(env, info, DistributedExtensionContextJS, OnConnectAbility);
    }

    static napi_value DisconnectAbility(napi_env env, napi_callback_info info)
    {
        GET_CB_INFO_AND_CALL(env, info, DistributedExtensionContextJS, OnDisconnectAbility);
    }

private:
    std::weak_ptr<DistributedExtensionContext> context;

    napi_value OnConnectAbility(napi_env env, size_t argc, napi_value *argv)
    {
        HILOGI("OnConnectAbility start.");
        if (argc != ARGC_TWO) {
            HILOGE("test failed: not enough params!");
            return CreateJsUndefined(env);
        }
        AAFwk::Want want;

        if (!OHOS::AppExecFwk::UnwrapWant(env, argv[INDEX_ZERO], want)) {
            HILOGE("parse want failed");
            return CreateJsUndefined(env);
        }
        HILOGI("%{public}s bundleName: %{public}s abilityName: %{public}s", __func__, want.GetBundle().c_str(),
            want.GetElement().GetAbilityName().c_str());
        sptr<DistributedExtensionContextJSConnection> connection = new DistributedExtensionContextJSConnection(env);
        connection->SetJsConnectionObject(argv[1]);
        int64_t connectId = serialNumber_;
        ConnectionKey key;
        key.id = serialNumber_;
        key.want = want;
        {
            std::lock_guard<std::mutex> lock(g_connectMapMtx);
            connects_.emplace(key, connection);
        }
        if (serialNumber_ < INT64_MAX) {
            serialNumber_++;
        } else {
            serialNumber_ = 0;
        }

        return StartConnectAsyncTask(env, connectId, want, connection);
    }

    napi_value StartConnectAsyncTask(napi_env env, int64_t connectId, const AAFwk::Want &want,
        const sptr<DistributedExtensionContextJSConnection> &connection)
    {
        napi_value result = nullptr;
        napi_value lastParam = nullptr;
        napi_value connectResult = nullptr;
        std::unique_ptr<NapiAsyncTask> napiAsyncTask = CreateEmptyAsyncTask(env, lastParam, &result);
        auto asyncTask = [weak = context, want, connection, connectId, env, task = napiAsyncTask.get()]() {
            HILOGI("OnConnectAbility start.");
            auto context = weak.lock();
            if (context == nullptr) {
                HILOGW("context is released.");
                task->Reject(env, CreateJsError(env, ERROR_CODE_ONE, "Context is released"));
                delete task;
                return;
            }
            HILOGI("context->ConnectAbility connection: %{public}d.", static_cast<int32_t>(connectId));
            if (!context->ConnectAbility(want, connection)) {
                connection->CallJsFailed(ERROR_CODE_ONE);
            }
            task->Resolve(env, CreateJsUndefined(env));
            delete task;
        };
        if (napi_send_event(env, asyncTask, napi_eprio_high) != napi_status::napi_ok) {
            napiAsyncTask->Reject(env, CreateJsError(env, ERROR_CODE_ONE, "send event failed"));
        } else {
            napiAsyncTask.release();
        }
        napi_create_int64(env, connectId, &connectResult);
        return connectResult;
    }

    napi_value OnDisconnectAbility(napi_env env, size_t argc, napi_value *argv)
    {
        HILOGI("OnDisconnectAbility is called.");
        if (!(argc == ARGC_ONE || argc == ARGC_TWO)) {
            HILOGE("test failed: not enough params!");
            return CreateJsUndefined(env);
        }
        AAFwk::Want want;
        int64_t connectId = -1;
        sptr<DistributedExtensionContextJSConnection> connection = nullptr;
        napi_get_value_int64(env, argv[INDEX_ZERO], &connectId);
        HILOGI("OnDisconnectAbility connection: %{public}d.", static_cast<int32_t>(connectId));
        {
            std::lock_guard<std::mutex> lock(g_connectMapMtx);
            auto item = std::find_if(connects_.begin(), connects_.end(),
                [connectId](const std::map<ConnectionKey,
                    sptr<DistributedExtensionContextJSConnection>>::value_type &obj) {
                    return connectId == obj.first.id;
                });
            if (item != connects_.end()) {
                want = item->first.want;
                connection = item->second;
            }
        }
        napi_value lastParam = argc == ARGC_ONE ? nullptr : argv[INDEX_ONE];
        return StartDisconnectAsyncTask(env, want, connection, lastParam);
    }

    napi_value StartDisconnectAsyncTask(napi_env env, const AAFwk::Want &want,
        const sptr<DistributedExtensionContextJSConnection> &connection, napi_value lastParam)
    {
        napi_value result = nullptr;
        std::unique_ptr<NapiAsyncTask> napiAsyncTask = CreateEmptyAsyncTask(env, lastParam, &result);
        auto asyncTask = [weak = context, want, connection, env, task = napiAsyncTask.get()]() {
            HILOGI("OnDisconnectAbility start.");
            auto context = weak.lock();
            if (context == nullptr) {
                HILOGW("context is released.");
                task->Reject(env, CreateJsError(env, ERROR_CODE_ONE, "Context is released"));
                delete task;
                return;
            }
            if (connection == nullptr) {
                HILOGW("connection is nullptr.");
                task->Reject(env, CreateJsError(env, ERROR_CODE_TWO, "not found connection"));
                delete task;
                return;
            }
            HILOGI("context->DisconnectAbility.");
            auto errcode = context->DisconnectAbility(want, connection);
            errcode == 0 ? task->Resolve(env, CreateJsUndefined(env))
                         : task->Reject(env, CreateJsError(env, errcode, "Disconnect Ability failed."));
            delete task;
        };
        if (napi_send_event(env, asyncTask, napi_eprio_high) != napi_status::napi_ok) {
            napiAsyncTask->Reject(env, CreateJsError(env, ERROR_CODE_ONE, "send event failed"));
        } else {
            napiAsyncTask.release();
        }
        return result;
    }
};

napi_value CreateDistributedExtensionContextJS(napi_env env, std::shared_ptr<DistributedExtensionContext> context)
{
    if (context == nullptr) {
        HILOGE("Failed to CreateDistributedExtensionContextJS, context is nullptr.");
        return nullptr;
    }
    std::shared_ptr<OHOS::AppExecFwk::AbilityInfo> abilityInfo = context->GetAbilityInfo();
    napi_value object = CreateJsExtensionContext(env, context, abilityInfo);
    if (object == nullptr) {
        HILOGE("Failed to CreateJsServiceExtensionContext, context is nullptr.");
        return nullptr;
    }
    std::unique_ptr<DistributedExtensionContextJS> jsContext =
        std::make_unique<DistributedExtensionContextJS>(context);
    napi_wrap(env, object, jsContext.release(), DistributedExtensionContextJS::Finalizer, nullptr, nullptr);

    const char *moduleName = "DistributedExtensionContextJS";
    BindNativeFunction(env, object, "connectAbility", moduleName, DistributedExtensionContextJS::ConnectAbility);
    BindNativeFunction(env, object, "disconnectAbility", moduleName,
        DistributedExtensionContextJS::DisconnectAbility);
    return object;
}

void DistributedExtensionContextJS::Finalizer(napi_env env, void* data, void* hint)
{
    HILOGI("Finalizer Called.");
    std::unique_ptr<DistributedExtensionContextJS>(static_cast<DistributedExtensionContextJS*>(data));
}

napi_value CreateJsMetadata(napi_env env, const AppExecFwk::Metadata &info)
{
    HILOGI("CreateJsMetadata start.");

    napi_value objValue = nullptr;
    napi_create_object(env, &objValue);

    napi_set_named_property(env, objValue, "name", CreateJsValue(env, info.name));
    napi_set_named_property(env, objValue, "value", CreateJsValue(env, info.value));
    napi_set_named_property(env, objValue, "resource", CreateJsValue(env, info.resource));
    return objValue;
}

napi_value CreateJsMetadataArray(napi_env env, const std::vector<AppExecFwk::Metadata> &info)
{
    HILOGI("CreateJsMetadataArray start.");
    napi_value arrayValue = nullptr;
    napi_create_array_with_length(env, info.size(), &arrayValue);
    uint32_t index = 0;
    for (const auto &item : info) {
        napi_set_element(env, arrayValue, index++, CreateJsMetadata(env, item));
    }
    return arrayValue;
}

napi_value CreateJsExtensionAbilityInfo(napi_env env, const AppExecFwk::ExtensionAbilityInfo &info)
{
    HILOGI("CreateJsExtensionAbilityInfo start.");
    napi_value objValue = nullptr;
    napi_create_object(env, &objValue);

    napi_set_named_property(env, objValue, "bundleName", CreateJsValue(env, info.bundleName));
    napi_set_named_property(env, objValue, "moduleName", CreateJsValue(env, info.moduleName));
    napi_set_named_property(env, objValue, "name", CreateJsValue(env, info.name));
    napi_set_named_property(env, objValue, "labelId", CreateJsValue(env, info.labelId));
    napi_set_named_property(env, objValue, "descriptionId", CreateJsValue(env, info.descriptionId));
    napi_set_named_property(env, objValue, "iconId", CreateJsValue(env, info.iconId));
    napi_set_named_property(env, objValue, "isVisible", CreateJsValue(env, info.visible));
    napi_set_named_property(env, objValue, "extensionAbilityType", CreateJsValue(env, info.type));

    napi_value permissionArray = nullptr;
    napi_create_array_with_length(env, info.permissions.size(), &permissionArray);

    if (permissionArray != nullptr) {
        int32_t index = 0;
        for (auto permission : info.permissions) {
            napi_set_element(env, permissionArray, index++, CreateJsValue(env, permission));
        }
    }
    napi_set_named_property(env, objValue, "permissions", permissionArray);
    napi_set_named_property(env, objValue, "applicationInfo", CreateJsApplicationInfo(env, info.applicationInfo));
    napi_set_named_property(env, objValue, "metadata", CreateJsMetadataArray(env, info.metadata));
    napi_set_named_property(env, objValue, "enabled", CreateJsValue(env, info.enabled));
    napi_set_named_property(env, objValue, "readPermission", CreateJsValue(env, info.readPermission));
    napi_set_named_property(env, objValue, "writePermission", CreateJsValue(env, info.writePermission));
    return objValue;
}

DistributedExtensionContextJSConnection::DistributedExtensionContextJSConnection(napi_env env) : env_(env),
    handler_(std::make_shared<AppExecFwk::EventHandler>(AppExecFwk::EventRunner::GetMainEventRunner()))
{
}

DistributedExtensionContextJSConnection::~DistributedExtensionContextJSConnection()
{
    ReleaseConnection();
}

void DistributedExtensionContextJSConnection::OnAbilityConnectDone(const AppExecFwk::ElementName &element,
    const sptr<IRemoteObject> &remoteObject, int32_t resultCode)
{
    HILOGI("OnAbilityConnectDone start, resultCode: %{public}d.", resultCode);
    if (jsConnectionObject_ == nullptr) {
        HILOGE("jsConnectionObject_ is nullptr!");
        ReleaseConnection();
        return;
    }
    if (handler_ == nullptr) {
        HILOGI("handler_ is nullptr.");
        return;
    }
    wptr<DistributedExtensionContextJSConnection> connection = this;
    auto task = [connection, element, remoteObject, resultCode]() {
        sptr<DistributedExtensionContextJSConnection> connectionSptr = connection.promote();
        if (connectionSptr == nullptr) {
            HILOGE("connectionSptr is nullptr.");
            return;
        }
        connectionSptr->HandleOnAbilityConnectDone(element, remoteObject, resultCode);
    };
    handler_->PostTask(task, "OnAbilityConnectDone", 0, AppExecFwk::EventQueue::Priority::VIP);
}

void DistributedExtensionContextJSConnection::HandleOnAbilityConnectDone(const AppExecFwk::ElementName &element,
    const sptr<IRemoteObject> &remoteObject, int32_t resultCode)
{
    HILOGI("HandleOnAbilityConnectDone start, resultCode:%{public}d.", resultCode);
    napi_value napiElementName = OHOS::AppExecFwk::WrapElementName(env_, element);

    HILOGI("OnAbilityConnectDone start NAPI_ohos_rpc_CreateJsRemoteObject.");
    napi_value napiRemoteObject = NAPI_ohos_rpc_CreateJsRemoteObject(env_, remoteObject);
    napi_value argv[] = { napiElementName, napiRemoteObject };

    if (jsConnectionObject_ == nullptr) {
        HILOGE("jsConnectionObject_ is nullptr!");
        return;
    }

    napi_value obj = nullptr;
    if (napi_get_reference_value(env_, jsConnectionObject_, &obj) != napi_ok) {
        HILOGE("failed to get jsConnectionObject_!");
        return;
    }
    if (obj == nullptr) {
        HILOGE("failed to get object!");
        return;
    }
    napi_value methodOnConnect = nullptr;
    napi_get_named_property(env_, obj, "onConnect", &methodOnConnect);
    if (methodOnConnect == nullptr) {
        HILOGE("failed to get onConnect from object!");
        return;
    }
    HILOGI("DistributedExtensionContextJSConnection::CallFunction onConnect, success.");
    napi_value callResult = nullptr;
    napi_call_function(env_, obj, methodOnConnect, ARGC_TWO, argv, &callResult);
    HILOGI("OnAbilityConnectDone end.");
}

void DistributedExtensionContextJSConnection::OnAbilityDisconnectDone(const AppExecFwk::ElementName &element,
    int32_t resultCode)
{
    HILOGI("OnAbilityDisconnectDone start, resultCode: %{public}d.", resultCode);
    if (handler_ == nullptr) {
        HILOGI("handler_ is nullptr.");
        return;
    }
    wptr<DistributedExtensionContextJSConnection> connection = this;
    auto task = [connection, element, resultCode]() {
        sptr<DistributedExtensionContextJSConnection> connectionSptr = connection.promote();
        if (!connectionSptr) {
            HILOGE("connectionSptr is nullptr.");
            return;
        }
        connectionSptr->HandleOnAbilityDisconnectDone(element, resultCode);
    };
    handler_->PostTask(task, "OnAbilityDisconnectDone", 0, AppExecFwk::EventQueue::Priority::VIP);
}

void DistributedExtensionContextJSConnection::HandleOnAbilityDisconnectDone(const AppExecFwk::ElementName &element,
    int32_t resultCode)
{
    HILOGI("HandleOnAbilityDisconnectDone start, resultCode:%{public}d.", resultCode);
    napi_value napiElementName = OHOS::AppExecFwk::WrapElementName(env_, element);
    napi_value argv[] = { napiElementName };
    if (jsConnectionObject_ == nullptr) {
        HILOGE("jsConnectionObject_ is nullptr!");
        return;
    }
    napi_value obj = nullptr;
    if (napi_get_reference_value(env_, jsConnectionObject_, &obj) != napi_ok) {
        HILOGE("failed to get jsConnectionObject_!");
        return;
    }
    if (obj == nullptr) {
        HILOGE("failed to get object!");
        return;
    }
    napi_value method = nullptr;
    napi_get_named_property(env_, obj, "onDisconnect", &method);
    if (method == nullptr) {
        HILOGE("failed to get onDisconnect from object!");
        return;
    }
    std::string bundleName = element.GetBundleName();
    std::string abilityName = element.GetAbilityName();
    {
        std::lock_guard<std::mutex> lock(g_connectMapMtx);
        HILOGI("OnAbilityDisconnectDone connects_.size: %{public}zu.", connects_.size());
        auto item = std::find_if(connects_.begin(), connects_.end(),
            [bundleName, abilityName](
                const std::map<ConnectionKey, sptr<DistributedExtensionContextJSConnection>>::value_type &obj) {
                return (bundleName == obj.first.want.GetBundle()) &&
                       (abilityName == obj.first.want.GetElement().GetAbilityName());
            });
        if (item != connects_.end()) {
            if (item->second != nullptr) {
                item->second->ReleaseConnection();
            }
            connects_.erase(item);
            HILOGI("OnAbilityDisconnectDone erase connects_.size: %{public}zu.", connects_.size());
        }
    }
    HILOGI("OnAbilityDisconnectDone CallFunction success.");
    napi_value callResult = nullptr;
    napi_call_function(env_, obj, method, ARGC_ONE, argv, &callResult);
}

void DistributedExtensionContextJSConnection::SetJsConnectionObject(napi_value jsConnectionObject)
{
    napi_create_reference(env_, jsConnectionObject, 1, &jsConnectionObject_);
}

void DistributedExtensionContextJSConnection::CallJsFailed(int32_t errorCode)
{
    HILOGI("CallJsFailed start");
    if (jsConnectionObject_ == nullptr) {
        HILOGE("jsConnectionObject_ is nullptr!");
        return;
    }
    napi_value obj = nullptr;
    if (napi_get_reference_value(env_, jsConnectionObject_, &obj) != napi_ok) {
        HILOGE("failed to get jsConnectionObject_!");
        return;
    }
    if (obj == nullptr) {
        HILOGE("failed to get object.");
        return;
    }

    napi_value method = nullptr;
    napi_get_named_property(env_, obj, "onFailed", &method);
    if (method == nullptr) {
        HILOGE("failed to get onFailed from object!");
        return;
    }
    napi_value result = nullptr;
    napi_create_int32(env_, errorCode, &result);
    napi_value argv[] = { result };
    HILOGI("CallJsFailed CallFunction success.");
    napi_value callResult = nullptr;
    napi_call_function(env_, obj, method, ARGC_ONE, argv, &callResult);
    HILOGI("CallJsFailed end.");
}

void DistributedExtensionContextJSConnection::ReleaseConnection()
{
    HILOGI("ReleaseConnection");
    if (jsConnectionObject_ != nullptr) {
        napi_delete_reference(env_, jsConnectionObject_);
        env_ = nullptr;
        jsConnectionObject_ = nullptr;
    }
}
}
}
