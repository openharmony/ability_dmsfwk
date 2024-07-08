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

#include "js_device_selection_listener.h"

#include "base/continuationmgr_log.h"
#include "js_runtime_utils.h"
#include "napi_common_util.h"

namespace OHOS {
namespace DistributedSchedule {
using namespace OHOS::AbilityRuntime;
namespace {
const std::string TAG = "JsDeviceSelectionListener";
}

void JsDeviceSelectionListener::OnDeviceConnect(const std::vector<ContinuationResult>& continuationResults)
{
    HILOGD("called.");
    CallJsMethod(EVENT_CONNECT, continuationResults);
}

void JsDeviceSelectionListener::OnDeviceDisconnect(const std::vector<ContinuationResult>& continuationResults)
{
    HILOGD("called.");
    CallJsMethod(EVENT_DISCONNECT, continuationResults);
}

void JsDeviceSelectionListener::AddCallback(const std::string& cbType, napi_value jsListenerObj)
{
    HILOGD("called.");
    napi_ref tempRef = nullptr;
    std::unique_ptr<NativeReference> callbackRef;
    if (engine_ == nullptr) {
        HILOGE("engine_ is nullptr");
        return;
    }
    napi_create_reference(engine_, jsListenerObj, 1, &tempRef);
    callbackRef.reset(reinterpret_cast<NativeReference *>(tempRef));
    std::lock_guard<std::mutex> jsCallBackMapLock(jsCallBackMapMutex_);
    jsCallBackMap_[cbType] = std::move(callbackRef);
    HILOGD("jsCallBackMap_ cbType: %{public}s, size: %{public}u!",
        cbType.c_str(), static_cast<uint32_t>(jsCallBackMap_.size()));
}

void JsDeviceSelectionListener::RemoveCallback(const std::string& cbType)
{
    HILOGD("called.");
    std::lock_guard<std::mutex> jsCallBackMapLock(jsCallBackMapMutex_);
    jsCallBackMap_.erase(cbType);
    HILOGD("jsCallBackMap_ cbType: %{public}s, size: %{public}u!",
        cbType.c_str(), static_cast<uint32_t>(jsCallBackMap_.size()));
}

void JsDeviceSelectionListener::CallJsMethod(const std::string& methodName,
    const std::vector<ContinuationResult>& continuationResults)
{
    HILOGD("methodName = %{public}s", methodName.c_str());
    if (engine_ == nullptr) {
        HILOGE("engine_ is nullptr");
        return;
    }
    // js callback should run in js thread
    std::unique_ptr<NapiAsyncTask::CompleteCallback> complete = std::make_unique<NapiAsyncTask::CompleteCallback>
        ([this, methodName, continuationResults]
            (napi_env env, NapiAsyncTask &task, int32_t status) {
            napi_handle_scope scope = nullptr;
            napi_open_handle_scope(env, &scope);
            if (scope == nullptr) {
                return;
            }

            CallJsMethodInner(methodName, continuationResults);

            napi_close_handle_scope(env, scope);
        });
    napi_ref callback = nullptr;
    std::unique_ptr<NapiAsyncTask::ExecuteCallback> execute = nullptr;
    NapiAsyncTask::Schedule("JsDeviceSelectionListener::OnDeviceConnect",
        engine_, std::make_unique<NapiAsyncTask>(callback, std::move(execute), std::move(complete)));
}

void JsDeviceSelectionListener::CallJsMethodInner(const std::string& methodName,
    const std::vector<ContinuationResult>& continuationResults)
{
    std::lock_guard<std::mutex> jsCallBackMapLock(jsCallBackMapMutex_);
    auto it = jsCallBackMap_.find(methodName);
    if (it == jsCallBackMap_.end()) {
        HILOGE("Callback method %s not found in jsCallBackMap_", methodName.c_str());
        return;
    }
    napi_value method = jsCallBackMap_[methodName]->GetNapiValue();
    if (method == nullptr) {
        HILOGE("Failed to get %{public}s from object", methodName.c_str());
        return;
    }
    napi_value argv[] = { WrapContinuationResultArray(engine_, continuationResults) };
    napi_call_function(engine_, CreateJsUndefined(engine_), method, ArraySize(argv), argv, nullptr);
}

void JsDeviceSelectionListener::CallJsMethod(const std::string& methodName, const std::vector<std::string>& deviceIds)
{
    HILOGD("methodName = %{public}s", methodName.c_str());
    if (engine_ == nullptr) {
        HILOGE("engine_ is nullptr");
        return;
    }
    // js callback should run in js thread
    std::unique_ptr<NapiAsyncTask::CompleteCallback> complete = std::make_unique<NapiAsyncTask::CompleteCallback>
        ([this, methodName, deviceIds]
            (napi_env env, NapiAsyncTask &task, int32_t status) {
            napi_handle_scope scope = nullptr;
            napi_open_handle_scope(env, &scope);
            if (scope == nullptr) {
                return;
            }
            CallJsMethodInner(methodName, deviceIds);

            napi_close_handle_scope(env, scope);
        });
    napi_ref callback = nullptr;
    std::unique_ptr<NapiAsyncTask::ExecuteCallback> execute = nullptr;
    NapiAsyncTask::Schedule("JsDeviceSelectionListener::OnDeviceDisconnect",
        engine_, std::make_unique<NapiAsyncTask>(callback, std::move(execute), std::move(complete)));
}

void JsDeviceSelectionListener::CallJsMethodInner(const std::string& methodName,
    const std::vector<std::string>& deviceIds)
{
    std::lock_guard<std::mutex> jsCallBackMapLock(jsCallBackMapMutex_);
    auto it = jsCallBackMap_.find(methodName);
    if (it == jsCallBackMap_.end()) {
        HILOGE("Callback method %s not found in jsCallBackMap_", methodName.c_str());
        return;
    }
    napi_value method = jsCallBackMap_[methodName]->GetNapiValue();
    if (method == nullptr) {
        HILOGE("Failed to get %{public}s from object", methodName.c_str());
        return;
    }
    napi_value argv[] = { WrapDeviceIdArray(engine_, deviceIds) };
    napi_call_function(engine_, CreateJsUndefined(engine_), method, ArraySize(argv), argv, nullptr);
}

napi_value JsDeviceSelectionListener::WrapContinuationResult(napi_env env,
    const ContinuationResult& continuationResult)
{
    napi_value objValue;
    napi_create_object(env, &objValue);
    SetKeyValue(env, objValue, "id", continuationResult.GetDeviceId());
    SetKeyValue(env, objValue, "type", continuationResult.GetDeviceType());
    SetKeyValue(env, objValue, "name", continuationResult.GetDeviceName());
    return objValue;
}

napi_value JsDeviceSelectionListener::WrapContinuationResultArray(napi_env env,
    const std::vector<ContinuationResult>& continuationResults)
{
    napi_value arrayValue;
    napi_create_array_with_length(env, continuationResults.size(), &arrayValue);
    uint32_t index = 0;
    for (const auto& continuationResult : continuationResults) {
        napi_set_element(env,
            arrayValue, index++, WrapContinuationResult(env, continuationResult));
    }
    return arrayValue;
}

napi_value JsDeviceSelectionListener::WrapDeviceIdArray(napi_env env,
    const std::vector<std::string>& deviceIds)
{
    napi_value arrayValue;
    napi_create_array_with_length(env, deviceIds.size(), &arrayValue);
    uint32_t index = 0;
    for (const auto& deviceId : deviceIds) {
        napi_set_element(env, arrayValue, index++, CreateJsValue(env, deviceId));
    }
    return arrayValue;
}

void JsDeviceSelectionListener::SetKeyValue(napi_env env,
    const napi_value object, const std::string &strKey, const std::string &strValue) const
{
    napi_value attrValue = nullptr;
    napi_create_string_utf8(env, strValue.c_str(), NAPI_AUTO_LENGTH, &attrValue);
    napi_set_named_property(env, object, strKey.c_str(), attrValue);
}
}  // namespace DistributedSchedule
}  // namespace OHOS