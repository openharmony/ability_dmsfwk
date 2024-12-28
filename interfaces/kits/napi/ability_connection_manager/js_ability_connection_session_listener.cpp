/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "js_ability_connection_session_listener.h"

#include "dtbcollabmgr_log.h"
#include "js_runtime_utils.h"
#include "napi_common_util.h"
#include "pixel_map_napi.h"

namespace OHOS {
namespace DistributedCollab {
using namespace OHOS::AbilityRuntime;
namespace {
const std::string TAG = "JsAbilityConnectionSessionListener";
}

void JsAbilityConnectionSessionListener::SetCallback(const napi_value& jsListenerObj)
{
    HILOGD("called.");
    napi_ref tempRef = nullptr;
    std::unique_ptr<NativeReference> callbackRef;
    if (env_ == nullptr) {
        HILOGE("env_ is nullptr");
        return;
    }
    napi_create_reference(env_, jsListenerObj, 1, &tempRef);
    callbackRef.reset(reinterpret_cast<NativeReference *>(tempRef));
    callbackRef_ = std::move(callbackRef);
}

void JsAbilityConnectionSessionListener::CallJsMethod(const EventCallbackInfo& callbackInfo)
{
    HILOGD("called.");
    if (env_ == nullptr) {
        HILOGE("env_ is nullptr");
        return;
    }

    std::unique_ptr<NapiAsyncTask::CompleteCallback> complete = std::make_unique<NapiAsyncTask::CompleteCallback>
        ([this, callbackInfo](napi_env env, NapiAsyncTask &task, int32_t status) {
            napi_handle_scope scope = nullptr;
            napi_open_handle_scope(env, &scope);
            if (scope == nullptr) {
                return;
            }

            CallJsMethodInner(callbackInfo);
            napi_close_handle_scope(env, scope);
        });

    napi_ref callback = nullptr;
    std::unique_ptr<NapiAsyncTask::ExecuteCallback> execute = nullptr;
    NapiAsyncTask::Schedule("JsAbilityConnectionSessionListener::CallJsMethod",
        env_, std::make_unique<NapiAsyncTask>(callback, std::move(execute), std::move(complete)));
}

void JsAbilityConnectionSessionListener::CallJsMethodInner(const EventCallbackInfo& callbackInfo)
{
    napi_value method = callbackRef_->GetNapiValue();
    if (method == nullptr) {
        HILOGE("Failed to get method from object");
        return;
    }
    napi_value argv[] = { WrapEventCallbackInfo(env_, callbackInfo) };
    napi_call_function(env_, CreateJsUndefined(env_), method, ArraySize(argv), argv, nullptr);
}

napi_value JsAbilityConnectionSessionListener::WrapEventCallbackInfo(napi_env& env,
    const EventCallbackInfo& callbackInfo)
{
    napi_value jsObject;
    napi_create_object(env, &jsObject);

    napi_value jsSessionId;
    napi_create_int32(env, callbackInfo.sessionId, &jsSessionId);
    napi_set_named_property(env, jsObject, "sessionId", jsSessionId);

    if (callbackInfo.reason != DisconnectReason::UNKNOW) {
        napi_value jsReason;
        napi_create_int32(env, static_cast<int32_t>(callbackInfo.reason), &jsReason);
        napi_set_named_property(env, jsObject, "reason", jsReason);
    }
    
    if (!callbackInfo.msg.empty()) {
        napi_value jsMsg;
        napi_create_string_utf8(env, callbackInfo.msg.c_str(), NAPI_AUTO_LENGTH, &jsMsg);
        napi_set_named_property(env, jsObject, "msg", jsMsg);
    }
    
    if (callbackInfo.data != nullptr) {
        napi_value jsDataBuffer = WrapAVTransDataBuffer(env, callbackInfo.data);
        napi_set_named_property(env, jsObject, "data", jsDataBuffer);
    }

    if (callbackInfo.image != nullptr) {
        napi_value jsPixelMap = Media::PixelMapNapi::CreatePixelMap(env, callbackInfo.image);
        napi_set_named_property(env, jsObject, "image", jsPixelMap);
    }
    return jsObject;
}

napi_value JsAbilityConnectionSessionListener::WrapAVTransDataBuffer(
    napi_env& env, const std::shared_ptr<AVTransDataBuffer>& dataBuffer)
{
    size_t dataSize = dataBuffer->Size();
    uint8_t* data = dataBuffer->Data();

    napi_value arrayBuffer;
    void* arrayBufferData;
    NAPI_CALL(env, napi_create_arraybuffer(env, dataSize, &arrayBufferData, &arrayBuffer));

    int32_t ret = memcpy_s(arrayBufferData, dataSize, data, dataSize);
    if (ret != EOK) {
        HILOGE("memory copy failed, ret %{public}d", ret);
        return nullptr;
    }
    return arrayBuffer;
}
}  // namespace DistributedCollab
}  // namespace OHOS