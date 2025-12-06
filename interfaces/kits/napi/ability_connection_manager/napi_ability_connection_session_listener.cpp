/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "napi_ability_connection_session_listener.h"

#include "dtbcollabmgr_log.h"
#include "js_runtime_utils.h"
#include "napi_common_util.h"
#include "pixel_map_napi.h"

namespace OHOS {
namespace DistributedCollab {
using namespace OHOS::AbilityRuntime;
namespace {
const std::string TAG = "NapiAbilityConnectionSessionListener";
}

NapiAbilityConnectionSessionListener::NapiAbilityConnectionSessionListener()
{
    HILOGI("called.");
}

NapiAbilityConnectionSessionListener::NapiAbilityConnectionSessionListener(napi_env env)
{
    HILOGI("called.");
    env_ = env;
}

NapiAbilityConnectionSessionListener::~NapiAbilityConnectionSessionListener()
{
    HILOGI("called.");
    if (callbackRef_ && env_) {
        auto task = [env = env_, ref = callbackRef_]() {
            HILOGI("called.");
            if (env == nullptr || ref == nullptr) {
                HILOGE("Invalid env_ or callbackRef_");
                return;
            }
            napi_delete_reference(env, ref);
        };
        if (napi_status::napi_ok != napi_send_event(env_, task, napi_eprio_vip,
            "distributedsched:~NapiAbilityConnectionSessionListener")) {
            HILOGE("send event failed!");
        }
    }
}

void NapiAbilityConnectionSessionListener::SetCallback(const napi_value& jsListenerObj)
{
    HILOGI("called.");
    if (env_ == nullptr) {
        HILOGE("env_ is nullptr");
        return;
    }
    
    if (callbackRef_) {
        HILOGE("the callbackRef has been set.");
        return;
    }
    
    napi_status status = napi_create_reference(env_, jsListenerObj, 1, &callbackRef_);
    if (status != napi_ok || callbackRef_ == nullptr) {
        HILOGE("Failed to create reference, status is %{public}d", static_cast<int32_t>(status));
        return;
    }
}

void NapiAbilityConnectionSessionListener::CallJsMethod(const EventCallbackInfo& eventCallbackInfo)
{
    CallJsMethodTemplate(eventCallbackInfo);
}

void NapiAbilityConnectionSessionListener::CallJsMethod(const CollaborateEventInfo& collaborateEventInfo)
{
    CallJsMethodTemplate(collaborateEventInfo);
}

template <typename T>
void NapiAbilityConnectionSessionListener::CallJsMethodTemplate(const T& callbackInfo)
{
    HILOGI("called.");
    if (env_ == nullptr) {
        HILOGE("env_ is nullptr");
        return;
    }
 
    auto self = shared_from_this();
    auto task = [self, callbackInfo]() {
        HILOGI("called js method template.");
        if (!self) {
            HILOGI("self is nullptr.");
            return;
        }
        napi_handle_scope scope = nullptr;
        auto env = self->env_;
        napi_status result = napi_open_handle_scope(env, &scope);
        if (result != napi_ok || scope == nullptr) {
            HILOGE("open handle scope failed!");
            return;
        }
 
        self->CallJsMethodInner(callbackInfo);
        result = napi_close_handle_scope(env, scope);
        if (result != napi_ok) {
            HILOGE("close handle scope failed!");
        }
        HILOGI("end.");
    };
    if (napi_status::napi_ok != napi_send_event(env_, task, napi_eprio_vip, "distributedsched:CallJsMethodTemplate")) {
        HILOGE("send event failed!");
    }
}

void NapiAbilityConnectionSessionListener::CallJsMethodInner(const EventCallbackInfo& eventCallbackInfo)
{
    CallJsMethodInnerTemplate(eventCallbackInfo);
}

void NapiAbilityConnectionSessionListener::CallJsMethodInner(const CollaborateEventInfo& collaborateEventInfo)
{
    CallJsMethodInnerTemplate(collaborateEventInfo);
}

template <typename T>
void NapiAbilityConnectionSessionListener::CallJsMethodInnerTemplate(const T& callbackInfo)
{
    HILOGI("called.");
    if (env_ == nullptr || callbackRef_ == nullptr) {
        HILOGE("Invalid env_ or callbackRef_");
        return;
    }

    napi_value callback = nullptr;
    napi_status status = napi_get_reference_value(env_, callbackRef_, &callback);
    if (status != napi_ok || callback == nullptr) {
        HILOGE("Failed to get callback from reference, status is %{public}d", static_cast<int32_t>(status));
        return;
    }

    napi_value argv[] = { WrapEventCallbackInfo(env_, callbackInfo) };
    status = napi_call_function(env_, CreateJsUndefined(env_), callback, ArraySize(argv), argv, nullptr);
    if (status != napi_ok) {
        HILOGE("Failed to call JS function, status is %{public}d", static_cast<int32_t>(status));
    }
    HILOGI("end.");
}

napi_value NapiAbilityConnectionSessionListener::WrapEventCallbackInfo(napi_env& env,
    const EventCallbackInfo& eventCallbackInfo)
{
    napi_value jsObject;
    napi_create_object(env, &jsObject);

    napi_value jsSessionId;
    napi_create_int32(env, eventCallbackInfo.sessionId, &jsSessionId);
    napi_set_named_property(env, jsObject, "sessionId", jsSessionId);

    napi_value jsEventType;
    napi_create_string_utf8(env, eventCallbackInfo.eventType.c_str(), NAPI_AUTO_LENGTH, &jsEventType);
    napi_set_named_property(env, jsObject, "eventType", jsEventType);

    if (eventCallbackInfo.reason != DisconnectReason::UNKNOW) {
        napi_value jsReason;
        napi_create_int32(env, static_cast<int32_t>(eventCallbackInfo.reason), &jsReason);
        napi_set_named_property(env, jsObject, "reason", jsReason);
    }
    
    if (!eventCallbackInfo.msg.empty()) {
        napi_value jsMsg;
        napi_create_string_utf8(env, eventCallbackInfo.msg.c_str(), NAPI_AUTO_LENGTH, &jsMsg);
        napi_set_named_property(env, jsObject, "msg", jsMsg);
    }
    
    if (eventCallbackInfo.data != nullptr) {
        napi_value jsDataBuffer = WrapAVTransDataBuffer(env, eventCallbackInfo.data);
        napi_set_named_property(env, jsObject, "data", jsDataBuffer);
    }

    if (eventCallbackInfo.image != nullptr) {
        napi_value jsPixelMap = Media::PixelMapNapi::CreatePixelMap(env, eventCallbackInfo.image);
        napi_set_named_property(env, jsObject, "image", jsPixelMap);
    }
    return jsObject;
}

napi_value NapiAbilityConnectionSessionListener::WrapEventCallbackInfo(napi_env& env,
    const CollaborateEventInfo& collaborateEventInfo)
{
    napi_value jsCallbackInfo;
    napi_create_object(env, &jsCallbackInfo);

    napi_value jsSessionId;
    napi_create_int32(env, collaborateEventInfo.sessionId, &jsSessionId);
    napi_set_named_property(env, jsCallbackInfo, "sessionId", jsSessionId);

    napi_value jsEventType;
    napi_create_int32(env, static_cast<int32_t>(collaborateEventInfo.eventType), &jsEventType);
    napi_set_named_property(env, jsCallbackInfo, "eventType", jsEventType);

    napi_value jsEventMsg;
    napi_create_string_utf8(env, collaborateEventInfo.eventMsg.c_str(), NAPI_AUTO_LENGTH, &jsEventMsg);
    napi_set_named_property(env, jsCallbackInfo, "eventMsg", jsEventMsg);

    return jsCallbackInfo;
}

napi_value NapiAbilityConnectionSessionListener::WrapAVTransDataBuffer(
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