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

#include "js_continuation_state_manager_stub.h"
#include "napi_error_code.h"
#include "distributedsched_ipc_interface_code.h"

namespace OHOS {
namespace DistributedSchedule {
using namespace OHOS::AbilityRuntime;
using namespace OHOS::AppExecFwk;
namespace {
    const std::string TAG = "JsContinuationStateManagerStub";
    const std::u16string CONNECTION_CALLBACK_INTERFACE_TOKEN = u"ohos.abilityshell.DistributedConnection";
    const int32_t CONTINUE_MANAGER_PERMISSION_ERR = -1;
    const int32_t CALLBACK_PARAMS_NUM = 2;
}

int32_t JsContinuationStateManagerStub::OnRemoteRequest(uint32_t code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    std::u16string token = data.ReadInterfaceToken();
    if (CONNECTION_CALLBACK_INTERFACE_TOKEN != token) {
        HILOGW("OnRemoteRequest interface token check failed!");
        return CONTINUE_MANAGER_PERMISSION_ERR;
    }
    switch (code) {
        case static_cast<uint32_t>(IDSchedInterfaceCode::CONTINUE_STATE_CALLBACK):
            return ContinueStateCallback(data, reply);
        default:
            return ERR_OK;
    }
}

int32_t JsContinuationStateManagerStub::ContinueStateCallback(MessageParcel &data, MessageParcel &reply)
{
    HILOGI("call");
    int32_t state = data.ReadInt32();
    std::string message = data.ReadString();
    auto task = [this, state, message](){
        napi_env env = callbackData_.env;
        napi_value callback = nullptr;
        napi_get_reference_value(env, callbackData_.callbackRef, &callback);
        napi_value undefined = nullptr;
        napi_get_undefined(env, &undefined);

        napi_value result;
        napi_create_object(env, &result);
        napi_value resultState;
        napi_create_int32(env, state, &resultState);
        napi_set_named_property(env, result, "resultState", resultState);
        napi_value resultInfo;
        napi_create_string_utf8(env, message.c_str(), NAPI_AUTO_LENGTH, &resultInfo);
        napi_set_named_property(env, result, "resultInfo", resultInfo);
        napi_value callbackResult[2] = {NULL, result};

        HILOGI("callback result: %{public}d", state);
        napi_value callbackReturn = nullptr;
        napi_call_function(env, undefined, callback, CALLBACK_PARAMS_NUM, callbackResult, &callbackReturn);
    };
    napi_send_event(callbackData_.env, task, napi_eprio_high);
    HILOGI("end");
    return ERR_OK;
}
} // namespace DistributedSchedule
} // namespace OHOS

