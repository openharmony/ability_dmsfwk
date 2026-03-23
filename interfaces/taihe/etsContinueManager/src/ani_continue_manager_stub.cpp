/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "ani_continue_manager_stub.h"
#include "distributedsched_ipc_interface_code.h"
#include "event_handler.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
    const std::string TAG = "AniContinuationStateManagerStub";
    const std::u16string CONNECTION_CALLBACK_INTERFACE_TOKEN = u"ohos.abilityshell.DistributedConnection";
    const int32_t CONTINUE_MANAGER_PERMISSION_ERR = -1;
}

AniContinuationStateManagerStub::AniContinuationStateManagerStub()
{
    callbackData_.callbackRef = nullptr;
}

AniContinuationStateManagerStub::~AniContinuationStateManagerStub()
{
    if (callbackData_.callbackRef != nullptr) {
        ani_ref callbackRef = callbackData_.callbackRef;
        callbackData_.callbackRef = nullptr;

        auto task = [callbackRef]() {
            ani_env *env = taihe::get_env();
            if (env == nullptr) {
                HILOGE("Env is null in destructor callback cleanup");
                return;
            }
            if (env->GlobalReference_Delete(callbackRef) != ANI_OK) {
                HILOGE("Failed to delete callback global reference in main thread");
            }
        };

        auto handler = std::make_shared<AppExecFwk::EventHandler>(AppExecFwk::EventRunner::GetMainEventRunner());
        if (handler != nullptr) {
            handler->PostTask(task, "AniContinueManagerStub::CleanupCallback", 0,
                AppExecFwk::EventQueue::Priority::VIP);
        } else {
            HILOGE("Failed to get main event handler for callback cleanup");
            ani_env *env = taihe::get_env();
            if (env != nullptr && env->GlobalReference_Delete(callbackRef) != ANI_OK) {
                HILOGE("Failed to delete callback global reference directly in destructor");
            }
        }
    }
}

int32_t AniContinuationStateManagerStub::OnRemoteRequest(uint32_t code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    std::u16string token = data.ReadInterfaceToken();
    if (CONNECTION_CALLBACK_INTERFACE_TOKEN != token) {
        HILOGD("OnRemoteRequest interface token check failed!");
        return CONTINUE_MANAGER_PERMISSION_ERR;
    }
    switch (code) {
        case static_cast<uint32_t>(IDSchedInterfaceCode::CONTINUE_STATE_CALLBACK):
            return ContinueStateCallback(data, reply);
        default:
            return ANI_OK;
    }
}

int32_t AniContinuationStateManagerStub::ContinueStateCallback(MessageParcel &data, MessageParcel &reply)
{
    int32_t state = data.ReadInt32();
    std::string message = data.ReadString();
    ani_ref callbackRef = callbackData_.callbackRef;

    auto task = [state, message, callbackRef]() {
        ani_env *env = taihe::get_env();
        if (env == nullptr) {
            HILOGE("Env is null in callback task");
            return;
        }

        std::vector<ani_ref> args;
        ani_string msgIdArgs;
        auto status = env->String_NewUTF8(message.c_str(), message.size(), &msgIdArgs);
        if (status != ANI_OK) {
            HILOGE("String_NewUTF8 failed, status: %{public}d", status);
            return;
        }

        args.push_back(reinterpret_cast<ani_ref>(state));
        args.push_back(reinterpret_cast<ani_ref>(msgIdArgs));

        ani_fn_object onFn = reinterpret_cast<ani_fn_object>(callbackRef);
        ani_ref result;
        if (env->FunctionalObject_Call(onFn, args.size(), args.data(), &result) != ANI_OK) {
            HILOGE("OnMessage functionalObject_Call failed");
        }

        if (env->GlobalReference_Delete(msgIdArgs) != ANI_OK) {
            HILOGE("Failed to delete temporary msgIdArgs reference");
        }
    };

    auto handler = std::make_shared<AppExecFwk::EventHandler>(AppExecFwk::EventRunner::GetMainEventRunner());
    if (handler == nullptr || !handler->PostTask(task, "AniContinuationStateManagerStub::ContinueStateCallback", 0,
        AppExecFwk::EventQueue::Priority::VIP)) {
        HILOGE("Failed to post callback task to main event handler");
        return ANI_ERROR;
    }

    return ANI_OK;
}
}
}