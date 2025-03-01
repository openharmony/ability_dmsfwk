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

#ifndef DISTRIBUTED_NAPI_MOCK_H
#define DISTRIBUTED_NAPI_MOCK_H

#include <gmock/gmock.h>
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "uv.h"

namespace OHOS::DistributedSchedule {
class Napi {
public:
    virtual ~Napi() = default;
public:
    virtual napi_status napi_get_uv_event_loop(napi_env, struct uv_loop_s**) = 0;
    virtual napi_status napi_call_function(napi_env, napi_value, napi_value, size_t, const napi_value*, napi_value*)
        = 0;
    virtual napi_status napi_get_named_property(napi_env, napi_value, const char*, napi_value*) = 0;
    virtual napi_status napi_send_event(napi_env, const std::function<void()>, napi_event_priority) = 0;
    virtual napi_status napi_escape_handle(napi_env, napi_escapable_handle_scope, napi_value, napi_value*) = 0;
    virtual napi_status napi_open_handle_scope(napi_env, napi_handle_scope*) = 0;
    virtual napi_status napi_close_handle_scope(napi_env, napi_handle_scope) = 0;
    virtual napi_status napi_wrap(napi_env, napi_value, void*, napi_finalize, void*, napi_ref*) = 0;
public:
    static inline std::shared_ptr<Napi> napi = nullptr;
};

class NapiMock : public Napi {
public:
    MOCK_METHOD2(napi_get_uv_event_loop, napi_status(napi_env, struct uv_loop_s**));
    MOCK_METHOD6(napi_call_function, napi_status(napi_env, napi_value, napi_value, size_t, const napi_value*,
        napi_value*));
    MOCK_METHOD4(napi_get_named_property, napi_status(napi_env, napi_value, const char*, napi_value*));
    MOCK_METHOD3(napi_send_event, napi_status(napi_env, const std::function<void()>, napi_event_priority));
    MOCK_METHOD4(napi_escape_handle, napi_status(napi_env, napi_escapable_handle_scope, napi_value, napi_value*));
    MOCK_METHOD2(napi_open_handle_scope, napi_status(napi_env, napi_handle_scope*));
    MOCK_METHOD2(napi_close_handle_scope, napi_status(napi_env, napi_handle_scope));
    MOCK_METHOD6(napi_wrap, napi_status(napi_env, napi_value, void*, napi_finalize, void*, napi_ref*));
};
} // namespace OHOS::DistributedSchedule
#endif // DISTRIBUTED_NAPI_MOCK_H
