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

#include "napi_mock.h"
#include "uv.h"

napi_status napi_send_event(napi_env env, const std::function<void()> cb, napi_event_priority priority)
{
    return OHOS::DistributedSchedule::Napi::napi->napi_send_event(env, cb, priority);
}

napi_status napi_get_uv_event_loop(napi_env env, struct uv_loop_s** loop)
{
    return OHOS::DistributedSchedule::Napi::napi->napi_get_uv_event_loop(env, loop);
}

NAPI_EXTERN napi_status napi_open_handle_scope(napi_env env, napi_handle_scope* result)
{
    return OHOS::DistributedSchedule::Napi::napi->napi_open_handle_scope(env, result);
}

NAPI_EXTERN napi_status napi_close_handle_scope(napi_env env, napi_handle_scope scope)
{
    return OHOS::DistributedSchedule::Napi::napi->napi_close_handle_scope(env, scope);
}

napi_status napi_call_function(napi_env env, napi_value recv, napi_value func, size_t argc, const napi_value* argv,
    napi_value* result)
{
    return OHOS::DistributedSchedule::Napi::napi->napi_call_function(env, recv, func, argc, argv, result);
}

napi_status napi_get_named_property(napi_env env, napi_value object, const char* utf8name, napi_value* result)
{
    return OHOS::DistributedSchedule::Napi::napi->napi_get_named_property(env, object, utf8name, result);
}

napi_status napi_escape_handle(napi_env env, napi_escapable_handle_scope scope, napi_value escapee, napi_value* result)
{
    return OHOS::DistributedSchedule::Napi::napi->napi_escape_handle(env, scope, escapee, result);
}

napi_status napi_wrap(napi_env env, napi_value js_object, void* native_object, napi_finalize finalize_cb,
    void* finalize_hint, napi_ref* result)
{
    return OHOS::DistributedSchedule::Napi::napi->napi_wrap(env, js_object, native_object, finalize_cb, finalize_hint,
                                                            result);
}
