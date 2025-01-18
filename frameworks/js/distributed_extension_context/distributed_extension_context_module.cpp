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

#include "native_engine/native_engine.h"

#define EXTERN_C_VISIBILITY_DEFAULT extern "C" __attribute__((visibility("default")))
#define EXTERN_C_CONSTRUCTOR extern "C" __attribute__((constructor))

extern const char BINARY_DISTRIBUTED_EXTENSION_CONTEXT_JS_START[];
extern const char BINARY_DISTRIBUTED_EXTENSION_ABILITY_JS_END[];
extern const char BINARY_DISTRIBUTED_EXTENSION_CONTEXT_ABC_START[];
extern const char BINARY_DISTRIBUTED_EXTENSION_CONTEXT_ABC_END[];

static napi_module _module = {
    .nm_version = 0,
    .nm_filename = "application/libdistributedextensioncontext.so/distributed_extension_context.js",
    .nm_modname = "application.DistributedExtensionContext",
};

EXTERN_C_CONSTRUCTOR void NapiApplicationDistributedExtensionContextAutoRegister()
{
    napi_module_register(&_module);
}

EXTERN_C_VISIBILITY_DEFAULT void NapiApplicationDistributedExtensionContextGetJsCode(const char **buf, int *bufLen)
{
    if (buf != nullptr) {
        *buf = BINARY_DISTRIBUTED_EXTENSION_CONTEXT_JS_START;
    }

    if (bufLen != nullptr) {
        *bufLen = BINARY_DISTRIBUTED_EXTENSION_ABILITY_JS_END - BINARY_DISTRIBUTED_EXTENSION_CONTEXT_JS_START;
    }
}

// extension_context JS register
EXTERN_C_VISIBILITY_DEFAULT void NapiApplicationDistributedExtensionContextGetAbcCode(const char **buf, int *buflen)
{
    if (buf != nullptr) {
        *buf = BINARY_DISTRIBUTED_EXTENSION_CONTEXT_ABC_START;
    }
    if (buflen != nullptr) {
        *buflen = BINARY_DISTRIBUTED_EXTENSION_CONTEXT_ABC_END - BINARY_DISTRIBUTED_EXTENSION_CONTEXT_ABC_START;
    }
}
