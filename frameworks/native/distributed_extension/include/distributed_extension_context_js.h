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

#ifndef OHOS_DISTRIBUTED_EXTENSION_CONTEXT_JS_H
#define OHOS_DISTRIBUTED_EXTENSION_CONTEXT_JS_H

#include "ability_connect_callback.h"
#include "distributed_extension_context.h"
#include "event_handler.h"
#include "js_runtime_utils.h"
#include "native_engine/native_engine.h"
#include "native_engine/native_value.h"

namespace OHOS {
namespace DistributedSchedule {
napi_value CreateDistributedExtensionContextJS(napi_env env, std::shared_ptr<DistributedExtensionContext> ct);

class DistributedExtensionContextJSConnection : public AbilityConnectCallback {
public:
    explicit DistributedExtensionContextJSConnection(napi_env env);
    ~DistributedExtensionContextJSConnection();
    void OnAbilityConnectDone(const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remoteObject,
        int32_t resultCode) override;
    void OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int32_t resultCode) override;
    // this function need to execute in main thread.
    void CallJsFailed(int32_t errorCode);
    void SetJsConnectionObject(napi_value jsConnectionObject);

private:
    void HandleOnAbilityConnectDone(const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remoteObject,
        int32_t resultCode);
    void HandleOnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int32_t resultCode);
    void ReleaseConnection();

private:
    napi_env env_;
    napi_ref jsConnectionObject_ = nullptr;
    std::shared_ptr<AppExecFwk::EventHandler> handler_ = nullptr;
};

struct ConnectionKey {
    AAFwk::Want want;
    int64_t id;
};

struct key_compare {
    bool operator()(const ConnectionKey &key1, const ConnectionKey &key2) const
    {
        return key1.id < key2.id;
    }
};

static std::map<ConnectionKey, sptr<DistributedExtensionContextJSConnection>, key_compare> connects_;
static int64_t serialNumber_ = 0;
static std::mutex g_connectMapMtx;
}
}

#endif // OHOS_DISTRIBUTED_EXTENSION_CONTEXT_JS_H
