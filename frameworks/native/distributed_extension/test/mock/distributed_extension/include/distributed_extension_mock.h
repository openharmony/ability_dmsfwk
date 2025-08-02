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

#ifndef OHOS_DISTRIBUTED_EXTENSION_MOCK_H
#define OHOS_DISTRIBUTED_EXTENSION_MOCK_H

#include <gmock/gmock.h>

#include "distributed_extension.h"

namespace OHOS::DistributedSchedule {
class TDExtension {
public:
    virtual void OnStart(const AAFwk::Want &) = 0;
    virtual void Init(const std::shared_ptr<AbilityRuntime::AbilityLocalRecord> &,
        const std::shared_ptr<AbilityRuntime::OHOSApplication> &,
        std::shared_ptr<AbilityRuntime::AbilityHandler> &,
        const sptr<IRemoteObject> &) = 0;
    virtual void OnCommand(const AAFwk::Want &, bool, int) = 0;
    virtual sptr<IRemoteObject> OnConnect(const AAFwk::Want &) = 0;
    virtual void OnDisconnect(const AAFwk::Want &) = 0;
    virtual int32_t OnCreate(AAFwk::Want& want) = 0;
    virtual int32_t OnDestroy() = 0;
    virtual int32_t OnCollabRequest(AAFwk::WantParams &wantParam) = 0;
public:
    virtual std::unique_ptr<NativeReference> LoadSystemModuleByEngine(napi_env, const std::string&, const napi_value*,
        size_t) = 0;
    virtual napi_env GetNapiEnv() const = 0;
    virtual napi_value CreateDistributedExtensionContextJS(napi_env, std::shared_ptr<DistributedExtensionContext>) = 0;
public:
    TDExtension() = default;
    virtual ~TDExtension() = default;
public:
    static inline std::shared_ptr<TDExtension> tDExtension = nullptr;
};

class DExtensionMock : public TDExtension {
public:
    MOCK_METHOD(void, OnStart, (const AAFwk::Want &));
    MOCK_METHOD(void, Init, (const std::shared_ptr<AbilityRuntime::AbilityLocalRecord> &,
              const std::shared_ptr<AbilityRuntime::OHOSApplication> &,
              std::shared_ptr<AbilityRuntime::AbilityHandler> &,
              const sptr<IRemoteObject> &));
    MOCK_METHOD(void, OnCommand, (const AAFwk::Want &, bool, int));
    MOCK_METHOD(sptr<IRemoteObject>, OnConnect, (const AAFwk::Want &));
    MOCK_METHOD(void, OnDisconnect, (const AAFwk::Want &));
    MOCK_METHOD(int32_t, OnCreate, (AAFwk::Want &));
    MOCK_METHOD(int32_t, OnDestroy, ());
    MOCK_METHOD(int32_t, OnCollabRequest, (AAFwk::WantParams &));
public:
    MOCK_METHOD(napi_value, CreateDistributedExtensionContextJS,
        (napi_env, std::shared_ptr<DistributedExtensionContext>));
    MOCK_METHOD((std::unique_ptr<NativeReference>), LoadSystemModuleByEngine, (napi_env, const std::string&,
        const napi_value*, size_t));
    MOCK_METHOD(napi_env, GetNapiEnv, (), (const));
};
} // namespace OHOS::DistributedSchedule
#endif // OHOS_DISTRIBUTED_EXTENSION_MOCK_H
