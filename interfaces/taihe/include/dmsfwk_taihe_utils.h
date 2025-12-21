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

#ifndef DMSFWK_TAIHE_UTILS_H
#define DMSFWK_TAIHE_UTILS_H

#include "ohos.distributedsched.abilityConnectionManager.proj.hpp"
#include "ohos.distributedsched.abilityConnectionManager.impl.hpp"
#include "taihe/runtime.hpp"

#include "ability_connection_manager.h"
#include "device_connect_status.h"
#include "taihe_error_code.h"

namespace abilityConnectionManagerTaihe = ohos::distributedsched::abilityConnectionManager;

namespace OHOS {
namespace DistributedCollab {

bool IsSystemApp();
std::string GetBusinessErrorInfo(int32_t errCode);

class PeerInfoAdapter {
public:
    static abilityConnectionManagerTaihe::PeerInfo ConvertToTaihe(const PeerInfo &peerInfo);
    static PeerInfo ConvertFromTaihe(const abilityConnectionManagerTaihe::PeerInfo &peerInfo);
};

class ConnectOptionsAdapter {
public:
    static abilityConnectionManagerTaihe::ConnectOptions ConvertToTaihe(const ConnectOption &connectOptions);
    static ConnectOption ConvertFromTaihe(const abilityConnectionManagerTaihe::ConnectOptions &connectOptions);
private:
    static std::string QueryStartOptions(const ConnectOption &connectOptions);
};

class StartOptionParamsAdapter {
public:
    static abilityConnectionManagerTaihe::StartOptionParams ConvertToTaihe(StartOptionParams startOptionParams);
    static StartOptionParams ConvertFromTaihe(abilityConnectionManagerTaihe::StartOptionParams startOptionParams);
};

class ConnectErrorCodeAdapter {
public:
    static abilityConnectionManagerTaihe::ConnectErrorCode ConvertToTaihe(ConnectErrorCode connectErrorCode);
};

class ConnectResultAdapter {
public:
    static abilityConnectionManagerTaihe::ConnectResult ConvertToTaihe(const ConnectResult &connectResult);
};

class StreamRoleAdapter {
public:
    static StreamRole ConvertFromTaihe(abilityConnectionManagerTaihe::StreamRole streamRole);
};

class StreamParamAdapter {
public:
    static StreamParams ConvertFromTaihe(const abilityConnectionManagerTaihe::StreamParam &streamParam);
};

class VideoPixelFormatAdapter {
public:
    static VideoPixelFormat ConvertFromTaihe(abilityConnectionManagerTaihe::VideoPixelFormat videoPixelFormat);
};

class FlipOptionsAdapter {
public:
    static FlipOptions ConvertFromTaihe(abilityConnectionManagerTaihe::FlipOptions flipOptions);
};

class SurfaceParamAdapter {
public:
    static SurfaceParams ConvertFromTaihe(const abilityConnectionManagerTaihe::SurfaceParam &surfaceParam);
};

class DisconnectReasonAdapter {
public:
    static abilityConnectionManagerTaihe::DisconnectReason ConvertToTaihe(DisconnectReason disconnectReason);
};

class EventCallbackInfoAdapter {
public:
    static abilityConnectionManagerTaihe::EventCallbackInfo ConvertToTaihe(const EventCallbackInfo &eventCallbackInfo);
};

class CollaborateEventTypeAdapter {
public:
    static abilityConnectionManagerTaihe::CollaborateEventType ConvertToTaihe(
        CollaborateEventType collaborateEventType);
};

class CollaborateEventInfoAdapter {
public:
    static abilityConnectionManagerTaihe::CollaborateEventInfo ConvertToTaihe(
        const CollaborateEventInfo &collaborateEventInfo);
};

class TaiheAbilityConnectionSessionListener : public JsAbilityConnectionSessionListener {
public:
    explicit TaiheAbilityConnectionSessionListener(ani_env *env);
    ~TaiheAbilityConnectionSessionListener() override;
    void CallJsMethod(const EventCallbackInfo& eventCallbackInfo) override;
    void CallJsMethod(const CollaborateEventInfo& collaborateEventInfo) override;
    void SetCallback(taihe::callback_view<void(abilityConnectionManagerTaihe::EventCallbackInfo const& info)> f,
        uintptr_t opq);
    void SetCallback(taihe::callback_view<void(abilityConnectionManagerTaihe::CollaborateEventInfo const& info)> f,
        uintptr_t opq);
private:
    bool SetCallbackCommon(uintptr_t opq);

private:
    ani_env *env_;
    ani_ref callbackRef_;
    std::shared_ptr<taihe::callback<void(abilityConnectionManagerTaihe::EventCallbackInfo const& info)>> callbackPtr_;
    std::shared_ptr<taihe::callback<void(abilityConnectionManagerTaihe::CollaborateEventInfo const& info)>>
        collaborateCallbackPtr_;
};
} // namespace DistributedCollab
} // namespace OHOS
#endif // DMSFWK_TAIHE_UTILS_H