/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef DISTRIBUTED_INTENT_ERROR_CODE_H_
#define DISTRIBUTED_INTENT_ERROR_CODE_H_

#include <string>

namespace OHOS {
namespace DistributedSchedule {
enum DistributedIntentErrorCode {
    ERR_DI_OK = 0,

    /**
     * Result(201) for permission denied.
     */
    ERR_DI_PERMISSION_DENIED = 201,

    /**
     * Result(202) for the caller is not a system application.
     */
    ERR_DI_NOT_SYSTEM_APP = 202,

    /**
     * Result(401) for parameter check failed.
     */
    ERR_DI_INVALID_PARAMETER = 401,

    /**
     * Result(801) for capability not support.
     */
    ERR_DI_CAPABILITY_NOT_SUPPORT = 801,

    /**
     * Result(16700001) for the distributed intent system ability work abnormally.
     */
    ERR_DI_SYSTEM_WORK_ABNORMALLY = 16700001,

    /**
     * Result(16700002) for remote device offline.
     */
    ERR_DI_REMOTE_DEVICE_OFFLINE = 16700002,

    /**
     * Result(16700003) for remote device version not compatible.
     */
    ERR_DI_VERSION_NOT_COMPATIBLE = 16700003,

    /**
     * Result(16700004) for distributed intent feature disabled.
     */
    ERR_DI_FEATURE_DISABLED = 16700004,

    /**
     * Result(16700005) for enterprise policy restricted.
     */
    ERR_DI_ENTERPRISE_POLICY_RESTRICTED = 16700005,

    /**
     * Result(16700006) for softbus communication failed.
     */
    ERR_DI_SOFTBUS_COMMUNICATION_FAILED = 16700006,

    /**
     * Result(16700007) for distributed intent execute timeout.
     */
    ERR_DI_EXECUTE_TIMEOUT = 16700007,

    /**
     * Result(16700008) for distributed intent execute failed.
     */
    ERR_DI_EXECUTE_FAILED = 16700008,

    /**
     * Result(16700009) for intent executor not registered.
     */
    ERR_DI_INTENT_NOT_REGISTERED = 16700009,

    /**
     * Result(16700010) for intent not exist.
     */
    ERR_DI_INTENT_NOT_EXIST = 16700010,

    /**
     * Result(16700011) for intent state is not executing.
     */
    ERR_DI_INTENT_STATE_ABNORMAL = 16700011,

    /**
     * Result(16700012) for concurrent intent exceeds the upper limit.
     */
    ERR_DI_CONCURRENT_INTENT_EXCEED_LIMIT = 16700012,

    /**
     * Result(16700013) for failed to get insight intent profile.
     */
    ERR_DI_GET_PROFILE_FAILED = 16700013,

    /**
     * Result(16700014) for starting invalid component by insight intent.
     */
    ERR_DI_START_INVALID_COMPONENT = 16700014,

    /**
     * Result(16700015) for insight intent execute reply failed.
     */
    ERR_DI_EXECUTE_REPLY_FAILED = 16700015,

    /**
     * Result(16700016) for insufficient memory.
     */
    ERR_DI_NO_MEMORY = 16700016,

    /**
     * Result(16700017) for socket create failed.
     */
    ERR_DI_SOCKET_CREATE_FAILED = 16700017,

    /**
     * Result(16700018) for socket bind failed.
     */
    ERR_DI_SOCKET_BIND_FAILED = 16700018,

    /**
     * Result(16700019) for data send failed.
     */
    ERR_DI_DATA_SEND_FAILED = 16700019,

    /**
     * Result(16700020) for socket not connected.
     */
    ERR_DI_SOCKET_NOT_CONNECTED = 16700020,

    /**
     * Result(16700021) for inner error in insight intent framework.
     */
    ERR_DI_INTENT_INTERNAL_ERROR = 16700021,

    /**
     * Result(16700022) for intent data serialize or deserialize failed.
     */
    ERR_DI_SERIALIZE_FAILED = 16700022,
};

enum IntentLinkDisconnectReason {
    INTENT_LINK_DISCONNECT_REASON_SHUTDOWN = 0,
    INTENT_LINK_DISCONNECT_REASON_IDLE_TIMEOUT = 1,
};

} // namespace DistributedSchedule
} // namespace OHOS
#endif // DISTRIBUTED_INTENT_ERROR_CODE_H_
