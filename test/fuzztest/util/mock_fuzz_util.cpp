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

#include "mock_fuzz_util.h"

#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
constexpr const char* FOUNDATION_PROCESS_NAME = "foundation";
}

void FuzzUtil::MockPermission()
{
    static const char *perms[] = {
        "ohos.permission.ABILITY_BACKGROUND_COMMUNICATION",
        "ohos.permission.ACCESS_SERVICE_DM",
        "ohos.permission.ACCESS_SERVICE_DP",
        "ohos.permission.DISTRIBUTED_DATASYNC",
        "ohos.permission.INPUT_MONITORING",
        "ohos.permission.GET_BUNDLE_INFO_PRIVILEGED",
        "ohos.permission.GET_WIFI_INFO",
        "ohos.permission.MANAGE_MISSIONS",
        "ohos.permission.MANAGE_WIFI_CONNECTION",
        "ohos.permission.MONITOR_DEVICE_NETWORK_STATE",
        "ohos.permission.PUBLISH_SYSTEM_COMMON_EVENT",
        "ohos.permission.REPORT_RESOURCE_SCHEDULE_EVENT",
        "ohos.permission.RUNNING_STATE_OBSERVER",
        "ohos.permission.START_INVISIBLE_ABILITY",
        "ohos.permission.INPUT_MONITORING",
        "ohos.permission.MANAGE_MISSIONS",
        "ohos.permission.MANAGE_WIFI_CONNECTION",
        "ohos.permission.MONITOR_DEVICE_NETWORK_STATE",
        "ohos.permission.START_INVISIBLE_ABILITY"
    };
    MockProcessAndPermission(FOUNDATION_PROCESS_NAME, perms, 1);
}

void FuzzUtil::MockProcessAndPermission(const char* processName, const char *perms[], int32_t permsNum)
{
    uint64_t tokenId;
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = permsNum,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = perms,
        .acls = nullptr,
        .processName = processName,
        .aplStr = "system_core",
    };
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
    setuid(0);
}
}
}