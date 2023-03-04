/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "distributed_ability_manager_dumper.h"

#include "accesstoken_kit.h"
#include "base/continuationmgr_log.h"
#include "distributed_ability_manager_service.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "ContinuationManagerDumper";
const std::string HIDUMPER_PROCESS_NAME = "hidumper_service";
const std::string ARGS_HELP = "-h";
const std::string ARGS_APP_REGISTER_INFO = "-register";
constexpr size_t MIN_ARGS_SIZE = 1;
}

bool DistributedAbilityManagerDumper::Dump(const std::vector<std::string>& args, std::string& result)
{
    result.clear();
    if (!CanDump()) {
        result.append("Dump failed, not allowed");
        return false;
    }
    if (args.size() < MIN_ARGS_SIZE) {
        return DumpDefault(result);
    }
    if (args.size() == MIN_ARGS_SIZE) {
        // -h
        if (args[0] == ARGS_HELP) {
            ShowHelp(result);
            return true;
        }
        // -register
        if (args[0] == ARGS_APP_REGISTER_INFO) {
            ShowAppRegisterInfo(result);
            return true;
        }
    }
    IllegalInput(result);
    return false;
}

bool DistributedAbilityManagerDumper::CanDump()
{
    uint32_t accessToken = IPCSkeleton::GetCallingTokenID();
    Security::AccessToken::NativeTokenInfo nativeTokenInfo;
    int32_t result = Security::AccessToken::AccessTokenKit::GetNativeTokenInfo(accessToken, nativeTokenInfo);
    if (result == ERR_OK && nativeTokenInfo.processName == HIDUMPER_PROCESS_NAME) {
        return true;
    }
    return false;
}

bool DistributedAbilityManagerDumper::DumpDefault(std::string& result)
{
    result.append("ContinuationManagerService Dump\n");
    result.append("\n");
    ShowAppRegisterInfo(result);
    return true;
}

void DistributedAbilityManagerDumper::ShowAppRegisterInfo(std::string& result)
{
    DistributedAbilityManagerService::GetInstance().DumpAppRegisterInfo(result);
}

void DistributedAbilityManagerDumper::ShowHelp(std::string& result)
{
    result.append("ContinuationManagerService Dump options:\n")
        .append("  [-h] [cmd]...\n")
        .append("cmd maybe one of:\n")
        .append("  -register: show all application register infos.\n");
}

void DistributedAbilityManagerDumper::IllegalInput(std::string& result)
{
    result.append("The arguments are illegal and you can enter '-h' for help.\n");
}
} // namespace DistributedSchedule
} // namespace OHOS