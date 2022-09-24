/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "distributed_ability_manager_service.h"
#include "dtbschedmgr_log.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "DistributedAbilityManagerDumper";
const char* HIDUMPER_PROCESS_NAME = "hidumper_service";
constexpr size_t MIN_ARGS_SIZE = 1;
const std::string ARGS_HELP = "-h";
const std::string ARGS_CONNECT_REMOTE_ABILITY = "-connect";
}

bool DistributedAbilityManagerDumper::Dump(const sptr<DmsDumper>& dmsDumper, const std::vector<std::string>& args,
    std::string& result)
{
    result.clear();
    if (!CanDump()) {
        result.append("Dump failed, not allowed");
        return false;
    }

    if (args.size() < MIN_ARGS_SIZE) {
        return ProcessDistributedSchedDump(dmsDumper, args, result);
    }

    if (args.size() == MIN_ARGS_SIZE) {
        // -h
        if (args[0] == ARGS_HELP) {
            ShowHelp(result);
            return true;
        }
        // -connect
        if (args[0] == ARGS_CONNECT_REMOTE_ABILITY) {
            return ProcessDistributedSchedDump(dmsDumper, args, result);
        }
    }
    IllegalInput(result);
    return false;
}

bool DistributedAbilityManagerDumper::ProcessDistributedSchedDump(const sptr<DmsDumper>& dmsDumper,
    const std::vector<std::string>& args, std::string& result)
{
    if (dmsDumper == nullptr) {
        HILOGE("dumper is nullptr");
        return false;
    }
    return dmsDumper->ProcessDistributedSchedDump(args, result);
}

void DistributedAbilityManagerDumper::ShowHelp(std::string& result)
{
    result.append("DistributedSched Dump options:\n")
        .append("  [-h] [cmd]...\n")
        .append("cmd maybe one of:\n")
        .append("  -connect: show all connected remote abilities.\n");
}

void DistributedAbilityManagerDumper::IllegalInput(std::string& result)
{
    result.append("The arguments are illegal and you can enter '-h' for help.\n");
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
} // namespace DistributedSchedule
} // namespace OHOS