/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "dfx/distributed_sched_dumper.h"

#include "accesstoken_kit.h"
#include "dfx/dms_continue_time_dumper.h"
#include "distributed_sched_service.h"
#include "dtbschedmgr_log.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "DistributedSchedDumper";
const std::string HIDUMPER_PROCESS_NAME = "hidumper_service";
const std::string ARGS_HELP = "-h";
const std::string ARGS_CONNECT_REMOTE_ABILITY = "-connect";
const std::string ARGS_CONNECT_CONTINUETIME_ABILITY = "-continueTime";
constexpr size_t MIN_ARGS_SIZE = 1;
}

bool DistributedSchedDumper::Dump(const std::vector<std::string>& args, std::string& result)
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
        // -connect
        if (args[0] == ARGS_CONNECT_REMOTE_ABILITY) {
            ShowConnectRemoteAbility(result);
            return true;
        }
        // -continueTime
        if (args[0] == ARGS_CONNECT_CONTINUETIME_ABILITY) {
            ShowDuration(result);
            return true;
        }
    }
    IllegalInput(result);
    return false;
}

bool DistributedSchedDumper::CanDump()
{
    uint32_t accessToken = IPCSkeleton::GetCallingTokenID();
    Security::AccessToken::NativeTokenInfo nativeTokenInfo;
    int32_t result = Security::AccessToken::AccessTokenKit::GetNativeTokenInfo(accessToken, nativeTokenInfo);
    if (result == ERR_OK && nativeTokenInfo.processName == HIDUMPER_PROCESS_NAME) {
        return true;
    }
    return false;
}

bool DistributedSchedDumper::DumpDefault(std::string& result)
{
    result.append("DistributedSched Dump\n");
    result.append("\n");
    ShowConnectRemoteAbility(result);
    return true;
}

void DistributedSchedDumper::ShowConnectRemoteAbility(std::string& result)
{
    DistributedSchedService::GetInstance().DumpConnectInfo(result);
}

void DistributedSchedDumper::ShowDuration(std::string& result)
{
    DmsContinueTime::GetInstance().ShowInfo(result);
}

void DistributedSchedDumper::ShowHelp(std::string& result)
{
    result.append("DistributedSched Dump options:\n")
        .append("  [-h] [cmd]...\n")
        .append("cmd maybe one of:\n")
        .append("  -connect: show all connected remote abilities.\n");
}

void DistributedSchedDumper::IllegalInput(std::string& result)
{
    result.append("The arguments are illegal and you can enter '-h' for help.\n");
}
} // namespace DistributedSchedule
} // namespace OHOS