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
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <securec.h>
#include <unistd.h>

#include "hilog/log.h"
#include "distribute_dextension_test.h"
#include "access_token.h"
#include "accesstoken_kit.h"
#include "access_token_error.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "ipc_skeleton.h"
#include "dms_client.h"
#include "distributed_extension_types.h"
#include "device_manager.h"

std::shared_ptr<OHOS::DistributedSchedule::DistributedClient> dmssaClient_;

namespace OHOS {
namespace DistributedSoftware {
namespace {
constexpr char const *PACKAGE_NAME = "ohos.msdp.spatialawareness";
const int32_t FIRST_CASE = 1;
const int32_t SECOND_CASE = 2;
const int32_t THIRD_CASE = 3;
const int32_t FOURTH_CASE = 4;
const int32_t SYSTEM_USER_ID = 7259;
const int32_t USER_ID = 120;
const int32_t DEFAULT_USER_ID = 100;
std::shared_ptr<DeviceMgr::DeviceInitCallBcak> initCallback = std::make_shared<DeviceMgr::DeviceInitCallBcak>();
}
void DeviceMgr::DeviceInitCallBcak::OnRemoteDied()
{
}

DistributeDextensionTest::DistributeDextensionTest()
{
    std::cout << "Control manager constructed." << std::endl;
}

DistributeDextensionTest::~DistributeDextensionTest()
{
    std::cout << "Control manager deconstructed." << std::endl;
}

static int32_t GetUserInput() // 获取用户输入
{
    int32_t res = -1;
    int32_t count = 5;
    std::cout << ">>";
    int ret = scanf_s("%d", &res);
    if (ret != 1) {
        std::cout << "Input error, exiting." << std::endl;
        return 0;
    }
    while (std::cin.fail() && count > 0) {
        std::cin.clear();
        std::cin.ignore();
        std::cout << "invalid input, not a number! Please retry with a number." << std::endl;
        std::cout << ">>";
        ret = scanf_s("%d", &res);
        if (ret == -1) {
            std::cout << "get input error" << std::endl;
            return 0;
        }
        count--;
    }
    return res;
}

static void PrintInteractiveUsage() // 根据提示输入相应的参数
{
    std::cout << std::endl << "=============== InteractiveRunTestSelect ================" << std::endl;
    std::cout << "You can respond to instructions for corresponding option:" << std::endl;
    std::cout <<  "\t enter 1 distribute dextension Start the process Message distribution selection. " << std::endl;
    std::cout <<  "\t enter 2 distribute dextension Start the change bundle name. " << std::endl;
    std::cout <<  "\t enter 3 distribute dextension Start the change ability name. " << std::endl;
    std::cout <<  "\t enter 4 distribute dextension Start the change user ID. " << std::endl;
    std::cout <<  "\t enter 0 to exit. " << std::endl;
}

static void SetConnectInfo(DistributedSchedule::DExtConnectInfo& connectInfo)
{
    DistributedSchedule::DExtSourceInfo srcInfo;
    DistributedSchedule::DExtSinkInfo sinkInfo;
    DistributedHardware::DmDeviceInfo localDmDeviceInfo;
    int ret = DistributedHardware::DeviceManager::GetInstance().InitDeviceManager(PACKAGE_NAME, initCallback);
    if (ret != ERR_OK) {
        std::cout << "\t" << "InitDeviceManager failed:" << ret << std::endl;
        return;
    }
    ret = DistributedHardware::DeviceManager::GetInstance().GetLocalDeviceInfo(PACKAGE_NAME, localDmDeviceInfo);
    if (ret != ERR_OK) {
        std::cout << "\t" << "GetLocalDeviceInfo failed:" << ret << std::endl;
        return;
    }
    srcInfo.deviceId = "123456";
    srcInfo.networkId = localDmDeviceInfo.networkId;
    srcInfo.bundleName = "com.example.dms_extension";
    srcInfo.moduleName = "Phone";
    srcInfo.abilityName = "EntrydistributedAbility";
    sinkInfo.userId = DEFAULT_USER_ID;
    sinkInfo.pid = 0;
    sinkInfo.bundleName = "com.example.it.welink";
    sinkInfo.moduleName = "Phone";
    sinkInfo.abilityName = "AttendanceDistributedAbility";
    sinkInfo.serviceName = "WeLink";
    connectInfo.sourceInfo = srcInfo;
    connectInfo.sinkInfo = sinkInfo;
    connectInfo.tokenId = "ohos.permission.dms_extension";
    connectInfo.delegatee = "WearEngine";
}

static void HandleDExtensionEvent(const int32_t cmd) // 根据输入参数确定回调
{
    DistributedSchedule::DExtConnectInfo connectInfo;
    SetConnectInfo(connectInfo);
    auto fun = [](DistributedSchedule::DExtConnectResultInfo info) {
        std::cout << "\t" << "ResultInfo.result:" << static_cast<uint32_t>(info.result) << std::endl;
        std::cout << "\t" << "ResultInfo.errCode:" << info.errCode << std::endl;
        std::cout << "\t" << "srcInfo.deviceId:" << info.connectInfo.sourceInfo.deviceId << std::endl;
        std::cout << "\t" << "srcInfo.networkId:" << info.connectInfo.sourceInfo.networkId << std::endl;
        std::cout << "\t" << "srcInfo.bundleName:" << info.connectInfo.sourceInfo.bundleName << std::endl;
        std::cout << "\t" << "srcInfo.moduleName:" << info.connectInfo.sourceInfo.moduleName << std::endl;
        std::cout << "\t" << "srcInfo.abilityName:" << info.connectInfo.sourceInfo.abilityName << std::endl;
        std::cout << "\t" << "sinkInfo.userId:" << info.connectInfo.sinkInfo.userId << std::endl;
        std::cout << "\t" << "sinkInfo.pid:" << info.connectInfo.sinkInfo.pid << std::endl;
        std::cout << "\t" << "sinkInfo.bundleName:" << info.connectInfo.sinkInfo.bundleName << std::endl;
        std::cout << "\t" << "sinkInfo.moduleName:" << info.connectInfo.sinkInfo.moduleName << std::endl;
        std::cout << "\t" << "sinkInfo.abilityName:" << info.connectInfo.sinkInfo.abilityName << std::endl;
        std::cout << "\t" << "sinkInfo.serviceName:" << info.connectInfo.sinkInfo.serviceName << std::endl;
    };
    switch (cmd) {
        case FIRST_CASE:
            dmssaClient_->ConnectDExtensionFromRemote(connectInfo, fun);
            break;
        case SECOND_CASE :
            connectInfo.sinkInfo.bundleName = "com.example.dms_extension_name";
            dmssaClient_->ConnectDExtensionFromRemote(connectInfo, fun);
            break;
        case THIRD_CASE :
            connectInfo.sinkInfo.abilityName = "EntrydistributedAbility_name";
            dmssaClient_->ConnectDExtensionFromRemote(connectInfo, fun);
            break;
        case FOURTH_CASE :
            connectInfo.sinkInfo.userId = USER_ID;
            dmssaClient_->ConnectDExtensionFromRemote(connectInfo, fun);
            break;
        default:
            break;
    }
}
}
} // namespace OHOS

using namespace OHOS::DistributedSoftware;
int main(int argc, char *argv[])
{
    dmssaClient_ = std::make_shared<OHOS::DistributedSchedule::DistributedClient>();
    if (!dmssaClient_) {
        std::cout << "\t" << "Client not initialized" << std::endl;
        return 0;
    }
    uint64_t tokenId;
    static const char *perms[] = {
        "ohos.permission.DISTRIBUTED_DATASYNC",
        "ohos.permission.MANAGE_MISSIONS",
    };
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 2,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = perms,
        .acls = nullptr,
        .processName = "foundation",
        .aplStr = "system_core",
    };
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
    if (setuid(SYSTEM_USER_ID) != 0) {
        std::cout << "\t" << "setuid failed" << std::endl;
        return 0;
    }
    PrintInteractiveUsage();
    int32_t cmd = GetUserInput();
    while (cmd != 0) {
        PrintInteractiveUsage();
        HandleDExtensionEvent(cmd);
        cmd = GetUserInput();
    }
    return 0;
}