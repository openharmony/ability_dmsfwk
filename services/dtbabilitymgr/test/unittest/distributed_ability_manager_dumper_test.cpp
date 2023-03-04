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

#include "distributed_ability_manager_dumper_test.h"

#define private public
#include "distributed_ability_manager_dumper.h"
#undef private
#include "dtbschedmgr_log.h"
#include "nativetoken_kit.h"
#include "test_log.h"
#include "token_setproc.h"

namespace OHOS {
namespace DistributedSchedule {
using namespace testing;
using namespace testing::ext;
namespace {
const char* HIDUMPER_PROCESS_NAME = "hidumper_service";
const char* DISTSCHED_PROCESS_NAME = "distributedsched";
const char* INVALID_PROCESS_NAME = "invalid_process";
}

static void MockProcess(const char* processName)
{
    uint64_t tokenId;
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 0,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = nullptr,
        .acls = nullptr,
        .processName = processName,
        .aplStr = "system_core",
    };
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
}

void DistributedAbilityManagerDumperTest::SetUpTestCase()
{
    DTEST_LOG << "DistributedAbilityManagerDumperTest::SetUpTestCase" << std::endl;
}

void DistributedAbilityManagerDumperTest::TearDownTestCase()
{
    DTEST_LOG << "DistributedAbilityManagerDumperTest::TearDownTestCase" << std::endl;
}

void DistributedAbilityManagerDumperTest::SetUp()
{
    dtbabilitymgrService_ = new DistributedAbilityManagerService();
    MockProcess(HIDUMPER_PROCESS_NAME);
    DTEST_LOG << "DistributedAbilityManagerDumperTest::SetUp" << std::endl;
}

void DistributedAbilityManagerDumperTest::TearDown()
{
    DTEST_LOG << "DistributedAbilityManagerDumperTest::TearDown" << std::endl;
}

/**
 * @tc.name: Dump_001
 * @tc.desc: call dump with invalid fd.
 * @tc.type: FUNC
 * @tc.require: I5PUBK
 */
HWTEST_F(DistributedAbilityManagerDumperTest, Dump_001, TestSize.Level4)
{
    DTEST_LOG << "ContinuationManagerTest Dump_001 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    int32_t fd = -1;
    const std::vector<std::u16string> args;
    int32_t result = dtbabilitymgrService_->Dump(fd, args);
    EXPECT_EQ(DMS_WRITE_FILE_FAILED_ERR, result);
    DTEST_LOG << "ContinuationManagerTest Dump_001 end" << std::endl;
}

/**
 * @tc.name: Dump_002
 * @tc.desc: call dump with fd = 1.
 * @tc.type: FUNC
 * @tc.require: I5PUBK
 */
HWTEST_F(DistributedAbilityManagerDumperTest, Dump_002, TestSize.Level3)
{
    DTEST_LOG << "ContinuationManagerTest Dump_002 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    int32_t fd = 1;
    const std::vector<std::u16string> args;
    int32_t result = dtbabilitymgrService_->Dump(fd, args);
    EXPECT_NE(DMS_WRITE_FILE_FAILED_ERR, result);
    DTEST_LOG << "ContinuationManagerTest Dump_002 end" << std::endl;
}

/**
 * @tc.name: Dumper_Dump_001
 * @tc.desc: call DistributedAbilityManagerDumper::Dump not from hidumper.
 * @tc.type: FUNC
 * @tc.require: I5PUBK
 */
HWTEST_F(DistributedAbilityManagerDumperTest, Dumper_Dump_001, TestSize.Level3)
{
    DTEST_LOG << "ContinuationManagerTest Dumper_Dump_001 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    MockProcess(DISTSCHED_PROCESS_NAME);
    const std::vector<std::string> args;
    std::string dumpResult;
    bool result = DistributedAbilityManagerDumper::Dump(args, dumpResult);
    EXPECT_EQ(false, result);
    DTEST_LOG << "ContinuationManagerTest Dumper_Dump_001 end" << std::endl;
}

/**
 * @tc.name: Dumper_Dump_002
 * @tc.desc: call DistributedAbilityManagerDumper::Dump with empty args.
 * @tc.type: FUNC
 * @tc.require: I5PUBK
 */
HWTEST_F(DistributedAbilityManagerDumperTest, Dumper_Dump_002, TestSize.Level3)
{
    DTEST_LOG << "ContinuationManagerTest Dumper_Dump_002 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    const std::vector<std::string> args;
    std::string dumpResult;
    bool result = DistributedAbilityManagerDumper::Dump(args, dumpResult);
    EXPECT_EQ(true, result);
    DTEST_LOG << "ContinuationManagerTest Dumper_Dump_002 end" << std::endl;
}

/**
 * @tc.name: Dumper_Dump_003
 * @tc.desc: call DistributedAbilityManagerDumper::Dump with args -h.
 * @tc.type: FUNC
 * @tc.require: I5PUBK
 */
HWTEST_F(DistributedAbilityManagerDumperTest, Dumper_Dump_003, TestSize.Level3)
{
    DTEST_LOG << "ContinuationManagerTest Dumper_Dump_003 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    const std::vector<std::string> args = {"-h"};
    std::string dumpResult;
    bool result = DistributedAbilityManagerDumper::Dump(args, dumpResult);
    EXPECT_EQ(true, result);
    DTEST_LOG << "ContinuationManagerTest Dumper_Dump_003 end" << std::endl;
}

/**
 * @tc.name: Dumper_Dump_004
 * @tc.desc: call DistributedAbilityManagerDumper::Dump with args -register.
 * @tc.type: FUNC
 * @tc.require: I5PUBK
 */
HWTEST_F(DistributedAbilityManagerDumperTest, Dumper_Dump_004, TestSize.Level3)
{
    DTEST_LOG << "ContinuationManagerTest Dumper_Dump_004 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    const std::vector<std::string> args = {"-register"};
    std::string dumpResult;
    bool result = DistributedAbilityManagerDumper::Dump(args, dumpResult);
    EXPECT_EQ(true, result);
    DTEST_LOG << "ContinuationManagerTest Dumper_Dump_004 end" << std::endl;
}

/**
 * @tc.name: Dumper_Dump_005
 * @tc.desc: call DistributedAbilityManagerDumper::Dump with invalid args.
 * @tc.type: FUNC
 * @tc.require: I5PUBK
 */
HWTEST_F(DistributedAbilityManagerDumperTest, Dumper_Dump_005, TestSize.Level3)
{
    DTEST_LOG << "ContinuationManagerTest Dumper_Dump_005 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    const std::vector<std::string> args = {"-mockArgs"};
    std::string dumpResult;
    bool result = DistributedAbilityManagerDumper::Dump(args, dumpResult);
    EXPECT_EQ(false, result);
    DTEST_LOG << "ContinuationManagerTest Dumper_Dump_005 end" << std::endl;
    DTEST_LOG << dumpResult << std::endl;
}

/**
 * @tc.name: Dumper_Dump_006
 * @tc.desc: call DistributedAbilityManagerDumper::Dump from invalid process.
 * @tc.type: FUNC
 * @tc.require: I5PUBK
 */
HWTEST_F(DistributedAbilityManagerDumperTest, Dumper_Dump_006, TestSize.Level4)
{
    DTEST_LOG << "ContinuationManagerTest Dumper_Dump_006 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    MockProcess(INVALID_PROCESS_NAME);
    const std::vector<std::string> args;
    std::string dumpResult;
    bool result = DistributedAbilityManagerDumper::Dump(args, dumpResult);
    EXPECT_EQ(false, result);
    DTEST_LOG << "ContinuationManagerTest Dumper_Dump_006 end" << std::endl;
}

/**
 * @tc.name: Dumper_DumpDefault_001
 * @tc.desc: call DistributedAbilityManagerDumper::DumpDefault.
 * @tc.type: FUNC
 */
HWTEST_F(DistributedAbilityManagerDumperTest, Dumper_DumpDefault_001, TestSize.Level4)
{
    DTEST_LOG << "ContinuationManagerTest Dumper_DumpDefault_001 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    std::string dumpResult;
    bool result = DistributedAbilityManagerDumper::DumpDefault(dumpResult);
    EXPECT_EQ(true, result);
    DTEST_LOG << "ContinuationManagerTest Dumper_DumpDefault_001 end" << std::endl;
}

/**
 * @tc.name: Dumper_ShowAppRegisterInfo_001
 * @tc.desc: call DistributedAbilityManagerDumper::ShowAppRegisterInfo.
 * @tc.type: FUNC
 */
HWTEST_F(DistributedAbilityManagerDumperTest, Dumper_ShowAppRegisterInfo_001, TestSize.Level4)
{
    DTEST_LOG << "ContinuationManagerTest Dumper_ShowAppRegisterInfo_001 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    std::string dumpResult;
    DistributedAbilityManagerDumper::ShowAppRegisterInfo(dumpResult);
    EXPECT_EQ(false, dumpResult.empty());
    DTEST_LOG << "ContinuationManagerTest Dumper_ShowAppRegisterInfo_001 end" << std::endl;
}
} // namespace DistributedSchedule
} // namespace OHOS