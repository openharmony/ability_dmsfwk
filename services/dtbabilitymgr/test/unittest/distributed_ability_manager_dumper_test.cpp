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

#include "distributed_ability_manager_dumper_test.h"

#include "distributed_ability_manager_dumper.h"
#include "dtbschedmgr_log.h"
#include "nativetoken_kit.h"
#include "test_log.h"
#include "token_setproc.h"

namespace OHOS {
namespace DistributedSchedule {
using namespace testing;
using namespace testing::ext;
namespace {
constexpr int32_t DISTRIBUTED_SCHED_SA_ID = 1401;
const char* HIDUMPER_PROCESS_NAME = "hidumper_service";
const char* DISTSCHED_PROCESS_NAME = "distributedsched";
const char* INVALID_PROCESS_NAME = "invalid_process";
bool g_mockResult = false;
}

static bool MockDistributedSchedDumpFunc(const std::vector<std::string>& args, std::string& result)
{
    return g_mockResult;
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
    dtbabilitymgrService_ = new DistributedAbilityManagerService(DISTRIBUTED_SCHED_SA_ID, true);
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
 * @tc.name: ProcessDistributedSchedDump_001
 * @tc.desc: call ProcessDistributedSchedDump with distributed server not load.
 * @tc.type: FUNC
 * @tc.require: I5PUBK
 */
HWTEST_F(DistributedAbilityManagerDumperTest, ProcessDistributedSchedDump_001, TestSize.Level3)
{
    DTEST_LOG << "ContinuationManagerTest ProcessDistributedSchedDump_001 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    dtbabilitymgrService_->isLoaded_ = false;
    dtbabilitymgrService_->distributedSchedDumpFunc_ = nullptr;
    const std::vector<std::string> args;
    std::string dumpResult;
    bool result = dtbabilitymgrService_->ProcessDistributedSchedDump(args, dumpResult);
    EXPECT_EQ(false, result);
    DTEST_LOG << "ContinuationManagerTest ProcessDistributedSchedDump_001 end" << std::endl;
}

/**
 * @tc.name: ProcessDistributedSchedDump_002
 * @tc.desc: call ProcessDistributedSchedDump with distributedSchedDumpFunc_ is nullptr.
 * @tc.type: FUNC
 * @tc.require: I5PUBK
 */
HWTEST_F(DistributedAbilityManagerDumperTest, ProcessDistributedSchedDump_002, TestSize.Level3)
{
    DTEST_LOG << "ContinuationManagerTest ProcessDistributedSchedDump_002 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    dtbabilitymgrService_->isLoaded_ = true;
    dtbabilitymgrService_->distributedSchedDumpFunc_ = nullptr;
    const std::vector<std::string> args;
    std::string dumpResult;
    bool result = dtbabilitymgrService_->ProcessDistributedSchedDump(args, dumpResult);
    EXPECT_EQ(false, result);
    DTEST_LOG << "ContinuationManagerTest ProcessDistributedSchedDump_002 end" << std::endl;
}

/**
 * @tc.name: ProcessDistributedSchedDump_003
 * @tc.desc: call ProcessDistributedSchedDump with distributed server load.
 * @tc.type: FUNC
 * @tc.require: I5PUBK
 */
HWTEST_F(DistributedAbilityManagerDumperTest, ProcessDistributedSchedDump_003, TestSize.Level3)
{
    DTEST_LOG << "ContinuationManagerTest ProcessDistributedSchedDump_003 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    dtbabilitymgrService_->isLoaded_ = true;
    g_mockResult = true;
    dtbabilitymgrService_->distributedSchedDumpFunc_ = &MockDistributedSchedDumpFunc;
    const std::vector<std::string> args;
    std::string dumpResult;
    bool result = dtbabilitymgrService_->ProcessDistributedSchedDump(args, dumpResult);
    EXPECT_EQ(true, result);
    DTEST_LOG << "ContinuationManagerTest ProcessDistributedSchedDump_003 end" << std::endl;
}

/**
 * @tc.name: ProcessDistributedSchedDump_004
 * @tc.desc: call ProcessDistributedSchedDump with distributed server load.
 * @tc.type: FUNC
 * @tc.require: I5PUBK
 */
HWTEST_F(DistributedAbilityManagerDumperTest, ProcessDistributedSchedDump_004, TestSize.Level3)
{
    DTEST_LOG << "ContinuationManagerTest ProcessDistributedSchedDump_004 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    dtbabilitymgrService_->isLoaded_ = true;
    g_mockResult = false;
    dtbabilitymgrService_->distributedSchedDumpFunc_ = &MockDistributedSchedDumpFunc;
    const std::vector<std::string> args;
    std::string dumpResult;
    bool result = dtbabilitymgrService_->ProcessDistributedSchedDump(args, dumpResult);
    EXPECT_EQ(false, result);
    DTEST_LOG << "ContinuationManagerTest ProcessDistributedSchedDump_004 end" << std::endl;
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
    bool result = DistributedAbilityManagerDumper::Dump(dtbabilitymgrService_, args, dumpResult);
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
    dtbabilitymgrService_->isLoaded_ = true;
    g_mockResult = true;
    dtbabilitymgrService_->distributedSchedDumpFunc_ = &MockDistributedSchedDumpFunc;
    const std::vector<std::string> args;
    std::string dumpResult;
    bool result = DistributedAbilityManagerDumper::Dump(dtbabilitymgrService_, args, dumpResult);
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
    dtbabilitymgrService_->isLoaded_ = true;
    g_mockResult = true;
    dtbabilitymgrService_->distributedSchedDumpFunc_ = &MockDistributedSchedDumpFunc;
    const std::vector<std::string> args = {"-h"};
    std::string dumpResult;
    bool result = DistributedAbilityManagerDumper::Dump(dtbabilitymgrService_, args, dumpResult);
    EXPECT_EQ(true, result);
    DTEST_LOG << "ContinuationManagerTest Dumper_Dump_003 end" << std::endl;
}

/**
 * @tc.name: Dumper_Dump_004
 * @tc.desc: call DistributedAbilityManagerDumper::Dump with args -connect.
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
    dtbabilitymgrService_->isLoaded_ = true;
    g_mockResult = true;
    dtbabilitymgrService_->distributedSchedDumpFunc_ = &MockDistributedSchedDumpFunc;
    const std::vector<std::string> args = {"-connect"};
    std::string dumpResult;
    bool result = DistributedAbilityManagerDumper::Dump(dtbabilitymgrService_, args, dumpResult);
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
    dtbabilitymgrService_->isLoaded_ = true;
    g_mockResult = true;
    dtbabilitymgrService_->distributedSchedDumpFunc_ = &MockDistributedSchedDumpFunc;
    const std::vector<std::string> args = {"-mockArgs"};
    std::string dumpResult;
    bool result = DistributedAbilityManagerDumper::Dump(dtbabilitymgrService_, args, dumpResult);
    EXPECT_EQ(false, result);
    DTEST_LOG << "ContinuationManagerTest Dumper_Dump_005 end" << std::endl;
    DTEST_LOG << dumpResult << std::endl;
}

/**
 * @tc.name: Dumper_Dump_006
 * @tc.desc: call DistributedAbilityManagerDumper::Dump with dmsDumper is nullptr.
 * @tc.type: FUNC
 * @tc.require: I5PUBK
 */
HWTEST_F(DistributedAbilityManagerDumperTest, Dumper_Dump_006, TestSize.Level4)
{
    DTEST_LOG << "ContinuationManagerTest Dumper_Dump_006 start" << std::endl;
    dtbabilitymgrService_->isLoaded_ = true;
    g_mockResult = true;
    dtbabilitymgrService_->distributedSchedDumpFunc_ = &MockDistributedSchedDumpFunc;
    const std::vector<std::string> args;
    std::string dumpResult;
    bool result = DistributedAbilityManagerDumper::Dump(nullptr, args, dumpResult);
    EXPECT_EQ(false, result);
    DTEST_LOG << "ContinuationManagerTest Dumper_Dump_006 end" << std::endl;
}

/**
 * @tc.name: Dumper_Dump_007
 * @tc.desc: call DistributedAbilityManagerDumper::Dump from invalid process.
 * @tc.type: FUNC
 * @tc.require: I5PUBK
 */
HWTEST_F(DistributedAbilityManagerDumperTest, Dumper_Dump_007, TestSize.Level4)
{
    DTEST_LOG << "ContinuationManagerTest Dumper_Dump_007 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    MockProcess(INVALID_PROCESS_NAME);
    const std::vector<std::string> args;
    std::string dumpResult;
    bool result = DistributedAbilityManagerDumper::Dump(dtbabilitymgrService_, args, dumpResult);
    EXPECT_EQ(false, result);
    DTEST_LOG << "ContinuationManagerTest Dumper_Dump_007 end" << std::endl;
}
} // namespace DistributedSchedule
} // namespace OHOS