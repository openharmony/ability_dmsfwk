/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "distributed_data_change_listener_test.h"

#include "change_notification.h"
#include "mission/distributed_data_change_listener.h"
#include "test_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {
namespace {
    const std::string BASEDIR = "/data/service/el1/public/database/DistributedSchedule";
    const std::string TEST_UUID = "test-uuid-123";
    const std::string TEST_NETWORK_ID = "test-network-id";
    const std::string TEST_DEVICE_ID = "test-device";
    const int32_t TEST_MISSION_ID = 100;
}

void DistributedDataChangeListenerTest::SetUpTestCase()
{
    mkdir(BASEDIR.c_str(), (S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH));
    DTEST_LOG << "DistributedDataChangeListenerTest::SetUpTestCase" << std::endl;
}

void DistributedDataChangeListenerTest::TearDownTestCase()
{
    (void)remove(BASEDIR.c_str());
    DTEST_LOG << "DistributedDataChangeListenerTest::TearDownTestCase" << std::endl;
}

void DistributedDataChangeListenerTest::SetUp()
{
    DTEST_LOG << "DistributedDataChangeListenerTest::SetUp" << std::endl;
}

void DistributedDataChangeListenerTest::TearDown()
{
    DTEST_LOG << "DistributedDataChangeListenerTest::TearDown" << std::endl;
}

/**
 * @tc.name: OnChange_Insert_001
 * @tc.desc: Test OnChange with valid insert entries
 * @tc.type: FUNC
 */
HWTEST_F(DistributedDataChangeListenerTest, OnChange_Insert_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedDataChangeListenerTest OnChange_Insert_001 start" << std::endl;

    DistributedDataChangeListener listener;

    std::vector<DistributedKv::Entry> insertEntries;
    DistributedKv::Entry entry;
    entry.key = TEST_UUID + "_" + std::to_string(TEST_MISSION_ID);
    entry.value = "test_value";
    insertEntries.push_back(entry);

    std::vector<DistributedKv::Entry> updateEntries;
    std::vector<DistributedKv::Entry> deleteEntries;

    DistributedKv::ChangeNotification changeNotification(std::move(insertEntries),
        std::move(updateEntries), std::move(deleteEntries), TEST_DEVICE_ID, false);

    // Should not crash, OnChange will handle the entries
    listener.OnChange(changeNotification);

    DTEST_LOG << "DistributedDataChangeListenerTest OnChange_Insert_001 end" << std::endl;
}

/**
 * @tc.name: OnChange_Insert_002
 * @tc.desc: Test OnChange with invalid key format in insert entries
 * @tc.type: FUNC
 */
HWTEST_F(DistributedDataChangeListenerTest, OnChange_Insert_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedDataChangeListenerTest OnChange_Insert_002 start" << std::endl;

    DistributedDataChangeListener listener;

    std::vector<DistributedKv::Entry> insertEntries;
    DistributedKv::Entry entry;
    // Invalid format - missing missionId
    entry.key = TEST_UUID;
    entry.value = "test_value";
    insertEntries.push_back(entry);

    std::vector<DistributedKv::Entry> updateEntries;
    std::vector<DistributedKv::Entry> deleteEntries;

    DistributedKv::ChangeNotification changeNotification(std::move(insertEntries),
        std::move(updateEntries), std::move(deleteEntries), TEST_DEVICE_ID, false);

    // Should not crash, invalid key is ignored
    listener.OnChange(changeNotification);

    DTEST_LOG << "DistributedDataChangeListenerTest OnChange_Insert_002 end" << std::endl;
}

/**
 * @tc.name: OnChange_Insert_003
 * @tc.desc: Test OnChange with invalid missionId in insert entries
 * @tc.type: FUNC
 */
HWTEST_F(DistributedDataChangeListenerTest, OnChange_Insert_003, TestSize.Level3)
{
    DTEST_LOG << "DistributedDataChangeListenerTest OnChange_Insert_003 start" << std::endl;

    DistributedDataChangeListener listener;

    std::vector<DistributedKv::Entry> insertEntries;
    DistributedKv::Entry entry;
    // Invalid missionId (not numeric)
    entry.key = TEST_UUID + "_abc";
    entry.value = "test_value";
    insertEntries.push_back(entry);

    std::vector<DistributedKv::Entry> updateEntries;
    std::vector<DistributedKv::Entry> deleteEntries;

    DistributedKv::ChangeNotification changeNotification(std::move(insertEntries),
        std::move(updateEntries), std::move(deleteEntries), TEST_DEVICE_ID, false);

    // Should not crash, invalid key is ignored
    listener.OnChange(changeNotification);

    DTEST_LOG << "DistributedDataChangeListenerTest OnChange_Insert_003 end" << std::endl;
}

/**
 * @tc.name: OnChange_Insert_004
 * @tc.desc: Test OnChange with extra underscore in insert entries
 * @tc.type: FUNC
 */
HWTEST_F(DistributedDataChangeListenerTest, OnChange_Insert_004, TestSize.Level3)
{
    DTEST_LOG << "DistributedDataChangeListenerTest OnChange_Insert_004 start" << std::endl;

    DistributedDataChangeListener listener;

    std::vector<DistributedKv::Entry> insertEntries;
    DistributedKv::Entry entry;
    // Invalid format - too many parts
    entry.key = TEST_UUID + "_extra_" + std::to_string(TEST_MISSION_ID);
    entry.value = "test_value";
    insertEntries.push_back(entry);

    std::vector<DistributedKv::Entry> updateEntries;
    std::vector<DistributedKv::Entry> deleteEntries;

    DistributedKv::ChangeNotification changeNotification(std::move(insertEntries),
        std::move(updateEntries), std::move(deleteEntries), TEST_DEVICE_ID, false);

    // Should not crash, invalid key is ignored
    listener.OnChange(changeNotification);

    DTEST_LOG << "DistributedDataChangeListenerTest OnChange_Insert_004 end" << std::endl;
}

/**
 * @tc.name: OnChange_Delete_001
 * @tc.desc: Test OnChange with valid delete entries
 * @tc.type: FUNC
 */
HWTEST_F(DistributedDataChangeListenerTest, OnChange_Delete_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedDataChangeListenerTest OnChange_Delete_001 start" << std::endl;

    DistributedDataChangeListener listener;

    std::vector<DistributedKv::Entry> insertEntries;
    std::vector<DistributedKv::Entry> updateEntries;
    std::vector<DistributedKv::Entry> deleteEntries;
    DistributedKv::Entry entry;
    entry.key = TEST_UUID + "_" + std::to_string(TEST_MISSION_ID);
    entry.value = "test_value";
    deleteEntries.push_back(entry);

    DistributedKv::ChangeNotification changeNotification(std::move(insertEntries),
        std::move(updateEntries), std::move(deleteEntries), TEST_DEVICE_ID, false);

    // Should not crash
    listener.OnChange(changeNotification);

    DTEST_LOG << "DistributedDataChangeListenerTest OnChange_Delete_001 end" << std::endl;
}

/**
 * @tc.name: OnChange_Delete_002
 * @tc.desc: Test OnChange with invalid key format in delete entries
 * @tc.type: FUNC
 */
HWTEST_F(DistributedDataChangeListenerTest, OnChange_Delete_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedDataChangeListenerTest OnChange_Delete_002 start" << std::endl;

    DistributedDataChangeListener listener;

    std::vector<DistributedKv::Entry> insertEntries;
    std::vector<DistributedKv::Entry> updateEntries;
    std::vector<DistributedKv::Entry> deleteEntries;
    DistributedKv::Entry entry;
    // Invalid format
    entry.key = "invalid_key";
    entry.value = "test_value";
    deleteEntries.push_back(entry);

    DistributedKv::ChangeNotification changeNotification(std::move(insertEntries),
        std::move(updateEntries), std::move(deleteEntries), TEST_DEVICE_ID, false);

    // Should not crash, invalid key is ignored
    listener.OnChange(changeNotification);

    DTEST_LOG << "DistributedDataChangeListenerTest OnChange_Delete_002 end" << std::endl;
}

/**
 * @tc.name: OnChange_Update_001
 * @tc.desc: Test OnChange with valid update entries
 * @tc.type: FUNC
 */
HWTEST_F(DistributedDataChangeListenerTest, OnChange_Update_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedDataChangeListenerTest OnChange_Update_001 start" << std::endl;

    DistributedDataChangeListener listener;

    std::vector<DistributedKv::Entry> insertEntries;
    std::vector<DistributedKv::Entry> updateEntries;
    DistributedKv::Entry entry;
    entry.key = TEST_UUID + "_" + std::to_string(TEST_MISSION_ID);
    entry.value = "test_value";
    updateEntries.push_back(entry);
    std::vector<DistributedKv::Entry> deleteEntries;

    DistributedKv::ChangeNotification changeNotification(std::move(insertEntries),
        std::move(updateEntries), std::move(deleteEntries), TEST_DEVICE_ID, false);

    // Should not crash
    listener.OnChange(changeNotification);

    DTEST_LOG << "DistributedDataChangeListenerTest OnChange_Update_001 end" << std::endl;
}

/**
 * @tc.name: OnChange_Update_002
 * @tc.desc: Test OnChange with invalid key format in update entries
 * @tc.type: FUNC
 */
HWTEST_F(DistributedDataChangeListenerTest, OnChange_Update_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedDataChangeListenerTest OnChange_Update_002 start" << std::endl;

    DistributedDataChangeListener listener;

    std::vector<DistributedKv::Entry> insertEntries;
    std::vector<DistributedKv::Entry> updateEntries;
    DistributedKv::Entry entry;
    // Invalid format
    entry.key = "invalid_key_format";
    entry.value = "test_value";
    updateEntries.push_back(entry);
    std::vector<DistributedKv::Entry> deleteEntries;

    DistributedKv::ChangeNotification changeNotification(std::move(insertEntries),
        std::move(updateEntries), std::move(deleteEntries), TEST_DEVICE_ID, false);

    // Should not crash, invalid key is ignored
    listener.OnChange(changeNotification);

    DTEST_LOG << "DistributedDataChangeListenerTest OnChange_Update_002 end" << std::endl;
}

/**
 * @tc.name: OnChange_Empty_001
 * @tc.desc: Test OnChange with empty entries
 * @tc.type: FUNC
 */
HWTEST_F(DistributedDataChangeListenerTest, OnChange_Empty_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedDataChangeListenerTest OnChange_Empty_001 start" << std::endl;

    DistributedDataChangeListener listener;

    std::vector<DistributedKv::Entry> insertEntries;
    std::vector<DistributedKv::Entry> updateEntries;
    std::vector<DistributedKv::Entry> deleteEntries;

    DistributedKv::ChangeNotification changeNotification(std::move(insertEntries),
        std::move(updateEntries), std::move(deleteEntries), TEST_DEVICE_ID, false);

    // Should not crash with empty entries
    listener.OnChange(changeNotification);

    DTEST_LOG << "DistributedDataChangeListenerTest OnChange_Empty_001 end" << std::endl;
}

/**
 * @tc.name: OnChange_Multiple_001
 * @tc.desc: Test OnChange with multiple entries in each category
 * @tc.type: FUNC
 */
HWTEST_F(DistributedDataChangeListenerTest, OnChange_Multiple_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedDataChangeListenerTest OnChange_Multiple_001 start" << std::endl;

    DistributedDataChangeListener listener;

    std::vector<DistributedKv::Entry> insertEntries;
    for (int32_t i = 0; i < 3; i++) {
        DistributedKv::Entry entry;
        entry.key = TEST_UUID + "_" + std::to_string(TEST_MISSION_ID + i);
        entry.value = "test_value_" + std::to_string(i);
        insertEntries.push_back(entry);
    }

    std::vector<DistributedKv::Entry> updateEntries;
    for (int32_t i = 0; i < 2; i++) {
        DistributedKv::Entry entry;
        entry.key = TEST_UUID + "_" + std::to_string(TEST_MISSION_ID + i);
        entry.value = "update_value_" + std::to_string(i);
        updateEntries.push_back(entry);
    }

    std::vector<DistributedKv::Entry> deleteEntries;
    DistributedKv::Entry entry;
    entry.key = TEST_UUID + "_" + std::to_string(TEST_MISSION_ID);
    entry.value = "delete_value";
    deleteEntries.push_back(entry);

    DistributedKv::ChangeNotification changeNotification(std::move(insertEntries),
        std::move(updateEntries), std::move(deleteEntries), TEST_DEVICE_ID, false);

    // Should not crash with multiple entries
    listener.OnChange(changeNotification);

    DTEST_LOG << "DistributedDataChangeListenerTest OnChange_Multiple_001 end" << std::endl;
}

/**
 * @tc.name: OnChange_Mixed_001
 * @tc.desc: Test OnChange with mixed valid and invalid keys
 * @tc.type: FUNC
 */
HWTEST_F(DistributedDataChangeListenerTest, OnChange_Mixed_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedDataChangeListenerTest OnChange_Mixed_001 start" << std::endl;

    DistributedDataChangeListener listener;

    std::vector<DistributedKv::Entry> insertEntries;
    // Valid key
    DistributedKv::Entry validEntry;
    validEntry.key = TEST_UUID + "_" + std::to_string(TEST_MISSION_ID);
    validEntry.value = "valid_value";
    insertEntries.push_back(validEntry);
    // Invalid key
    DistributedKv::Entry invalidEntry;
    invalidEntry.key = "invalid_key";
    invalidEntry.value = "invalid_value";
    insertEntries.push_back(invalidEntry);

    std::vector<DistributedKv::Entry> updateEntries;
    std::vector<DistributedKv::Entry> deleteEntries;

    DistributedKv::ChangeNotification changeNotification(std::move(insertEntries),
        std::move(updateEntries), std::move(deleteEntries), TEST_DEVICE_ID, false);

    // Should not crash, valid keys processed, invalid keys ignored
    listener.OnChange(changeNotification);

    DTEST_LOG << "DistributedDataChangeListenerTest OnChange_Mixed_001 end" << std::endl;
}

/**
 * @tc.name: OnChange_EdgeCase_001
 * @tc.desc: Test OnChange with negative missionId
 * @tc.type: FUNC
 */
HWTEST_F(DistributedDataChangeListenerTest, OnChange_EdgeCase_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedDataChangeListenerTest OnChange_EdgeCase_001 start" << std::endl;

    DistributedDataChangeListener listener;

    std::vector<DistributedKv::Entry> insertEntries;
    DistributedKv::Entry entry;
    entry.key = TEST_UUID + "_" + std::to_string(-1);
    entry.value = "test_value";
    insertEntries.push_back(entry);

    std::vector<DistributedKv::Entry> updateEntries;
    std::vector<DistributedKv::Entry> deleteEntries;

    DistributedKv::ChangeNotification changeNotification(std::move(insertEntries),
        std::move(updateEntries), std::move(deleteEntries), TEST_DEVICE_ID, false);

    // Should not crash, negative missionId is accepted by StrToInt
    listener.OnChange(changeNotification);

    DTEST_LOG << "DistributedDataChangeListenerTest OnChange_EdgeCase_001 end" << std::endl;
}

/**
 * @tc.name: OnChange_EdgeCase_002
 * @tc.desc: Test OnChange with zero missionId
 * @tc.type: FUNC
 */
HWTEST_F(DistributedDataChangeListenerTest, OnChange_EdgeCase_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedDataChangeListenerTest OnChange_EdgeCase_002 start" << std::endl;

    DistributedDataChangeListener listener;

    std::vector<DistributedKv::Entry> insertEntries;
    DistributedKv::Entry entry;
    entry.key = TEST_UUID + "_" + std::to_string(0);
    entry.value = "test_value";
    insertEntries.push_back(entry);

    std::vector<DistributedKv::Entry> updateEntries;
    std::vector<DistributedKv::Entry> deleteEntries;

    DistributedKv::ChangeNotification changeNotification(std::move(insertEntries),
        std::move(updateEntries), std::move(deleteEntries), TEST_DEVICE_ID, false);

    // Should not crash, zero missionId is valid
    listener.OnChange(changeNotification);

    DTEST_LOG << "DistributedDataChangeListenerTest OnChange_EdgeCase_002 end" << std::endl;
}

/**
 * @tc.name: OnChange_EdgeCase_003
 * @tc.desc: Test OnChange with empty UUID
 * @tc.type: FUNC
 */
HWTEST_F(DistributedDataChangeListenerTest, OnChange_EdgeCase_003, TestSize.Level3)
{
    DTEST_LOG << "DistributedDataChangeListenerTest OnChange_EdgeCase_003 start" << std::endl;

    DistributedDataChangeListener listener;

    std::vector<DistributedKv::Entry> insertEntries;
    DistributedKv::Entry entry;
    // Empty UUID but valid format
    entry.key = "_" + std::to_string(TEST_MISSION_ID);
    entry.value = "test_value";
    insertEntries.push_back(entry);

    std::vector<DistributedKv::Entry> updateEntries;
    std::vector<DistributedKv::Entry> deleteEntries;

    DistributedKv::ChangeNotification changeNotification(std::move(insertEntries),
        std::move(updateEntries), std::move(deleteEntries), TEST_DEVICE_ID, false);

    // Should not crash, empty UUID is technically valid format
    listener.OnChange(changeNotification);

    DTEST_LOG << "DistributedDataChangeListenerTest OnChange_EdgeCase_003 end" << std::endl;
}

} // namespace DistributedSchedule
} // namespace OHOS
