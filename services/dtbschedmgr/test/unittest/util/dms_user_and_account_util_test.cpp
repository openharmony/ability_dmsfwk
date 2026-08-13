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

#include "dms_user_and_account_util_test.h"

#include "util/dms_user_and_account_util.h"
#include "test_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {

std::shared_ptr<AccountSA::OhosAccountKitsMock> DmsUserAndAccountUtilTest::ohosAccountMock_;
std::shared_ptr<AccountSA::OsAccountManagerMock> DmsUserAndAccountUtilTest::osAccountMock_;

void DmsUserAndAccountUtilTest::SetUpTestCase()
{
    DTEST_LOG << "DmsUserAndAccountUtilTest::SetUpTestCase" << std::endl;
    ohosAccountMock_ = std::make_shared<AccountSA::OhosAccountKitsMock>();
    AccountSA::IOhosAccountKits::ohosAccountMock = ohosAccountMock_;
    osAccountMock_ = std::make_shared<AccountSA::OsAccountManagerMock>();
    AccountSA::IOsAccountManager::osAccountMock = osAccountMock_;
}

void DmsUserAndAccountUtilTest::TearDownTestCase()
{
    DTEST_LOG << "DmsUserAndAccountUtilTest::TearDownTestCase" << std::endl;
    AccountSA::IOhosAccountKits::ohosAccountMock = nullptr;
    ohosAccountMock_ = nullptr;
    AccountSA::IOsAccountManager::osAccountMock = nullptr;
    osAccountMock_ = nullptr;
}

void DmsUserAndAccountUtilTest::SetUp()
{
    DTEST_LOG << "DmsUserAndAccountUtilTest::SetUp" << std::endl;
    ASSERT_NE(ohosAccountMock_, nullptr);
    ::testing::Mock::VerifyAndClearExpectations(ohosAccountMock_.get());
    ON_CALL(*ohosAccountMock_, GetOsAccountDistributedInfo(_, _))
        .WillByDefault(Invoke([](int32_t localId, AccountSA::OhosAccountInfo& info) {
            if (localId < 0) {
                return static_cast<ErrCode>(-1);
            }
            info.uid_ = "test_uid";
            return 0;
        }));
    ASSERT_NE(osAccountMock_, nullptr);
    ::testing::Mock::VerifyAndClearExpectations(osAccountMock_.get());
    ON_CALL(*osAccountMock_, GetForegroundOsAccountLocalId(_))
        .WillByDefault(Invoke([](int32_t& localId) {
            localId = 100;
            return 0;
        }));
    ON_CALL(*osAccountMock_, GetOsAccountLocalIdFromUid(_, _))
        .WillByDefault(Invoke([](const int uid, int& id) {
            if (uid < 0) {
                return static_cast<ErrCode>(-1);
            }
            id = uid;
            return 0;
        }));
}

void DmsUserAndAccountUtilTest::TearDown()
{
    DTEST_LOG << "DmsUserAndAccountUtilTest::TearDown" << std::endl;
}

/**
 * @tc.name: DmsUserAndAccountUtil_GetForegroundUserId_001
 * @tc.desc: test GetForegroundUserId
 * @tc.type: FUNC
 */
HWTEST_F(DmsUserAndAccountUtilTest, DmsUserAndAccountUtil_GetForegroundUserId_001, TestSize.Level3)
{
    DTEST_LOG << "DmsUserAndAccountUtil_GetForegroundUserId_001 start" << std::endl;
    int32_t userId = -1;
    ErrCode ret = DmsUserAndAccountUtil::GetForegroundUserId(userId);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_GE(userId, 0);
    DTEST_LOG << "DmsUserAndAccountUtil_GetForegroundUserId_001 end, userId: " << userId << std::endl;
}

/**
 * @tc.name: DmsUserAndAccountUtil_GetForegroundAccountInfo_001
 * @tc.desc: test GetForegroundAccountInfo
 * @tc.type: FUNC
 */
HWTEST_F(DmsUserAndAccountUtilTest, DmsUserAndAccountUtil_GetForegroundAccountInfo_001, TestSize.Level3)
{
    DTEST_LOG << "DmsUserAndAccountUtil_GetForegroundAccountInfo_001 start" << std::endl;
    AccountSA::OhosAccountInfo accountInfo;
    ErrCode ret = DmsUserAndAccountUtil::GetForegroundAccountInfo(accountInfo);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(accountInfo.uid_.empty());
    DTEST_LOG << "DmsUserAndAccountUtil_GetForegroundAccountInfo_001 end, uid: " << accountInfo.uid_ << std::endl;
}

/**
 * @tc.name: DmsUserAndAccountUtil_GetAccountInfoFromUserId_001
 * @tc.desc: test GetAccountInfoFromUserId with valid userId
 * @tc.type: FUNC
 */
HWTEST_F(DmsUserAndAccountUtilTest, DmsUserAndAccountUtil_GetAccountInfoFromUserId_001, TestSize.Level3)
{
    DTEST_LOG << "DmsUserAndAccountUtil_GetAccountInfoFromUserId_001 start" << std::endl;
    int32_t userId = 100;
    AccountSA::OhosAccountInfo accountInfo;
    ErrCode ret = DmsUserAndAccountUtil::GetAccountInfoFromUserId(userId, accountInfo);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(accountInfo.uid_.empty());
    DTEST_LOG << "DmsUserAndAccountUtil_GetAccountInfoFromUserId_001 end, uid: " << accountInfo.uid_ << std::endl;
}

/**
 * @tc.name: DmsUserAndAccountUtil_GetAccountInfoFromUserId_002
 * @tc.desc: test GetAccountInfoFromUserId with invalid userId
 * @tc.type: FUNC
 */
HWTEST_F(DmsUserAndAccountUtilTest, DmsUserAndAccountUtil_GetAccountInfoFromUserId_002, TestSize.Level3)
{
    DTEST_LOG << "DmsUserAndAccountUtil_GetAccountInfoFromUserId_002 start" << std::endl;
    int32_t userId = -1;
    AccountSA::OhosAccountInfo accountInfo;
    ErrCode ret = DmsUserAndAccountUtil::GetAccountInfoFromUserId(userId, accountInfo);
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DmsUserAndAccountUtil_GetAccountInfoFromUserId_002 end" << std::endl;
}

/**
 * @tc.name: DmsUserAndAccountUtil_GetUserIdFromCallingUid_001
 * @tc.desc: test GetUserIdFromCallingUid with valid callingUid
 * @tc.type: FUNC
 */
HWTEST_F(DmsUserAndAccountUtilTest, DmsUserAndAccountUtil_GetUserIdFromCallingUid_001, TestSize.Level3)
{
    DTEST_LOG << "DmsUserAndAccountUtil_GetUserIdFromCallingUid_001 start" << std::endl;
    int32_t callingUid = 20000100;
    int32_t userId = -1;
    ErrCode ret = DmsUserAndAccountUtil::GetUserIdFromCallingUid(callingUid, userId);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_GE(userId, 0);
    DTEST_LOG << "DmsUserAndAccountUtil_GetUserIdFromCallingUid_001 end, userId: " << userId << std::endl;
}

/**
 * @tc.name: DmsUserAndAccountUtil_GetUserIdFromCallingUid_002
 * @tc.desc: test GetUserIdFromCallingUid with root uid
 * @tc.type: FUNC
 */
HWTEST_F(DmsUserAndAccountUtilTest, DmsUserAndAccountUtil_GetUserIdFromCallingUid_002, TestSize.Level3)
{
    DTEST_LOG << "DmsUserAndAccountUtil_GetUserIdFromCallingUid_002 start" << std::endl;
    int32_t callingUid = 0;
    int32_t userId = -1;
    ErrCode ret = DmsUserAndAccountUtil::GetUserIdFromCallingUid(callingUid, userId);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(userId, 0);
    DTEST_LOG << "DmsUserAndAccountUtil_GetUserIdFromCallingUid_002 end, userId: " << userId << std::endl;
}

/**
 * @tc.name: DmsUserAndAccountUtil_GetAccountInfoFromCallingUid_001
 * @tc.desc: test GetAccountInfoFromCallingUid with valid callingUid
 * @tc.type: FUNC
 */
HWTEST_F(DmsUserAndAccountUtilTest, DmsUserAndAccountUtil_GetAccountInfoFromCallingUid_001, TestSize.Level3)
{
    DTEST_LOG << "DmsUserAndAccountUtil_GetAccountInfoFromCallingUid_001 start" << std::endl;
    int32_t callingUid = 20000100;
    AccountSA::OhosAccountInfo accountInfo;
    ErrCode ret = DmsUserAndAccountUtil::GetAccountInfoFromCallingUid(callingUid, accountInfo);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(accountInfo.uid_.empty());
    DTEST_LOG << "DmsUserAndAccountUtil_GetAccountInfoFromCallingUid_001 end, uid: " << accountInfo.uid_ << std::endl;
}

/**
 * @tc.name: DmsUserAndAccountUtil_GetAccountInfoFromCallingUid_002
 * @tc.desc: test GetAccountInfoFromCallingUid with invalid callingUid
 * @tc.type: FUNC
 */
HWTEST_F(DmsUserAndAccountUtilTest, DmsUserAndAccountUtil_GetAccountInfoFromCallingUid_002, TestSize.Level3)
{
    DTEST_LOG << "DmsUserAndAccountUtil_GetAccountInfoFromCallingUid_002 start" << std::endl;
    int32_t callingUid = -1;
    AccountSA::OhosAccountInfo accountInfo;
    ErrCode ret = DmsUserAndAccountUtil::GetAccountInfoFromCallingUid(callingUid, accountInfo);
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DmsUserAndAccountUtil_GetAccountInfoFromCallingUid_002 end" << std::endl;
}

/**
 * @tc.name: DmsUserAndAccountUtil_GetForegroundUserId_002
 * @tc.desc: test GetForegroundUserId with GetForegroundOsAccountLocalId failed
 * @tc.type: FUNC
 */
HWTEST_F(DmsUserAndAccountUtilTest, DmsUserAndAccountUtil_GetForegroundUserId_002, TestSize.Level3)
{
    DTEST_LOG << "DmsUserAndAccountUtil_GetForegroundUserId_002 start" << std::endl;
    EXPECT_CALL(*osAccountMock_, GetForegroundOsAccountLocalId(_))
        .WillOnce(Return(static_cast<ErrCode>(-1)));
    int32_t userId = -1;
    ErrCode ret = DmsUserAndAccountUtil::GetForegroundUserId(userId);
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DmsUserAndAccountUtil_GetForegroundUserId_002 end" << std::endl;
}

/**
 * @tc.name: DmsUserAndAccountUtil_GetForegroundAccountInfo_002
 * @tc.desc: test GetForegroundAccountInfo with GetForegroundOsAccountLocalId failed
 * @tc.type: FUNC
 */
HWTEST_F(DmsUserAndAccountUtilTest, DmsUserAndAccountUtil_GetForegroundAccountInfo_002, TestSize.Level3)
{
    DTEST_LOG << "DmsUserAndAccountUtil_GetForegroundAccountInfo_002 start" << std::endl;
    EXPECT_CALL(*osAccountMock_, GetForegroundOsAccountLocalId(_))
        .WillOnce(Return(static_cast<ErrCode>(-1)));
    AccountSA::OhosAccountInfo accountInfo;
    ErrCode ret = DmsUserAndAccountUtil::GetForegroundAccountInfo(accountInfo);
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DmsUserAndAccountUtil_GetForegroundAccountInfo_002 end" << std::endl;
}

/**
 * @tc.name: DmsUserAndAccountUtil_GetUserIdFromCallingUid_003
 * @tc.desc: test GetUserIdFromCallingUid with GetOsAccountLocalIdFromUid failed
 * @tc.type: FUNC
 */
HWTEST_F(DmsUserAndAccountUtilTest, DmsUserAndAccountUtil_GetUserIdFromCallingUid_003, TestSize.Level3)
{
    DTEST_LOG << "DmsUserAndAccountUtil_GetUserIdFromCallingUid_003 start" << std::endl;
    EXPECT_CALL(*osAccountMock_, GetOsAccountLocalIdFromUid(_, _))
        .WillOnce(Return(static_cast<ErrCode>(-1)));
    int32_t callingUid = 20000100;
    int32_t userId = -1;
    ErrCode ret = DmsUserAndAccountUtil::GetUserIdFromCallingUid(callingUid, userId);
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DmsUserAndAccountUtil_GetUserIdFromCallingUid_003 end" << std::endl;
}

} // namespace DistributedSchedule
} // namespace OHOS