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

#include "ability_connection_session_test.h"

#include "dtbcollabmgr_log.h"
#include "test_log.h"

#include "message_data_header.h"

using namespace testing;
using namespace testing::ext;

namespace {
    const int32_t WAITTIME = 10000;
}

namespace OHOS {
namespace DistributedCollab {
void AbilityConnectionSessionTest::SetUpTestCase()
{
    DTEST_LOG << "AbilityConnectionSessionTest::SetUpTestCase" << std::endl;
    PeerInfo peerInfo = {"", "bundleName", "moduleName", "abilityName", "serverId"};
    PeerInfo localInfo = {"", "bundleName1", "moduleName1", "abilityName1", "serverId1"};
    ConnectOption options;
    std::string serverId = "test";
    AbilityConnectionSessionInfo info{serverId, localInfo, peerInfo};
    connectionSesion_ = std::make_shared<AbilityConnectionSession>(1, "serverSocketName",
        info, options);
}

void AbilityConnectionSessionTest::TearDownTestCase()
{
    DTEST_LOG << "AbilityConnectionSessionTest::TearDownTestCase" << std::endl;
}

void AbilityConnectionSessionTest::TearDown()
{
    DTEST_LOG << "AbilityConnectionSessionTest::TearDown" << std::endl;
    usleep(WAITTIME);
}

void AbilityConnectionSessionTest::SetUp()
{
    DTEST_LOG << "AbilityConnectionSessionTest::SetUp" << std::endl;
}

/**
 * @tc.name: IsVaildChannel_Test_001
 * @tc.desc: call IsVaildChannel
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(AbilityConnectionSessionTest, IsVaildChannel_Test_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionSessionTest IsVaildPeerInfo_Test_001 begin" << std::endl;
    ASSERT_NE(connectionSesion_, nullptr);
    int32_t channelId = 30;
    connectionSesion_->transChannels_.clear();
    EXPECT_FALSE(connectionSesion_->IsVaildChannel(channelId));
    
    TransChannelInfo info;
    info.channelId = 31;
    connectionSesion_->transChannels_[TransChannelType::MESSAGE] = info;
    EXPECT_FALSE(connectionSesion_->IsVaildChannel(channelId));

    info.channelId = channelId;
    connectionSesion_->transChannels_[TransChannelType::DATA] = info;
    EXPECT_TRUE(connectionSesion_->IsVaildChannel(channelId));
    connectionSesion_->transChannels_.clear();
    DTEST_LOG << "AbilityConnectionSessionTest IsVaildChannel_Test_001 end" << std::endl;
}

/**
 * @tc.name: GetStreamTransChannel_Test_001
 * @tc.desc: call GetStreamTransChannel
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(AbilityConnectionSessionTest, GetStreamTransChannel_Test_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionSessionTest GetStreamTransChannel_Test_001 begin" << std::endl;
    ASSERT_NE(connectionSesion_, nullptr);
    TransChannelInfo info;
    connectionSesion_->transChannels_.clear();
    auto rlt = connectionSesion_->GetStreamTransChannel(info);
    EXPECT_EQ(rlt, INVALID_PARAMETERS_ERR);
    
    TransChannelInfo info1;
    info1.channelId = 31;
    connectionSesion_->transChannels_[TransChannelType::STREAM_BYTES] = info1;
    rlt = connectionSesion_->GetStreamTransChannel(info);
    EXPECT_EQ(rlt, INVALID_PARAMETERS_ERR);

    connectionSesion_->transChannels_.erase(TransChannelType::STREAM_BYTES);
    info1.isConnected = true;
    connectionSesion_->transChannels_[TransChannelType::STREAM_BYTES] = info1;
    rlt = connectionSesion_->GetStreamTransChannel(info);
    EXPECT_EQ(rlt, ERR_OK);
    EXPECT_EQ(info.channelId, info1.channelId);
    
    TransChannelInfo info2;
    info2.channelId = 30;
    connectionSesion_->transChannels_[TransChannelType::STREAM] = info2;
    rlt = connectionSesion_->GetStreamTransChannel(info);
    EXPECT_EQ(rlt, ERR_OK);
    EXPECT_EQ(info.channelId, info1.channelId);

    connectionSesion_->transChannels_.erase(TransChannelType::STREAM);
    info2.isConnected = true;
    connectionSesion_->transChannels_[TransChannelType::STREAM] = info2;
    rlt = connectionSesion_->GetStreamTransChannel(info);
    EXPECT_EQ(rlt, ERR_OK);
    EXPECT_EQ(info.channelId, info2.channelId);
    connectionSesion_->transChannels_.clear();
    DTEST_LOG << "AbilityConnectionSessionTest GetStreamTransChannel_Test_001 end" << std::endl;
}

/**
 * @tc.name: ConvertToSurfaceParam_Test_001
 * @tc.desc: call ConvertToSurfaceParam
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(AbilityConnectionSessionTest, ConvertToSurfaceParam_Test_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionSessionTest ConvertToSurfaceParam_Test_001 begin" << std::endl;
    ASSERT_NE(connectionSesion_, nullptr);
    SurfaceParams param;
    param.rotation = SURFACE_ROTATE_NONE;
    param.flip = FlipOption::HORIZONTAL;
    auto outParam = connectionSesion_->ConvertToSurfaceParam(param);
    EXPECT_EQ(outParam.rotate, SurfaceRotate::ROTATE_NONE);
    EXPECT_EQ(outParam.filp, SurfaceFilp::FLIP_H);

    param.rotation = SURFACE_ROTATE_90;
    param.flip = FlipOption::VERTICAL;
    outParam = connectionSesion_->ConvertToSurfaceParam(param);
    EXPECT_EQ(outParam.rotate, SurfaceRotate::ROTATE_90);
    EXPECT_EQ(outParam.filp, SurfaceFilp::FLIP_V);

    param.rotation = SURFACE_ROTATE_180;
    param.flip = FlipOption::UNKNOWN;
    outParam = connectionSesion_->ConvertToSurfaceParam(param);
    EXPECT_EQ(outParam.rotate, SurfaceRotate::ROTATE_180);
    EXPECT_EQ(outParam.filp, SurfaceFilp::FLIP_NONE);

    param.rotation = SURFACE_ROTATE_270;
    param.flip = FlipOption::HORIZONTAL;
    outParam = connectionSesion_->ConvertToSurfaceParam(param);
    EXPECT_EQ(outParam.rotate, SurfaceRotate::ROTATE_270);
    EXPECT_EQ(outParam.filp, SurfaceFilp::FLIP_H);

    param.rotation = static_cast<SurfaceRotateParams>(1);
    param.flip = FlipOption::HORIZONTAL;
    outParam = connectionSesion_->ConvertToSurfaceParam(param);
    EXPECT_EQ(outParam.rotate, SurfaceRotate::ROTATE_NONE);
    EXPECT_EQ(outParam.filp, SurfaceFilp::FLIP_H);
    DTEST_LOG << "AbilityConnectionSessionTest ConvertToSurfaceParam_Test_001 end" << std::endl;
}

/**
 * @tc.name: OnMessageReceived_Test_001
 * @tc.desc: call OnMessageReceived
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(AbilityConnectionSessionTest, OnMessageReceived_Test_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionSessionTest OnMessageReceived_Test_001 begin" << std::endl;
    ASSERT_NE(connectionSesion_, nullptr);
    int32_t channelId = 30;
    size_t capacity = 20;
    std::shared_ptr<AVTransDataBuffer> dataBuffer = std::make_shared<AVTransDataBuffer>(capacity);
    connectionSesion_->transChannels_.clear();
    EXPECT_NO_FATAL_FAILURE(connectionSesion_->OnMessageReceived(channelId, dataBuffer));
    
    TransChannelInfo info;
    info.channelId = channelId;
    connectionSesion_->transChannels_[TransChannelType::MESSAGE] = info;
    EXPECT_NO_FATAL_FAILURE(connectionSesion_->OnMessageReceived(channelId, dataBuffer));

    MessageDataHeader data;
    dataBuffer = data.Serialize();
    EXPECT_NO_FATAL_FAILURE(connectionSesion_->OnMessageReceived(channelId, dataBuffer));
    connectionSesion_->transChannels_.clear();
    DTEST_LOG << "AbilityConnectionSessionTest GetStreamTransChannel_Test_001 end" << std::endl;
}
}
}
