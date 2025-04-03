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

#include "ability_connection_session_listener.h"
#include "av_sender_filter.h"
#include "dtbcollabmgr_log.h"
#include "test_log.h"
#include "tokenid_kit_mock.h"

#include "message_data_header.h"
#include "pixel_map.h"

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
    param.flip = FlipOptions::HORIZONTAL;
    auto outParam = connectionSesion_->ConvertToSurfaceParam(param);
    EXPECT_EQ(outParam.rotate, SurfaceRotate::ROTATE_NONE);
    EXPECT_EQ(outParam.filp, SurfaceFilp::FLIP_H);

    param.rotation = SURFACE_ROTATE_90;
    param.flip = FlipOptions::VERTICAL;
    outParam = connectionSesion_->ConvertToSurfaceParam(param);
    EXPECT_EQ(outParam.rotate, SurfaceRotate::ROTATE_90);
    EXPECT_EQ(outParam.filp, SurfaceFilp::FLIP_V);

    param.rotation = SURFACE_ROTATE_180;
    param.flip = FlipOptions::UNKNOWN;
    outParam = connectionSesion_->ConvertToSurfaceParam(param);
    EXPECT_EQ(outParam.rotate, SurfaceRotate::ROTATE_180);
    EXPECT_EQ(outParam.filp, SurfaceFilp::FLIP_NONE);

    param.rotation = SURFACE_ROTATE_270;
    param.flip = FlipOptions::HORIZONTAL;
    outParam = connectionSesion_->ConvertToSurfaceParam(param);
    EXPECT_EQ(outParam.rotate, SurfaceRotate::ROTATE_270);
    EXPECT_EQ(outParam.filp, SurfaceFilp::FLIP_H);

    param.rotation = static_cast<SurfaceRotateParams>(1);
    param.flip = FlipOptions::HORIZONTAL;
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

/**
 * @tc.name: OnSendFile_Test_001
 * @tc.desc: call OnSendFile
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(AbilityConnectionSessionTest, OnSendFile_Test_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionSessionTest OnSendFileTest_001 begin" << std::endl;
    ASSERT_NE(connectionSesion_, nullptr);
    int32_t channelId = 30;
    FileInfo fileInfo;
    connectionSesion_->transChannels_.clear();
    EXPECT_NO_FATAL_FAILURE(connectionSesion_->OnSendFile(channelId, fileInfo));

    TransChannelInfo info;
    info.channelId = channelId;
    connectionSesion_->transChannels_[TransChannelType::MESSAGE] = info;
    EXPECT_NO_FATAL_FAILURE(connectionSesion_->OnSendFile(channelId, fileInfo));
    connectionSesion_->transChannels_.clear();
    DTEST_LOG << "AbilityConnectionSessionTest OnSendFileTest_001 end" << std::endl;
}

/**
 * @tc.name: OnRecvFile_Test_001
 * @tc.desc: call OnRecvFile
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(AbilityConnectionSessionTest, OnRecvFile_Test_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionSessionTest OnRecvFile_Test_001 begin" << std::endl;
    ASSERT_NE(connectionSesion_, nullptr);
    int32_t channelId = 30;
    FileInfo fileInfo;
    connectionSesion_->transChannels_.clear();
    EXPECT_NO_FATAL_FAILURE(connectionSesion_->OnRecvFile(channelId, fileInfo));

    TransChannelInfo info;
    info.channelId = channelId;
    connectionSesion_->transChannels_[TransChannelType::MESSAGE] = info;
    EXPECT_NO_FATAL_FAILURE(connectionSesion_->OnRecvFile(channelId, fileInfo));
    connectionSesion_->transChannels_.clear();
    DTEST_LOG << "AbilityConnectionSessionTest OnRecvFile_Test_001 end" << std::endl;
}

/**
 * @tc.name: GetRecvPath_Test_001
 * @tc.desc: call GetRecvPath
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(AbilityConnectionSessionTest, GetRecvPath_Test_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionSessionTest GetRecvPath_Test_001 begin" << std::endl;
    ASSERT_NE(connectionSesion_, nullptr);
    int32_t channelId = 30;
    FileInfo fileInfo;
    connectionSesion_->transChannels_.clear();
    EXPECT_NO_FATAL_FAILURE(connectionSesion_->GetRecvPath(channelId));

    TransChannelInfo info;
    info.channelId = channelId;
    connectionSesion_->transChannels_[TransChannelType::MESSAGE] = info;
    EXPECT_NO_FATAL_FAILURE(connectionSesion_->GetRecvPath(channelId));
    connectionSesion_->transChannels_.clear();
    DTEST_LOG << "AbilityConnectionSessionTest GetRecvPath_Test_001 end" << std::endl;
}

/**
 * @tc.name: ExeuteMessageEventCallback_Test_001
 * @tc.desc: call ExeuteMessageEventCallback
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(AbilityConnectionSessionTest, ExeuteMessageEventCallback_Test_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionSessionTest ExeuteMessageEventCallback_Test_001 begin" << std::endl;
    ASSERT_NE(connectionSesion_, nullptr);
    std::string msg = "this is a test msg";
    EXPECT_NO_FATAL_FAILURE(connectionSesion_->ExeuteMessageEventCallback(msg));
    DTEST_LOG << "AbilityConnectionSessionTest GetRecvPath_Test_001 end" << std::endl;
}

/**
 * @tc.name: OnChannelClosed_Test_001
 * @tc.desc: call OnChannelClosed
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(AbilityConnectionSessionTest, OnChannelClosed_Test_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionSessionTest OnChannelClosed_Test_001 begin" << std::endl;
    ASSERT_NE(connectionSesion_, nullptr);
    int32_t channelId = 30;
    FileInfo fileInfo;
    connectionSesion_->transChannels_.clear();
    EXPECT_NO_FATAL_FAILURE(connectionSesion_->OnChannelClosed(channelId,
        ShutdownReason::SHUTDOWN_REASON_LNN_OFFLINE));

    connectionSesion_->sessionStatus_ = SessionStatus::CONNECTING;
    TransChannelInfo info;
    info.channelId = channelId;
    connectionSesion_->transChannels_[TransChannelType::MESSAGE] = info;
    EXPECT_NO_FATAL_FAILURE(connectionSesion_->OnChannelClosed(channelId,
        ShutdownReason::SHUTDOWN_REASON_LNN_OFFLINE));

    connectionSesion_->sessionStatus_ = SessionStatus::CONNECTED;
    EXPECT_NO_FATAL_FAILURE(connectionSesion_->OnChannelClosed(channelId,
        ShutdownReason::SHUTDOWN_REASON_LNN_OFFLINE));
    connectionSesion_->transChannels_.clear();
    DTEST_LOG << "AbilityConnectionSessionTest OnChannelClosed_Test_001 end" << std::endl;
}

/**
 * @tc.name: IsAllChannelConnected_Test_001
 * @tc.desc: call IsAllChannelConnected
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(AbilityConnectionSessionTest, IsAllChannelConnected_Test_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionSessionTest IsAllChannelConnected_Test_001 begin" << std::endl;
    ASSERT_NE(connectionSesion_, nullptr);
    int32_t channelId = 30;
    connectionSesion_->transChannels_.clear();
    TransChannelInfo info;
    info.channelId = channelId;
    info.isConnected = true;
    connectionSesion_->transChannels_[TransChannelType::MESSAGE] = info;
    EXPECT_TRUE(connectionSesion_->IsAllChannelConnected());

    info.isConnected = false;
    info.transType = TransChannelType::STREAM;
    connectionSesion_->transChannels_[TransChannelType::MESSAGE] = info;
    EXPECT_TRUE(connectionSesion_->IsAllChannelConnected());

    info.transType = TransChannelType::DATA;
    connectionSesion_->transChannels_[TransChannelType::MESSAGE] = info;
    EXPECT_FALSE(connectionSesion_->IsAllChannelConnected());
    DTEST_LOG << "AbilityConnectionSessionTest OnChannelClosed_Test_001 end" << std::endl;
}

/**
 * @tc.name: AcceptConnect_Test_001
 * @tc.desc: call AcceptConnect
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(AbilityConnectionSessionTest, AcceptConnect_Test_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionSessionTest AcceptConnect_Test_001 begin" << std::endl;
    ASSERT_NE(connectionSesion_, nullptr);
    int32_t version = 0;
    connectionSesion_->HandlePeerVersion(version);

    std::string token = "token";
    connectionSesion_->sessionStatus_ = SessionStatus::CONNECTED;
    MockIsSystemAppByFullTokenID(true);
    auto ret = connectionSesion_->AcceptConnect(token);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "AbilityConnectionSessionTest AcceptConnect_Test_001 end" << std::endl;
}

/**
 * @tc.name: RequestReceiveFileChannelConnection_Test_001
 * @tc.desc: call RequestReceiveFileChannelConnection
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(AbilityConnectionSessionTest, RequestReceiveFileChannelConnection_Test_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionSessionTest RequestReceiveFileChannelConnection_Test_001 begin" << std::endl;
    ASSERT_NE(connectionSesion_, nullptr);
    connectionSesion_->RequestReceiveFileChannelConnection();

    connectionSesion_->connectOption_.needSendFile = true;
    connectionSesion_->NotifyPeerSessionConnected();

    connectionSesion_->connectOption_.needSendFile = false;
    connectionSesion_->connectOption_.needReceiveFile = false;
    EXPECT_NO_FATAL_FAILURE(connectionSesion_->NotifyPeerSessionConnected());

    bool isConnected = true;
    EXPECT_NO_FATAL_FAILURE(connectionSesion_->NotifyAppConnectResult(isConnected));
    
    connectionSesion_->sessionStatus_ = SessionStatus::CONNECTING;
    auto ret = connectionSesion_->HandleDisconnect();
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "AbilityConnectionSessionTest RequestReceiveFileChannelConnection_Test_001 end" << std::endl;
}

/**
 * @tc.name: CreateStream_Test_001
 * @tc.desc: call CreateStream
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(AbilityConnectionSessionTest, CreateStream_Test_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionSessionTest CreateStream_Test_001 begin" << std::endl;
    ASSERT_NE(connectionSesion_, nullptr);
    StreamParams param;
    param.role = StreamRole::SOURCE;
    connectionSesion_->CreateStream(0, param);

    param.role = StreamRole::SINK;
    connectionSesion_->CreateStream(0, param);

    param.role = static_cast<StreamRole>(-1);
    auto ret = connectionSesion_->CreateStream(0, param);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "AbilityConnectionSessionTest CreateStream_Test_001 end" << std::endl;
}

/**
 * @tc.name: InitSenderEngine_Test_001
 * @tc.desc: call InitSenderEngine
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(AbilityConnectionSessionTest, InitSenderEngine_Test_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionSessionTest InitSenderEngine_Test_001 begin" << std::endl;
    ASSERT_NE(connectionSesion_, nullptr);
    connectionSesion_->connectOption_.needSendStream = false;
    auto ret = connectionSesion_->InitSenderEngine();
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    connectionSesion_->connectOption_.needSendStream = true;
    connectionSesion_->senderEngine_ = nullptr;
    ret = connectionSesion_->InitSenderEngine();
    EXPECT_EQ(ret, ERR_OK);

    ret = connectionSesion_->InitSenderEngine();
    EXPECT_EQ(ret, ONLY_SUPPORT_ONE_STREAM);
    DTEST_LOG << "AbilityConnectionSessionTest InitSenderEngine_Test_001 end" << std::endl;
}

/**
 * @tc.name: InitRecvEngine_Test_001
 * @tc.desc: call InitRecvEngine
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(AbilityConnectionSessionTest, InitRecvEngine_Test_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionSessionTest InitRecvEngine_Test_001 begin" << std::endl;
    ASSERT_NE(connectionSesion_, nullptr);
    connectionSesion_->connectOption_.needReceiveStream = false;
    auto ret = connectionSesion_->InitRecvEngine();
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    connectionSesion_->connectOption_.needReceiveStream = true;
    connectionSesion_->recvEngine_ = nullptr;
    ret = connectionSesion_->InitRecvEngine();
    EXPECT_EQ(ret, ERR_OK);

    ret = connectionSesion_->InitRecvEngine();
    EXPECT_EQ(ret, ONLY_SUPPORT_ONE_STREAM);
    DTEST_LOG << "AbilityConnectionSessionTest InitRecvEngine_Test_001 end" << std::endl;
}

/**
 * @tc.name: GetSurfaceId_Test_001
 * @tc.desc: call GetSurfaceId
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(AbilityConnectionSessionTest, GetSurfaceId_Test_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionSessionTest GetSurfaceId_Test_001 begin" << std::endl;
    ASSERT_NE(connectionSesion_, nullptr);
    SurfaceParams param;
    std::string surfaceId = "surfaceId";
    connectionSesion_->senderEngine_ = nullptr;
    connectionSesion_->GetSurfaceId(param, surfaceId);

    connectionSesion_->connectOption_.needSendStream = true;
    connectionSesion_->InitSenderEngine();
    auto ret = connectionSesion_->GetSurfaceId(param, surfaceId);
    EXPECT_NE(ret, ERR_OK);

    ret = connectionSesion_->UpdateSurfaceParam(param);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "AbilityConnectionSessionTest GetSurfaceId_Test_001 end" << std::endl;
}

/**
 * @tc.name: SetSurfaceId_Test_001
 * @tc.desc: call SetSurfaceId
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(AbilityConnectionSessionTest, SetSurfaceId_Test_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionSessionTest SetSurfaceId_Test_001 begin" << std::endl;
    ASSERT_NE(connectionSesion_, nullptr);
    SurfaceParams param;
    std::string surfaceId = "123";
    connectionSesion_->recvEngine_ = nullptr;
    connectionSesion_->SetSurfaceId(surfaceId, param);

    connectionSesion_->connectOption_.needReceiveStream = true;
    connectionSesion_->InitRecvEngine();
    auto ret = connectionSesion_->SetSurfaceId(surfaceId, param);
    EXPECT_NE(ret, ERR_OK);

    connectionSesion_->senderEngine_ = nullptr;
    ret = connectionSesion_->UpdateSurfaceParam(param);
    EXPECT_EQ(ret, ERR_OK);

    connectionSesion_->recvEngine_ = nullptr;
    ret = connectionSesion_->UpdateSurfaceParam(param);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "AbilityConnectionSessionTest SetSurfaceId_Test_001 end" << std::endl;
}

/**
 * @tc.name: StartStream_Test_001
 * @tc.desc: call StartStream
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(AbilityConnectionSessionTest, StartStream_Test_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionSessionTest StartStream_Test_001 begin" << std::endl;
    ASSERT_NE(connectionSesion_, nullptr);
    int32_t streamId = 0;
    connectionSesion_->connectOption_.needSendStream = true;
    connectionSesion_->InitSenderEngine();
    connectionSesion_->StartStream(streamId);

    connectionSesion_->senderEngine_ = nullptr;
    connectionSesion_->connectOption_.needReceiveStream = true;
    connectionSesion_->InitRecvEngine();
    connectionSesion_->StartStream(streamId);
    
    connectionSesion_->connectOption_.needSendStream = false;
    connectionSesion_->recvEngine_ = nullptr;
    connectionSesion_->StartStream(streamId);

    connectionSesion_->connectOption_.needReceiveStream = false;
    auto ret = connectionSesion_->StartStream(streamId);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "AbilityConnectionSessionTest StartStream_Test_001 end" << std::endl;
}

/**
 * @tc.name: RegisterEventCallback_Test_001
 * @tc.desc: call RegisterEventCallback
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(AbilityConnectionSessionTest, RegisterEventCallback_Test_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionSessionTest RegisterEventCallback_Test_001 begin" << std::endl;
    ASSERT_NE(connectionSesion_, nullptr);
    auto ret = connectionSesion_->RegisterEventCallback(nullptr);
    EXPECT_EQ(ret, INVALID_LISTENER);

    ret = connectionSesion_->CreateStreamChannel("channelName", false);
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "AbilityConnectionSessionTest RegisterEventCallback_Test_001 end" << std::endl;
}

/**
 * @tc.name: ConnectStreamChannel_Test_001
 * @tc.desc: call ConnectStreamChannel
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(AbilityConnectionSessionTest, ConnectStreamChannel_Test_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionSessionTest ConnectStreamChannel_Test_001 begin" << std::endl;
    ASSERT_NE(connectionSesion_, nullptr);
    connectionSesion_->connectOption_.needSendStream = false;
    connectionSesion_->connectOption_.needReceiveStream = false;
    auto ret = connectionSesion_->ConnectStreamChannel();
    EXPECT_EQ(ret, ERR_OK);

    connectionSesion_->connectOption_.needReceiveStream = true;
    connectionSesion_->transChannels_.clear();
    ret = connectionSesion_->ConnectStreamChannel();
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    TransChannelInfo info;
    info.isConnected = true;
    connectionSesion_->connectOption_.needSendStream = true;
    connectionSesion_->transChannels_[TransChannelType::STREAM] = info;
    ret = connectionSesion_->ConnectStreamChannel();
    EXPECT_EQ(ret, ERR_OK);

    connectionSesion_->transChannels_.clear();
    info.isConnected = false;
    connectionSesion_->transChannels_[TransChannelType::STREAM] = info;
    ret = connectionSesion_->ConnectStreamChannel();
    EXPECT_EQ(ret, ERR_OK);

    connectionSesion_->direction_ = CollabrateDirection::COLLABRATE_SOURCE;
    ret = connectionSesion_->ConnectStreamChannel();
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "AbilityConnectionSessionTest ConnectStreamChannel_Test_001 end" << std::endl;
}

/**
 * @tc.name: DoConnectStreamChannel_Test_001
 * @tc.desc: call DoConnectStreamChannel
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(AbilityConnectionSessionTest, DoConnectStreamChannel_Test_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionSessionTest DoConnectStreamChannel_Test_001 begin" << std::endl;
    ASSERT_NE(connectionSesion_, nullptr);
    int32_t channelId = 0;
    auto ret = connectionSesion_->DoConnectStreamChannel(channelId);
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "AbilityConnectionSessionTest DoConnectStreamChannel_Test_001 end" << std::endl;
}

/**
 * @tc.name: OnChannelConnect_Test_001
 * @tc.desc: call OnChannelConnect
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(AbilityConnectionSessionTest, OnChannelConnect_Test_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionSessionTest OnChannelConnect_Test_001 begin" << std::endl;
    ASSERT_NE(connectionSesion_, nullptr);
    int32_t channelId = 0;
    connectionSesion_->transChannels_.clear();
    EXPECT_NO_FATAL_FAILURE(connectionSesion_->OnChannelConnect(channelId));

    TransChannelInfo info;
    info.channelId = channelId;
    connectionSesion_->connectOption_.needSendStream = true;
    connectionSesion_->transChannels_[TransChannelType::STREAM] = info;
    EXPECT_NO_FATAL_FAILURE(connectionSesion_->OnChannelConnect(channelId));

    EXPECT_NO_FATAL_FAILURE(connectionSesion_->UpdateTransChannelStatus(channelId, false));
    EXPECT_NO_FATAL_FAILURE(connectionSesion_->UpdateTransChannelStatus(1, false));
    DTEST_LOG << "AbilityConnectionSessionTest OnChannelConnect_Test_001 end" << std::endl;
}

/**
 * @tc.name: UpdateRecvEngineTransChannel_Test_001
 * @tc.desc: call UpdateRecvEngineTransChannel
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(AbilityConnectionSessionTest, UpdateRecvEngineTransChannel_Test_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionSessionTest UpdateRecvEngineTransChannel_Test_001 begin" << std::endl;
    ASSERT_NE(connectionSesion_, nullptr);
    connectionSesion_->recvEngine_ = nullptr;
    EXPECT_NO_FATAL_FAILURE(connectionSesion_->UpdateRecvEngineTransChannel());

    connectionSesion_->transChannels_.clear();
    connectionSesion_->InitRecvEngine();
    EXPECT_NO_FATAL_FAILURE(connectionSesion_->UpdateRecvEngineTransChannel());

    TransChannelInfo info;
    connectionSesion_->connectOption_.needSendStream = true;
    connectionSesion_->transChannels_[TransChannelType::STREAM] = info;
    EXPECT_NO_FATAL_FAILURE(connectionSesion_->UpdateRecvEngineTransChannel());
    DTEST_LOG << "AbilityConnectionSessionTest UpdateRecvEngineTransChannel_Test_001 end" << std::endl;
}

/**
 * @tc.name: UpdateSenderEngineTransChannel_Test_001
 * @tc.desc: call UpdateSenderEngineTransChannel
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(AbilityConnectionSessionTest, UpdateSenderEngineTransChannel_Test_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionSessionTest UpdateSenderEngineTransChannel_Test_001 begin" << std::endl;
    ASSERT_NE(connectionSesion_, nullptr);
    connectionSesion_->senderEngine_ = nullptr;
    EXPECT_NO_FATAL_FAILURE(connectionSesion_->UpdateSenderEngineTransChannel());

    connectionSesion_->transChannels_.clear();
    connectionSesion_->InitSenderEngine();
    EXPECT_NO_FATAL_FAILURE(connectionSesion_->UpdateSenderEngineTransChannel());

    TransChannelInfo info;
    connectionSesion_->connectOption_.needSendStream = true;
    connectionSesion_->transChannels_[TransChannelType::STREAM] = info;
    EXPECT_NO_FATAL_FAILURE(connectionSesion_->UpdateSenderEngineTransChannel());
    DTEST_LOG << "AbilityConnectionSessionTest UpdateSenderEngineTransChannel_Test_001 end" << std::endl;
}
/**
 * @tc.name: ConnectFileChannel_Test_001
 * @tc.desc: call ConnectFileChannel
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(AbilityConnectionSessionTest, ConnectFileChannel_Test_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionSessionTest ConnectFileChannel_Test_001 begin" << std::endl;
    ASSERT_NE(connectionSesion_, nullptr);
    std::string peerSocketName = "peerSocketName";
    EXPECT_NO_FATAL_FAILURE(connectionSesion_->ConnectFileChannel(peerSocketName));

    EXPECT_NO_FATAL_FAILURE(connectionSesion_->OnRecvPixelMap(nullptr));

    int32_t channelId = 0;
    size_t capacity = 20;
    std::shared_ptr<AVTransDataBuffer> dataBuffer = std::make_shared<AVTransDataBuffer>(capacity);
    connectionSesion_->transChannels_.clear();
    EXPECT_NO_FATAL_FAILURE(connectionSesion_->OnBytesReceived(channelId, dataBuffer));

    TransChannelInfo info;
    info.channelId = channelId;
    connectionSesion_->transChannels_[TransChannelType::STREAM] = info;
    EXPECT_NO_FATAL_FAILURE(connectionSesion_->OnBytesReceived(channelId, dataBuffer));

    connectionSesion_->transChannels_.clear();
    EXPECT_NO_FATAL_FAILURE(connectionSesion_->OnBytesReceived(channelId, dataBuffer));

    connectionSesion_->transChannels_[TransChannelType::STREAM_BYTES] = info;
    EXPECT_NO_FATAL_FAILURE(connectionSesion_->OnBytesReceived(channelId, dataBuffer));

    connectionSesion_->sessionListener_ = nullptr;
    EXPECT_NO_FATAL_FAILURE(connectionSesion_->OnBytesReceived(channelId, dataBuffer));
    DTEST_LOG << "AbilityConnectionSessionTest ConnectFileChannel_Test_001 end" << std::endl;
}

/**
 * @tc.name: SetTimeOut_Test_001
 * @tc.desc: call SetTimeOut
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(AbilityConnectionSessionTest, SetTimeOut_Test_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionSessionTest SetTimeOut_Test_001 begin" << std::endl;
    ASSERT_NE(connectionSesion_, nullptr);
    connectionSesion_->eventHandler_ = nullptr;
    EXPECT_NO_FATAL_FAILURE(connectionSesion_->SetTimeOut(1));
    EXPECT_NO_FATAL_FAILURE(connectionSesion_->RemoveTimeout());
    DTEST_LOG << "AbilityConnectionSessionTest SetTimeOut_Test_001 end" << std::endl;
}

/**
 * @tc.name: SendData_Test_001
 * @tc.desc: call SendData
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(AbilityConnectionSessionTest, SendData_Test_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionSessionTest SendData_Test_001 begin" << std::endl;
    ASSERT_NE(connectionSesion_, nullptr);
    size_t capacity = 20;
    std::shared_ptr<AVTransDataBuffer> dataBuffer = std::make_shared<AVTransDataBuffer>(capacity);
    EXPECT_NO_FATAL_FAILURE(connectionSesion_->SendData(dataBuffer));
    DTEST_LOG << "AbilityConnectionSessionTest SendData_Test_001 end" << std::endl;
}

/**
 * @tc.name: SendImage_Test_001
 * @tc.desc: call SendImage
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(AbilityConnectionSessionTest, SendImage_Test_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionSessionTest SendImage_Test_001 begin" << std::endl;
    ASSERT_NE(connectionSesion_, nullptr);
    connectionSesion_->InitSenderEngine();
    int32_t imageQuality = 30;
    EXPECT_NO_FATAL_FAILURE(connectionSesion_->SendImage(nullptr, imageQuality));
    DTEST_LOG << "AbilityConnectionSessionTest SendImage_Test_001 end" << std::endl;
}

/**
 * @tc.name: StopStream_Test_001
 * @tc.desc: call StopStream
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(AbilityConnectionSessionTest, StopStream_Test_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionSessionTest StopStream_Test_001 begin" << std::endl;
    ASSERT_NE(connectionSesion_, nullptr);
    connectionSesion_->connectOption_.needSendStream = true;
    connectionSesion_->connectOption_.needReceiveStream = true;
    connectionSesion_->senderEngine_ = nullptr;
    connectionSesion_->recvEngine_ = nullptr;
    EXPECT_NO_FATAL_FAILURE(connectionSesion_->StopStream(0));

    connectionSesion_->InitRecvEngine();
    EXPECT_NO_FATAL_FAILURE(connectionSesion_->StopStream(0));

    connectionSesion_->InitSenderEngine();
    EXPECT_NO_FATAL_FAILURE(connectionSesion_->StopStream(0));
    DTEST_LOG << "AbilityConnectionSessionTest StopStream_Test_001 end" << std::endl;
}

/**
 * @tc.name: ExeuteEventCallback_Test_001
 * @tc.desc: call ExeuteEventCallback
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(AbilityConnectionSessionTest, ExeuteEventCallback_Test_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionSessionTest ExeuteEventCallback_Test_001 begin" << std::endl;
    ASSERT_NE(connectionSesion_, nullptr);
    connectionSesion_->listeners_["connect"] = nullptr;
    EventCallbackInfo callbackInfo;
    auto ret = connectionSesion_->ExeuteEventCallback("connect1", callbackInfo);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = connectionSesion_->ExeuteEventCallback("connect", callbackInfo);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "AbilityConnectionSessionTest ExeuteEventCallback_Test_001 end" << std::endl;
}

/**
 * @tc.name: CollabChannelListener_Test_001
 * @tc.desc: call CollabChannelListener
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(AbilityConnectionSessionTest, CollabChannelListener_Test_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionSessionTest CollabChannelListener_Test_001 begin" << std::endl;
    ASSERT_NE(connectionSesion_, nullptr);
    connectionSesion_->channelListener_ = std::make_shared<AbilityConnectionSession::CollabChannelListener>(nullptr);
    EXPECT_NO_FATAL_FAILURE(connectionSesion_->channelListener_->OnConnect(0));

    EXPECT_NO_FATAL_FAILURE(connectionSesion_->channelListener_->OnDisConnect(0,
        ShutdownReason::SHUTDOWN_REASON_UNKNOWN));

    EXPECT_NO_FATAL_FAILURE(connectionSesion_->channelListener_->OnMessage(0, nullptr));

    EXPECT_NO_FATAL_FAILURE(connectionSesion_->channelListener_->OnBytes(0, nullptr));

    FileInfo info;
    EXPECT_NO_FATAL_FAILURE(connectionSesion_->channelListener_->OnSendFile(0, info));

    EXPECT_NO_FATAL_FAILURE(connectionSesion_->channelListener_->OnRecvFile(0, info));

    EXPECT_NO_FATAL_FAILURE(connectionSesion_->channelListener_->GetRecvPath(0));

    connectionSesion_->pixelMapListener = std::make_shared<AbilityConnectionSession::PixelMapListener>();
    EXPECT_NO_FATAL_FAILURE(connectionSesion_->pixelMapListener->OnRecvPixelMap(nullptr));
    DTEST_LOG << "AbilityConnectionSessionTest CollabChannelListener_Test_001 end" << std::endl;
}

/**
 * @tc.name: HandleSessionConnect_Test_001
 * @tc.desc: call HandleSessionConnect
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(AbilityConnectionSessionTest, HandleSessionConnect_Test_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionSessionTest HandleSessionConnect_Test_001 begin" << std::endl;
    ASSERT_NE(connectionSesion_, nullptr);
    connectionSesion_->sessionStatus_ = SessionStatus::CONNECTED;
    EXPECT_NO_FATAL_FAILURE(connectionSesion_->HandleSessionConnect());

    connectionSesion_->sessionListener_ = nullptr;
    EXPECT_NO_FATAL_FAILURE(connectionSesion_->HandleSessionConnect());

    EXPECT_NO_FATAL_FAILURE(connectionSesion_->OnChannelClosed(30, ShutdownReason::SHUTDOWN_REASON_LNN_OFFLINE));
    DTEST_LOG << "AbilityConnectionSessionTest HandleSessionConnect_Test_001 end" << std::endl;
}
}
}
