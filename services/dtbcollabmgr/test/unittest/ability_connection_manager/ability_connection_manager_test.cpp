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

#include "ability_connection_manager_test.h"

#include "dtbcollabmgr_log.h"
#include "test_log.h"

using namespace testing;
using namespace testing::ext;

namespace {
    const int32_t WAITTIME = 10000;
}

namespace OHOS {
namespace DistributedCollab {
void AbilityConnectionMgrTest::SetUpTestCase()
{
    DTEST_LOG << "AbilityConnectionMgrTest::SetUpTestCase" << std::endl;
}

void AbilityConnectionMgrTest::TearDownTestCase()
{
    DTEST_LOG << "AbilityConnectionMgrTest::TearDownTestCase" << std::endl;
}

void AbilityConnectionMgrTest::TearDown()
{
    DTEST_LOG << "AbilityConnectionMgrTest::TearDown" << std::endl;
    AbilityConnectionManager::GetInstance().sessionMap_.clear();
    AbilityConnectionManager::GetInstance().streamMap_.clear();
    usleep(WAITTIME);
}

void AbilityConnectionMgrTest::SetUp()
{
    DTEST_LOG << "AbilityConnectionMgrTest::SetUp" << std::endl;
    AbilityConnectionManager::GetInstance().sessionMap_.clear();
    AbilityConnectionManager::GetInstance().streamMap_.clear();
}

void CreateSessionMap(int32_t sessionId)
{
    PeerInfo peerInfo = {"", "bundleName", "moduleName", "abilityName", "serverId"};
    PeerInfo localInfo = {"", "bundleName1", "moduleName1", "abilityName1", "serverId1"};
    ConnectOption options;
    std::string serverId = "test";
    AbilityConnectionSessionInfo info{serverId, localInfo, peerInfo};
    auto connectionSesion = std::make_shared<AbilityConnectionSession>(1, "serverSocketName",
        info, options);
    AbilityConnectionManager::GetInstance().sessionMap_.emplace(sessionId, connectionSesion);
}

/**
 * @tc.name: IsVaildPeerInfo_Test_001
 * @tc.desc: call IsVaildPeerInfo
 * @tc.type: FUNC
 * @tc.require: IBP3MC
 */
HWTEST_F(AbilityConnectionMgrTest, IsVaildPeerInfo_Test_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionMgr IsVaildPeerInfo_Test_001 begin" << std::endl;
    PeerInfo peerInfo;
    EXPECT_FALSE(AbilityConnectionManager::GetInstance().IsVaildPeerInfo(peerInfo));
    peerInfo.deviceId = "deviceId";
    EXPECT_FALSE(AbilityConnectionManager::GetInstance().IsVaildPeerInfo(peerInfo));
    peerInfo.bundleName = "bundleName";
    EXPECT_FALSE(AbilityConnectionManager::GetInstance().IsVaildPeerInfo(peerInfo));
    peerInfo.moduleName = "moduleName";
    EXPECT_FALSE(AbilityConnectionManager::GetInstance().IsVaildPeerInfo(peerInfo));
    peerInfo.abilityName = "abilityName";
    EXPECT_FALSE(AbilityConnectionManager::GetInstance().IsVaildPeerInfo(peerInfo));
    peerInfo.serverId = "serverId";
    EXPECT_TRUE(AbilityConnectionManager::GetInstance().IsVaildPeerInfo(peerInfo));
    DTEST_LOG << "AbilityConnectionMgr IsVaildPeerInfo_Test_001 end" << std::endl;
}

/**
 * @tc.name: IsVaildConnectOption_Test_001
 * @tc.desc: call IsVaildConnectOption
 * @tc.type: FUNC
 * @tc.require: IBP3MC
 */
HWTEST_F(AbilityConnectionMgrTest, IsVaildConnectOption_Test_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionMgr IsVaildConnectOption_Test_001 begin" << std::endl;
    ConnectOption opt;
    opt.needSendStream = false;
    opt.needReceiveStream = false;
    EXPECT_TRUE(AbilityConnectionManager::GetInstance().IsVaildConnectOption(opt));
    opt.needSendStream = true;
    EXPECT_TRUE(AbilityConnectionManager::GetInstance().IsVaildConnectOption(opt));
    opt.needReceiveStream = true;
    EXPECT_FALSE(AbilityConnectionManager::GetInstance().IsVaildConnectOption(opt));
    DTEST_LOG << "AbilityConnectionMgr IsVaildConnectOption_Test_001 end" << std::endl;
}

/**
 * @tc.name: GetAbilityConnectionSession_Test_001
 * @tc.desc: call GetAbilityConnectionSession
 * @tc.type: FUNC
 * @tc.require: IBP3MC
 */
HWTEST_F(AbilityConnectionMgrTest, GetAbilityConnectionSession_Test_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionMgr GetAbilityConnectionSession_Test_001 begin" << std::endl;
    int32_t sessionId = -1;
    auto rltSesion = AbilityConnectionManager::GetInstance().GetAbilityConnectionSession(sessionId);
    EXPECT_EQ(rltSesion, nullptr);

    sessionId = 1;
    rltSesion = AbilityConnectionManager::GetInstance().GetAbilityConnectionSession(sessionId);
    EXPECT_EQ(rltSesion, nullptr);

    CreateSessionMap(sessionId);
    rltSesion = AbilityConnectionManager::GetInstance().GetAbilityConnectionSession(sessionId);
    EXPECT_NE(rltSesion, nullptr);
    DTEST_LOG << "AbilityConnectionMgr GetAbilityConnectionSession_Test_001 end" << std::endl;
}

/**
 * @tc.name: DestroySession_Test_001
 * @tc.desc: call DestroySession
 * @tc.type: FUNC
 * @tc.require: IBP3MC
 */
HWTEST_F(AbilityConnectionMgrTest, DestroySession_Test_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionMgr DestroySession_Test_001 begin" << std::endl;
    int32_t sessionId = 1;
    auto rlt = AbilityConnectionManager::GetInstance().DestroySession(sessionId);
    EXPECT_EQ(rlt, INVALID_PARAMETERS_ERR);

    CreateSessionMap(sessionId);
    rlt = AbilityConnectionManager::GetInstance().DestroySession(sessionId);
    EXPECT_EQ(rlt, ERR_OK);
    DTEST_LOG << "AbilityConnectionMgr DestroySession_Test_001 end" << std::endl;
}

/**
 * @tc.name: getPeerInfoBySessionId_Test_001
 * @tc.desc: call getPeerInfoBySessionId
 * @tc.type: FUNC
 * @tc.require: IBP3MC
 */
HWTEST_F(AbilityConnectionMgrTest, getPeerInfoBySessionId_Test_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionMgr getPeerInfoBySessionId_Test_001 begin" << std::endl;
    int32_t sessionId = 1;
    PeerInfo rltInfo;
    auto rlt = AbilityConnectionManager::GetInstance().getPeerInfoBySessionId(sessionId, rltInfo);
    EXPECT_EQ(rlt, INVALID_PARAMETERS_ERR);

    CreateSessionMap(sessionId);
    rlt = AbilityConnectionManager::GetInstance().getPeerInfoBySessionId(sessionId, rltInfo);
    EXPECT_EQ(rlt, ERR_OK);
    DTEST_LOG << "AbilityConnectionMgr getPeerInfoBySessionId_Test_001 end" << std::endl;
}

/**
 * @tc.name: ConnectSession_Test_001
 * @tc.desc: call ConnectSession
 * @tc.type: FUNC
 * @tc.require: IBP3MC
 */
HWTEST_F(AbilityConnectionMgrTest, ConnectSession_Test_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionMgr ConnectSession_Test_001 begin" << std::endl;
    int32_t sessionId = 1;
    std::function<void(const ConnectResult& result)> callback;
    auto rlt = AbilityConnectionManager::GetInstance().ConnectSession(sessionId, callback);
    EXPECT_EQ(rlt, INVALID_SESSION_ID);

    CreateSessionMap(sessionId);
    rlt = AbilityConnectionManager::GetInstance().ConnectSession(sessionId, callback);
    EXPECT_NE(rlt, ERR_OK);
    DTEST_LOG << "AbilityConnectionMgr ConnectSession_Test_001 end" << std::endl;
}

/**
 * @tc.name: DisconnectSession_Test_001
 * @tc.desc: call DisconnectSession
 * @tc.type: FUNC
 * @tc.require: IBP3MC
 */
HWTEST_F(AbilityConnectionMgrTest, DisconnectSession_Test_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionMgr DisconnectSession_Test_001 begin" << std::endl;
    int32_t sessionId = 1;
    auto rlt = AbilityConnectionManager::GetInstance().DisconnectSession(sessionId);
    EXPECT_EQ(rlt, INVALID_PARAMETERS_ERR);

    CreateSessionMap(sessionId);
    rlt = AbilityConnectionManager::GetInstance().DisconnectSession(sessionId);
    EXPECT_EQ(rlt, ERR_OK);
    DTEST_LOG << "AbilityConnectionMgr DisconnectSession_Test_001 end" << std::endl;
}

/**
 * @tc.name: AcceptConnect_Test_001
 * @tc.desc: call AcceptConnect
 * @tc.type: FUNC
 * @tc.require: IBP3MC
 */
HWTEST_F(AbilityConnectionMgrTest, AcceptConnect_Test_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionMgr AcceptConnect_Test_001 begin" << std::endl;
    int32_t sessionId = 1;
    std::string token = "token";
    auto rlt = AbilityConnectionManager::GetInstance().AcceptConnect(sessionId, token);
    EXPECT_EQ(rlt, INVALID_PARAMETERS_ERR);

    CreateSessionMap(sessionId);
    rlt = AbilityConnectionManager::GetInstance().AcceptConnect(sessionId, token);
    EXPECT_EQ(rlt, ERR_OK);
    DTEST_LOG << "AbilityConnectionMgr AcceptConnect_Test_001 end" << std::endl;
}

/**
 * @tc.name: NotifyCollabResult_Test_001
 * @tc.desc: call NotifyCollabResult
 * @tc.type: FUNC
 * @tc.require: IBP3MC
 */
HWTEST_F(AbilityConnectionMgrTest, NotifyCollabResult_Test_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionMgr NotifyCollabResult_Test_001 begin" << std::endl;
    int32_t sessionId = 1;
    int32_t result = ERR_OK;
    std::string peerServerName = "peer";
    std::string dmsServerToken = "dmsServerToken";
    std::string reason = "reason";
    auto rlt = AbilityConnectionManager::GetInstance().NotifyCollabResult(
        sessionId, result, peerServerName, dmsServerToken, reason);
    EXPECT_EQ(rlt, INVALID_PARAMETERS_ERR);

    CreateSessionMap(sessionId);
    rlt = AbilityConnectionManager::GetInstance().NotifyCollabResult(
        sessionId, result, peerServerName, dmsServerToken, reason);
    EXPECT_NE(rlt, ERR_OK);

    result = 2;
    rlt = AbilityConnectionManager::GetInstance().NotifyCollabResult(
        sessionId, result, peerServerName, dmsServerToken, reason);
    EXPECT_EQ(rlt, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "AbilityConnectionMgr NotifyCollabResult_Test_001 end" << std::endl;
}

/**
 * @tc.name: NotifyDisconnect_Test_001
 * @tc.desc: call NotifyDisconnect
 * @tc.type: FUNC
 * @tc.require: IBP3MC
 */
HWTEST_F(AbilityConnectionMgrTest, NotifyDisconnect_Test_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionMgr NotifyDisconnect_Test_001 begin" << std::endl;
    int32_t sessionId = 1;
    auto rlt = AbilityConnectionManager::GetInstance().NotifyDisconnect(sessionId);
    EXPECT_EQ(rlt, INVALID_PARAMETERS_ERR);

    CreateSessionMap(sessionId);
    rlt = AbilityConnectionManager::GetInstance().NotifyDisconnect(sessionId);
    EXPECT_EQ(rlt, ERR_OK);
    DTEST_LOG << "AbilityConnectionMgr NotifyDisconnect_Test_001 end" << std::endl;
}

/**
 * @tc.name: SendMessage_Test_001
 * @tc.desc: call SendMessage
 * @tc.type: FUNC
 * @tc.require: IBP3MC
 */
HWTEST_F(AbilityConnectionMgrTest, SendMessage_Test_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionMgr SendMessage_Test_001 begin" << std::endl;
    int32_t sessionId = 1;
    std::string msg = "test";
    auto rlt = AbilityConnectionManager::GetInstance().SendMessage(sessionId, msg);
    EXPECT_EQ(rlt, INVALID_PARAMETERS_ERR);

    CreateSessionMap(sessionId);
    rlt = AbilityConnectionManager::GetInstance().SendMessage(sessionId, msg);
    EXPECT_NE(rlt, ERR_OK);
    DTEST_LOG << "AbilityConnectionMgr SendMessage_Test_001 end" << std::endl;
}

/**
 * @tc.name: SendData_Test_001
 * @tc.desc: call SendData
 * @tc.type: FUNC
 * @tc.require: IBP3MC
 */
HWTEST_F(AbilityConnectionMgrTest, SendData_Test_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionMgr SendData_Test_001 begin" << std::endl;
    int32_t sessionId = -1;
    std::shared_ptr<AVTransDataBuffer> buffer = nullptr;
    auto rlt = AbilityConnectionManager::GetInstance().SendData(sessionId, buffer);
    EXPECT_EQ(rlt, INVALID_PARAMETERS_ERR);

    CreateSessionMap(sessionId);
    rlt = AbilityConnectionManager::GetInstance().SendData(sessionId, buffer);
    EXPECT_NE(rlt, ERR_OK);
    DTEST_LOG << "AbilityConnectionMgr SendData_Test_001 end" << std::endl;
}

/**
 * @tc.name: SendImage_Test_001
 * @tc.desc: call SendImage
 * @tc.type: FUNC
 * @tc.require: IBP3MC
 */
HWTEST_F(AbilityConnectionMgrTest, SendImage_Test_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionMgr SendImage_Test_001 begin" << std::endl;
    int32_t sessionId = 1;
    std::shared_ptr<Media::PixelMap> image = nullptr;
    auto rlt = AbilityConnectionManager::GetInstance().SendImage(sessionId, image);
    EXPECT_EQ(rlt, INVALID_PARAMETERS_ERR);

    CreateSessionMap(sessionId);
    rlt = AbilityConnectionManager::GetInstance().SendImage(sessionId, image);
    EXPECT_NE(rlt, ERR_OK);
    DTEST_LOG << "AbilityConnectionMgr SendImage_Test_001 end" << std::endl;
}

/**
 * @tc.name: SendFile_Test_001
 * @tc.desc: call SendFile
 * @tc.type: FUNC
 * @tc.require: IBP3MC
 */
HWTEST_F(AbilityConnectionMgrTest, SendFile_Test_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionMgr SendFile_Test_001 begin" << std::endl;
    int32_t sessionId = 1;
    std::vector<std::string> sFiles;
    std::vector<std::string> dFiles;
    auto rlt = AbilityConnectionManager::GetInstance().SendFile(sessionId, sFiles, dFiles);
    EXPECT_EQ(rlt, INVALID_PARAMETERS_ERR);

    CreateSessionMap(sessionId);
    rlt = AbilityConnectionManager::GetInstance().SendFile(sessionId, sFiles, dFiles);
    EXPECT_NE(rlt, ERR_OK);
    DTEST_LOG << "AbilityConnectionMgr SendFile_Test_001 end" << std::endl;
}

/**
 * @tc.name: CreateStream_Test_001
 * @tc.desc: call CreateStream
 * @tc.type: FUNC
 * @tc.require: IBP3MC
 */
HWTEST_F(AbilityConnectionMgrTest, CreateStream_Test_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionMgr CreateStream_Test_001 begin" << std::endl;
    int32_t sessionId = 1;
    StreamParams param;
    int32_t streamId = 0;
    auto rlt = AbilityConnectionManager::GetInstance().CreateStream(sessionId, param, streamId);
    EXPECT_EQ(rlt, INVALID_PARAMETERS_ERR);

    CreateSessionMap(sessionId);
    rlt = AbilityConnectionManager::GetInstance().CreateStream(sessionId, param, streamId);
    EXPECT_NE(rlt, ERR_OK);
    DTEST_LOG << "AbilityConnectionMgr CreateStream_Test_001 end" << std::endl;
}

/**
 * @tc.name: SetSurfaceId_Test_001
 * @tc.desc: call SetSurfaceId
 * @tc.type: FUNC
 * @tc.require: IBP3MC
 */
HWTEST_F(AbilityConnectionMgrTest, SetSurfaceId_Test_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionMgr SetSurfaceId_Test_001 begin" << std::endl;
    int32_t sessionId = 1;
    int32_t streamId = 1;
    std::string surfaceId = "surfaceId";
    SurfaceParams param;
    auto rlt = AbilityConnectionManager::GetInstance().SetSurfaceId(streamId, surfaceId, param);
    EXPECT_EQ(rlt, INVALID_PARAMETERS_ERR);

    CreateSessionMap(sessionId);
    AbilityConnectionManager::GetInstance().streamMap_[streamId] = sessionId;
    rlt = AbilityConnectionManager::GetInstance().SetSurfaceId(streamId, surfaceId, param);
    EXPECT_NE(rlt, ERR_OK);
    DTEST_LOG << "AbilityConnectionMgr SetSurfaceId_Test_001 end" << std::endl;
}

/**
 * @tc.name: GetSurfaceId_Test_001
 * @tc.desc: call GetSurfaceId
 * @tc.type: FUNC
 * @tc.require: IBP3MC
 */
HWTEST_F(AbilityConnectionMgrTest, GetSurfaceId_Test_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionMgr GetSurfaceId_Test_001 begin" << std::endl;
    int32_t sessionId = 1;
    int32_t streamId = 1;
    std::string surfaceId = "surfaceId";
    SurfaceParams param;
    auto rlt = AbilityConnectionManager::GetInstance().GetSurfaceId(streamId, param, surfaceId);
    EXPECT_EQ(rlt, INVALID_PARAMETERS_ERR);

    CreateSessionMap(sessionId);
    AbilityConnectionManager::GetInstance().streamMap_[streamId] = sessionId;
    rlt = AbilityConnectionManager::GetInstance().GetSurfaceId(streamId, param, surfaceId);
    EXPECT_NE(rlt, ERR_OK);
    DTEST_LOG << "AbilityConnectionMgr AcceptConnect_Test_001 end" << std::endl;
}

/**
 * @tc.name: UpdateSurfaceParam_Test_001
 * @tc.desc: call UpdateSurfaceParam
 * @tc.type: FUNC
 * @tc.require: IBP3MC
 */
HWTEST_F(AbilityConnectionMgrTest, UpdateSurfaceParam_Test_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionMgr UpdateSurfaceParam_Test_001 begin" << std::endl;
    int32_t sessionId = 1;
    int32_t streamId = 1;
    SurfaceParams param;
    auto rlt = AbilityConnectionManager::GetInstance().UpdateSurfaceParam(streamId, param);
    EXPECT_EQ(rlt, INVALID_PARAMETERS_ERR);

    CreateSessionMap(sessionId);
    AbilityConnectionManager::GetInstance().streamMap_[streamId] = sessionId;
    rlt = AbilityConnectionManager::GetInstance().UpdateSurfaceParam(streamId, param);
    EXPECT_NE(rlt, ERR_OK);
    DTEST_LOG << "AbilityConnectionMgr AcceptConnect_Test_001 end" << std::endl;
}

/**
 * @tc.name: DestroyStream_Test_001
 * @tc.desc: call DestroyStream
 * @tc.type: FUNC
 * @tc.require: IBP3MC
 */
HWTEST_F(AbilityConnectionMgrTest, DestroyStream_Test_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionMgr DestroyStream_Test_001 begin" << std::endl;
    int32_t sessionId = 1;
    int32_t streamId = 1;
    auto rlt = AbilityConnectionManager::GetInstance().DestroyStream(streamId);
    EXPECT_EQ(rlt, INVALID_PARAMETERS_ERR);

    CreateSessionMap(sessionId);
    AbilityConnectionManager::GetInstance().streamMap_[streamId] = sessionId;
    rlt = AbilityConnectionManager::GetInstance().DestroyStream(streamId);
    EXPECT_EQ(rlt, ERR_OK);
    DTEST_LOG << "AbilityConnectionMgr DestroyStream_Test_001 end" << std::endl;
}

/**
 * @tc.name: StartStream_Test_001
 * @tc.desc: call StartStream
 * @tc.type: FUNC
 * @tc.require: IBP3MC
 */
HWTEST_F(AbilityConnectionMgrTest, StartStream_Test_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionMgr StartStream_Test_001 begin" << std::endl;
    int32_t sessionId = 1;
    int32_t streamId = 1;
    auto rlt = AbilityConnectionManager::GetInstance().StartStream(streamId);
    EXPECT_EQ(rlt, INVALID_PARAMETERS_ERR);

    CreateSessionMap(sessionId);
    AbilityConnectionManager::GetInstance().streamMap_[streamId] = sessionId;
    rlt = AbilityConnectionManager::GetInstance().StartStream(streamId);
    EXPECT_NE(rlt, ERR_OK);
    DTEST_LOG << "AbilityConnectionMgr StartStream_Test_001 end" << std::endl;
}

/**
 * @tc.name: StopStream_Test_001
 * @tc.desc: call StopStream
 * @tc.type: FUNC
 * @tc.require: IBP3MC
 */
HWTEST_F(AbilityConnectionMgrTest, StopStream_Test_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionMgr StopStream_Test_001 begin" << std::endl;
    int32_t sessionId = 1;
    int32_t streamId = 1;
    auto rlt = AbilityConnectionManager::GetInstance().StopStream(streamId);
    EXPECT_EQ(rlt, INVALID_PARAMETERS_ERR);

    CreateSessionMap(sessionId);
    AbilityConnectionManager::GetInstance().streamMap_[streamId] = sessionId;
    rlt = AbilityConnectionManager::GetInstance().StopStream(streamId);
    EXPECT_EQ(rlt, ERR_OK);
    DTEST_LOG << "AbilityConnectionMgr StopStreamTest_001 end" << std::endl;
}

/**
 * @tc.name: RegisterEventCallback_Test_001
 * @tc.desc: call RegisterEventCallback
 * @tc.type: FUNC
 * @tc.require: IBP3MC
 */
HWTEST_F(AbilityConnectionMgrTest, RegisterEventCallback_Test_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionMgr RegisterEventCallback_Test_001 begin" << std::endl;
    int32_t sessionId = 1;
    std::string eventType = "test";
    std::shared_ptr<JsAbilityConnectionSessionListener> listener = nullptr;
    auto rlt = AbilityConnectionManager::GetInstance().RegisterEventCallback(sessionId, eventType, listener);
    EXPECT_EQ(rlt, INVALID_PARAMETERS_ERR);

    rlt = AbilityConnectionManager::GetInstance().UnregisterEventCallback(sessionId, eventType);
    EXPECT_EQ(rlt, INVALID_PARAMETERS_ERR);

    CreateSessionMap(sessionId);
    rlt = AbilityConnectionManager::GetInstance().RegisterEventCallback(sessionId, eventType, listener);
    EXPECT_EQ(rlt, ERR_OK);

    rlt = AbilityConnectionManager::GetInstance().UnregisterEventCallback(sessionId, eventType);
    EXPECT_EQ(rlt, ERR_OK);
    DTEST_LOG << "AbilityConnectionMgr SendMessage_Test_001 end" << std::endl;
}

/**
 * @tc.name: GetSessionToken_Test_001
 * @tc.desc: call GetSessionToken
 * @tc.type: FUNC
 * @tc.require: IBP3MC
 */
HWTEST_F(AbilityConnectionMgrTest, GetSessionToken_Test_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionMgr GetSessionToken_Test_001 begin" << std::endl;
    int32_t sessionId = 1;
    auto rlt = AbilityConnectionManager::GetInstance().GetSessionToken(sessionId);
    EXPECT_EQ(rlt, "");

    CreateSessionMap(sessionId);
    rlt = AbilityConnectionManager::GetInstance().GetSessionToken(sessionId);
    EXPECT_EQ(rlt, "");
    DTEST_LOG << "AbilityConnectionMgr SendMessage_Test_001 end" << std::endl;
}

/**
 * @tc.name: UpdateClientSession_Test_001
 * @tc.desc: call UpdateClientSession
 * @tc.type: FUNC
 * @tc.require: IBP3MC
 */
HWTEST_F(AbilityConnectionMgrTest, UpdateClientSession_Test_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionMgr UpdateClientSession_Test_001 begin" << std::endl;
    AbilityConnectionManager::GetInstance().clientSessionMap_.clear();
    AbilityConnectionManager::GetInstance().serverSessionMap_.clear();
    PeerInfo peerInfo = {"", "bundleName", "moduleName", "abilityName", "serverId"};
    PeerInfo localInfo = {"", "bundleName1", "moduleName1", "abilityName1", "serverId1"};
    std::string serverId = "test";
    AbilityConnectionSessionInfo info{serverId, localInfo, peerInfo};

    int32_t sessionId = 1;
    auto rlt = AbilityConnectionManager::GetInstance().UpdateClientSession(info, sessionId);
    EXPECT_EQ(rlt, ERR_OK);

    rlt = AbilityConnectionManager::GetInstance().UpdateClientSession(info, sessionId);
    EXPECT_EQ(rlt, SAME_SESSION_IS_CONNECTING);

    AbilityConnectionManager::GetInstance().clientSessionMap_.clear();
    AbilityConnectionManager::GetInstance().serverSessionMap_[info] = sessionId;
    rlt = AbilityConnectionManager::GetInstance().UpdateClientSession(info, sessionId);
    EXPECT_EQ(rlt, SAME_SESSION_IS_CONNECTING);
    AbilityConnectionManager::GetInstance().clientSessionMap_.clear();
    AbilityConnectionManager::GetInstance().serverSessionMap_.clear();
    DTEST_LOG << "AbilityConnectionMgr UpdateClientSession_Test_001 end" << std::endl;
}

/**
 * @tc.name: UpdateServerSession_Test_001
 * @tc.desc: call UpdateServerSession
 * @tc.type: FUNC
 * @tc.require: IBP3MC
 */
HWTEST_F(AbilityConnectionMgrTest, UpdateServerSession_Test_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionMgr UpdateServerSession_Test_001 begin" << std::endl;
    AbilityConnectionManager::GetInstance().clientSessionMap_.clear();
    AbilityConnectionManager::GetInstance().serverSessionMap_.clear();
    PeerInfo peerInfo = {"", "bundleName", "moduleName", "abilityName", "serverId"};
    PeerInfo localInfo = {"", "bundleName1", "moduleName1", "abilityName1", "serverId1"};
    std::string serverId = "test";
    AbilityConnectionSessionInfo info{serverId, localInfo, peerInfo};

    int32_t sessionId = 1;
    auto rlt = AbilityConnectionManager::GetInstance().UpdateServerSession(info, sessionId);
    EXPECT_EQ(rlt, ERR_OK);

    rlt = AbilityConnectionManager::GetInstance().UpdateServerSession(info, sessionId);
    EXPECT_EQ(rlt, SAME_SESSION_IS_CONNECTING);

    AbilityConnectionManager::GetInstance().serverSessionMap_.clear();
    AbilityConnectionManager::GetInstance().clientSessionMap_[info] = sessionId;
    rlt = AbilityConnectionManager::GetInstance().UpdateServerSession(info, sessionId);
    EXPECT_EQ(rlt, ERR_OK);
    AbilityConnectionManager::GetInstance().clientSessionMap_.clear();
    AbilityConnectionManager::GetInstance().serverSessionMap_.clear();
    DTEST_LOG << "AbilityConnectionMgr UpdateClientSession_Test_001 end" << std::endl;
}

/**
 * @tc.name: DeleteConnectSession_Test_001
 * @tc.desc: call DeleteConnectSession
 * @tc.type: FUNC
 * @tc.require: IBP3MC
 */
HWTEST_F(AbilityConnectionMgrTest, DeleteConnectSession_Test_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionMgr DeleteConnectSession_Test_001 begin" << std::endl;
    AbilityConnectionManager::GetInstance().clientSessionMap_.clear();
    AbilityConnectionManager::GetInstance().serverSessionMap_.clear();
    PeerInfo peerInfo = {"", "bundleName", "moduleName", "abilityName", "serverId"};
    PeerInfo localInfo = {"", "bundleName1", "moduleName1", "abilityName1", "serverId1"};
    std::string serverId = "test";
    AbilityConnectionSessionInfo info{serverId, localInfo, peerInfo};

    int32_t sessionId = 1;
    auto rlt = AbilityConnectionManager::GetInstance().DeleteConnectSession(info, sessionId);
    EXPECT_EQ(rlt, ERR_OK);

    int32_t srvId = 2;
    int32_t cltId = 3;
    AbilityConnectionManager::GetInstance().serverSessionMap_[info] = srvId;
    AbilityConnectionManager::GetInstance().clientSessionMap_[info] = cltId;
    rlt = AbilityConnectionManager::GetInstance().DeleteConnectSession(info, sessionId);
    EXPECT_EQ(rlt, ERR_OK);

    rlt = AbilityConnectionManager::GetInstance().DeleteConnectSession(info, srvId);
    EXPECT_EQ(rlt, ERR_OK);

    rlt = AbilityConnectionManager::GetInstance().DeleteConnectSession(info, cltId);
    EXPECT_EQ(AbilityConnectionManager::GetInstance().serverSessionMap_.count(info), 0);
    EXPECT_EQ(AbilityConnectionManager::GetInstance().clientSessionMap_.count(info), 0);
    AbilityConnectionManager::GetInstance().clientSessionMap_.clear();
    AbilityConnectionManager::GetInstance().serverSessionMap_.clear();
    DTEST_LOG << "AbilityConnectionMgr DeleteConnectSession_Test_001 end" << std::endl;
}
}
}
