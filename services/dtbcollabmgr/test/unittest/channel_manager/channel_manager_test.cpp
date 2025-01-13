/*
* Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "channel_manager_test.h"
#include "channel_manager.h"
#include "dtbcollabmgr_log.h"
#include "securec.h"
#include "ichannel_listener_mock.h"
#include <chrono>
#include <thread>

namespace OHOS {
namespace DistributedCollab {
namespace {
    static const std::string TAG = "DSchedCollabChannelManagerTest";
    using namespace testing;
    using namespace testing::ext;
    static constexpr int32_t NUM_1234 = 1234;
    static constexpr int32_t NUM_MINUS_1 = -1;
    static constexpr int32_t MESSAGE_START_ID = 1001;
    static constexpr int32_t BYTES_START_ID = 2001;
    static constexpr int32_t STREAM_START_ID = 3001;
    static constexpr int32_t CHANNGE_GAP = 1000;
    static constexpr int32_t INVALID_CHANNEL = 9999;
    static constexpr int32_t SLEEP_FOR_INIT = 100;
    static constexpr int32_t NUM_1024 = 1024;
    static constexpr int32_t NUM_1 = 1;
    static constexpr int32_t NUM_200 = 200;
}

void ChannelManagerTest::SetUpTestCase()
{
    HILOGI("ChannelManagerTest::SetUpTestCase");
}

void ChannelManagerTest::TearDownTestCase()
{
    HILOGI("ChannelManagerTest::TearDownTestCase");
}

void ChannelManagerTest::SetUp()
{
    HILOGI("ChannelManagerTest::SetUp");
}

void ChannelManagerTest::TearDown()
{
    HILOGI("ChannelManagerTest::TearDown");
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_FOR_INIT));
    ChannelManager::GetInstance().DeInit();
}

/**
 * @tc.name: TestInit_Success
 * @tc.desc: Test for Init when all conditions are successful
 * @tc.type: FUNC
 */
HWTEST_F(ChannelManagerTest, TestInit_Success, TestSize.Level1)
{
    EXPECT_CALL(mockSoftbus, Socket(testing::_))
        .WillOnce(testing::Return(NUM_1234));

    EXPECT_CALL(mockSoftbus, Listen(testing::_, testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(ERR_OK));

    int32_t result = ChannelManager::GetInstance().Init(ownerName);

    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: TestInit_SocketFailure
 * @tc.desc: Test for Init when CreateServerSocket fails
 * @tc.type: FUNC
 */
HWTEST_F(ChannelManagerTest, TestInit_SocketFailure, TestSize.Level1)
{
    EXPECT_CALL(mockSoftbus, Socket(testing::_))
        .WillOnce(testing::Return(NUM_MINUS_1));

    int32_t result = ChannelManager::GetInstance().Init(ownerName);

    EXPECT_EQ(result, CREATE_SOCKET_FAILED);
}

/**
 * @tc.name: TestInit_ListenFailure
 * @tc.desc: Test for Init when Listen fails
 * @tc.type: FUNC
 */
HWTEST_F(ChannelManagerTest, TestInit_ListenFailure, TestSize.Level1)
{
    EXPECT_CALL(mockSoftbus, Socket(testing::_))
        .WillOnce(testing::Return(NUM_1234));

    EXPECT_CALL(mockSoftbus, Listen(testing::_, testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(-2));

    int32_t result = ChannelManager::GetInstance().Init(ownerName);

    EXPECT_EQ(result, LISTEN_SOCKET_FAILED);
}

/**
 * @tc.name: CreateServerChannel_Success
 * @tc.desc: Test for CreateServerChannel when the base channel is successfully created
 * @tc.type: FUNC
 */
HWTEST_F(ChannelManagerTest, CreateServerChannel_Success, TestSize.Level1)
{
    std::string channelName = "TestChannel";
    ChannelDataType dataType = ChannelDataType::MESSAGE;
    ChannelPeerInfo peerInfo = { "peerName", "networkId" };

    int32_t channelId = ChannelManager::GetInstance().CreateServerChannel(channelName, dataType, peerInfo);
    EXPECT_EQ(channelId, MESSAGE_START_ID);
}

/**
 * @tc.name: CreateServerChannel_ExceedMax_Failed
 * @tc.desc: Test for CreateServerChannel when the base channel is ExceedMax_Failed
 * @tc.type: FUNC
 */
HWTEST_F(ChannelManagerTest, CreateServerChannel_ExceedMax_Failed, TestSize.Level1)
{
    std::string channelName = "TestChannel";
    ChannelDataType dataType = ChannelDataType::MESSAGE;
    ChannelPeerInfo peerInfo = { "peerName", "networkId" };

    int32_t channelId = 0;
    for (int32_t i = 0; i < CHANNGE_GAP + 1; i++)
    {
        channelId = ChannelManager::GetInstance().CreateServerChannel(channelName, dataType, peerInfo);
    }
    EXPECT_EQ(channelId, CREATE_SERVER_CHANNEL_FAILED);
}

/**
 * @tc.name: CreateClientChannel_Success
 * @tc.desc: Test for CreateClientChannel when CreateBaseChannel and RegisterSocket succeed
 * @tc.type: FUNC
 */
HWTEST_F(ChannelManagerTest, CreateClientChannel_Success, TestSize.Level1)
{
    // Setup the test data
    std::string channelName = "testClientChannel";
    ChannelDataType dataType = ChannelDataType::MESSAGE;
    ChannelPeerInfo peerInfo = { "peerName", "networkId" };

    EXPECT_CALL(mockSoftbus, Socket(testing::_))
        .WillOnce(testing::Return(NUM_1234));

    // Call CreateClientChannel and check the result
    int32_t result = ChannelManager::GetInstance().CreateClientChannel(channelName, dataType, peerInfo);
    EXPECT_EQ(result, MESSAGE_START_ID);  // Should return valid channelId
}

/**
 * @tc.name: CreateClientChannel_CreateSocket_Fail
 * @tc.desc: Test for CreateClientChannel when CreateBaseChannel fails
 * @tc.type: FUNC
 */
HWTEST_F(ChannelManagerTest, CreateClientChannel_CreateSocket_Fail, TestSize.Level1)
{
    // Setup the test data
    std::string channelName = "testClientChannel";
    ChannelDataType dataType = ChannelDataType::MESSAGE;
    ChannelPeerInfo peerInfo = { "peerName", "networkId" };

    EXPECT_CALL(mockSoftbus, Socket(testing::_))
        .WillOnce(testing::Return(NUM_MINUS_1));

    // Call CreateClientChannel and check the result
    int32_t result = ChannelManager::GetInstance().CreateClientChannel(channelName, dataType, peerInfo);
    EXPECT_EQ(result, CREATE_SOCKET_FAILED);  // Should return valid channelId
}

/**
 * @tc.name: CreateClientChannel_LoneName_Fail
 * @tc.desc: Test for CreateClientChannel when RegisterSocket fails
 * @tc.type: FUNC
 */
HWTEST_F(ChannelManagerTest, CreateClientChannel_LoneName_Fail, TestSize.Level1)
{
    // Setup the test data
    std::string channelName = "ssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssss";
    ChannelDataType dataType = ChannelDataType::MESSAGE;
    ChannelPeerInfo peerInfo = { "peerName", "networkId" };

    // Call CreateClientChannel and check the result
    int32_t result = ChannelManager::GetInstance().CreateClientChannel(channelName, dataType, peerInfo);
    EXPECT_EQ(result, CREATE_SOCKET_FAILED);  // Should return valid channelId
}

/**
 * @tc.name: CreateClientChannel_ExceedNum_Fail
 * @tc.desc: Test for CreateClientChannel when RegisterSocket fails
 * @tc.type: FUNC
 */
HWTEST_F(ChannelManagerTest, CreateClientChannel_ExceedNum_Fail, TestSize.Level1)
{
    // Setup the test data
    std::string channelName = "testClientChannel";
    ChannelDataType dataType = ChannelDataType::MESSAGE;
    ChannelPeerInfo peerInfo = { "peerName", "networkId" };

    int32_t channelId = 0;
    for (int32_t i = 0; i < CHANNGE_GAP + 1; i++)
    {
        channelId = ChannelManager::GetInstance().CreateClientChannel(channelName, dataType, peerInfo);
    }
    EXPECT_EQ(channelId, CREATE_CLIENT_CHANNEL_FAILED);
}

/**
 * @tc.name: DeleteChannel_Success
 * @tc.desc: Test for DeleteChannel when valid channelId is provided and socket resources are cleared successfully
 * @tc.type: FUNC
 */
HWTEST_F(ChannelManagerTest, DeleteChannel_Success, TestSize.Level1)
{
    // Setup the test data
    std::string channelName = "testDeleteChannel";
    ChannelDataType dataType = ChannelDataType::MESSAGE;
    ChannelPeerInfo peerInfo = { "peerName", "networkId" };

    EXPECT_CALL(mockSoftbus, Socket(testing::_))
        .WillOnce(testing::Return(NUM_1234));

    int32_t channelId = ChannelManager::GetInstance().CreateClientChannel(channelName, dataType, peerInfo);
    ASSERT_EQ(channelId, MESSAGE_START_ID);  // Ensure the channel is created successfully

    int32_t deleteResult = ChannelManager::GetInstance().DeleteChannel(channelId);
    EXPECT_EQ(deleteResult, channelId);
}

/**
 * @tc.name: DeleteChannel_InvalidChannelId
 * @tc.desc: Test for DeleteChannel when invalid channelId is provided
 * @tc.type: FUNC
 */
HWTEST_F(ChannelManagerTest, DeleteChannel_InvalidChannelId, TestSize.Level1)
{
    int32_t invalidChannelId = -1;
    int32_t result = ChannelManager::GetInstance().DeleteChannel(invalidChannelId);
    EXPECT_EQ(result, INVALID_CHANNEL_ID);
}

/**
 * @tc.name: RegisterChannelListener_NullListener
 * @tc.desc: Test for RegisterChannelListener when listener is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(ChannelManagerTest, RegisterChannelListener_NullListener, TestSize.Level1)
{
    int32_t channelId = MESSAGE_START_ID;
    std::shared_ptr<IChannelListener> nullListener = nullptr;
    int32_t result = ChannelManager::GetInstance().RegisterChannelListener(channelId, nullListener);
    EXPECT_EQ(result, INVALID_LISTENER);
}

/**
 * @tc.name: RegisterChannelListener_ChannelIdNotExist
 * @tc.desc: Test for RegisterChannelListener when channelId is not present in listenersMap_
 * @tc.type: FUNC
 */
HWTEST_F(ChannelManagerTest, RegisterChannelListener_ChannelIdNotExist, TestSize.Level1)
{
    int32_t channelId = MESSAGE_START_ID;
    std::shared_ptr<IChannelListener> listener = std::make_shared<MockChannelListener>();
    int32_t result = ChannelManager::GetInstance().RegisterChannelListener(channelId, listener);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: RegisterChannelListener_ListenerExist
 * @tc.desc: Test for RegisterChannelListener when Listener already has listeners
 * @tc.type: FUNC
 */
HWTEST_F(ChannelManagerTest, RegisterChannelListener_ListenerExist, TestSize.Level1)
{
    int32_t channelId = MESSAGE_START_ID;
    std::shared_ptr<IChannelListener> listener = std::make_shared<MockChannelListener>();
    ChannelManager::GetInstance().RegisterChannelListener(channelId, listener);
    int32_t result = ChannelManager::GetInstance().RegisterChannelListener(channelId, listener);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: ConnectChannel_Success
 * @tc.desc: Test for ConnectChannel when valid channelId and client sockets are present
 * @tc.type: FUNC
 */
HWTEST_F(ChannelManagerTest, ConnectChannel_Success, TestSize.Level1)
{
    // Init
    EXPECT_CALL(mockSoftbus, Socket(testing::_))
        .WillRepeatedly(testing::Return(NUM_1234));
    EXPECT_CALL(mockSoftbus, Listen(testing::_, testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(ERR_OK));
    int32_t result = ChannelManager::GetInstance().Init(ownerName);
    EXPECT_EQ(result, ERR_OK);

    // CreateClient
    // Setup the test data
    std::string channelName = "testClientChannel";
    ChannelDataType dataType = ChannelDataType::MESSAGE;
    ChannelPeerInfo peerInfo = { "peerName", "networkId" };

    int32_t channelId = ChannelManager::GetInstance().CreateClientChannel(channelName, dataType, peerInfo);
    EXPECT_EQ(channelId, MESSAGE_START_ID);  // Should return valid channelId
 
    // Step 3: Mock Bind to succeed
    EXPECT_CALL(mockSoftbus, Bind(testing::_, testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(ERR_OK)); // Mock Bind to succeed

    // Call ConnectChannel and check the result
    result = ChannelManager::GetInstance().ConnectChannel(channelId);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: ConnectChannel_BindFailed
 * @tc.desc: Test for ConnectChannel when Bind fails.
 * @tc.type: FUNC
 */
HWTEST_F(ChannelManagerTest, ConnectChannel_BindFailed, TestSize.Level1)
{
   // Init
    EXPECT_CALL(mockSoftbus, Socket(testing::_))
        .WillRepeatedly(testing::Return(NUM_1234));
    EXPECT_CALL(mockSoftbus, Listen(testing::_, testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(ERR_OK));
    int32_t result = ChannelManager::GetInstance().Init(ownerName);
    EXPECT_EQ(result, ERR_OK);

    // CreateClient
    // Setup the test data
    std::string channelName = "testClientChannel";
    ChannelDataType dataType = ChannelDataType::MESSAGE;
    ChannelPeerInfo peerInfo = { "peerName", "networkId" };

    int32_t channelId = ChannelManager::GetInstance().CreateClientChannel(channelName, dataType, peerInfo);
    EXPECT_EQ(channelId, MESSAGE_START_ID);  // Should return valid channelId
 
    // Step 3: Mock Bind to succeed
    EXPECT_CALL(mockSoftbus, Bind(testing::_, testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(NUM_MINUS_1)); // Mock Bind to succeed

    // Call ConnectChannel and check the result
    result = ChannelManager::GetInstance().ConnectChannel(channelId);
    EXPECT_EQ(result, CONNECT_CHANNEL_FAILED);
}

/**
 * @tc.name: ConnectChannel_InvalidChannelId
 * @tc.desc: Test for ConnectChannel when channelId is invalid (not found in channelInfoMap_).
 * @tc.type: FUNC
 */
HWTEST_F(ChannelManagerTest, ConnectChannel_InvalidChannelId, TestSize.Level1)
{
    // Simulate channelId not being in the channelInfoMap_
    int32_t invalidChannelId = INVALID_CHANNEL; // Invalid channel ID
    int32_t connectResult = ChannelManager::GetInstance().ConnectChannel(invalidChannelId);
 
    // Verify that ConnectChannel returns INVALID_CHANNEL_ID for an invalid channelId
    EXPECT_EQ(connectResult, INVALID_CHANNEL_ID);
}

/**
 * @tc.name: ConnectChannel_RepeatConnection
 * @tc.desc: Test for ConnectChannel when the channelId is already connected.
 * @tc.type: FUNC
 */
HWTEST_F(ChannelManagerTest, ConnectChannel_RepeatConnection, TestSize.Level1)
{
    // Step 1: Initialize the ChannelManager
    EXPECT_CALL(mockSoftbus, Socket(testing::_))
        .WillRepeatedly(testing::Return(NUM_1234));
    EXPECT_CALL(mockSoftbus, Listen(testing::_, testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(ERR_OK)); // Mock Listen to return success
 
    int32_t initResult = ChannelManager::GetInstance().Init(ownerName);
    EXPECT_EQ(initResult, ERR_OK); // Ensure Init was successful

    // Step 2: Create Client Channel
    std::string channelName = "testClientChannel";
    ChannelDataType dataType = ChannelDataType::MESSAGE;
    ChannelPeerInfo peerInfo = { "peerName", "networkId" };

    int32_t channelId = ChannelManager::GetInstance().CreateClientChannel(channelName, dataType, peerInfo);
    EXPECT_EQ(channelId, MESSAGE_START_ID); // Verify the channel ID is correctly returned

    // Step 3: Mock Bind to succeed
    EXPECT_CALL(mockSoftbus, Bind(testing::_, testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(ERR_OK)); // Mock Bind to succeed

    // Call ConnectChannel and check the result
    int32_t result = ChannelManager::GetInstance().ConnectChannel(channelId);
    EXPECT_EQ(result, ERR_OK);

    // Step 4: Test ConnectChannel with already connected channelId
    // When channelId is already connected, ConnectChannel should return ERR_OK
    int32_t connectResult = ChannelManager::GetInstance().ConnectChannel(channelId);
    EXPECT_EQ(connectResult, ERR_OK); // Already connected, no need to connect again
}

/**
 * @tc.name: OnSocketConnected_Success_WithCallback
 * @tc.desc: Test for OnSocketConnected when the socket is successfully connected and valid channel is found,
 *           and callback methods are invoked correctly.
 * @tc.type: FUNC
 */
HWTEST_F(ChannelManagerTest, OnSocketConnected_Success_WithCallback, TestSize.Level1)
{
    // Step 1: Initialize the ChannelManager
    EXPECT_CALL(mockSoftbus, Socket(testing::_))
        .WillRepeatedly(testing::Return(NUM_1234));
    EXPECT_CALL(mockSoftbus, Listen(testing::_, testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(ERR_OK)); // Mock Listen to return success
 
    int32_t initResult = ChannelManager::GetInstance().Init(ownerName);
    EXPECT_EQ(initResult, ERR_OK); // Ensure Init was successful

    std::string channelName = "TestChannel";
    ChannelDataType dataType = ChannelDataType::MESSAGE;
    ChannelPeerInfo peerInfo = { "peerName", "networkId" };
    int32_t channelId = ChannelManager::GetInstance().CreateServerChannel(channelName, dataType, peerInfo);
    EXPECT_EQ(channelId, MESSAGE_START_ID); // Assuming MESSAGE_START_ID is defined

    // Step 2: Prepare PeerSocketInfo with correctly formatted name
    std::string prefix = "ssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssss";
    std::string name = prefix + "_M_" + channelName;
    PeerSocketInfo info = {
        .name = const_cast<char*>(name.c_str()), // valid name
        .networkId = nullptr,  // network ID
        .pkgName = nullptr,  // package name
        .dataType = DATA_TYPE_MESSAGE  // channel data type
    };

    int32_t socketId = NUM_1234; // valid socketId

    // Mock the listener and expect the OnConnect callback to be triggered
    auto mockListener = std::make_shared<MockChannelListener>();
    EXPECT_CALL(*mockListener, OnConnect(channelId)).Times(1);

    // Register listener for the channelId
    int32_t result = ChannelManager::GetInstance().RegisterChannelListener(channelId, mockListener);
    EXPECT_EQ(result, ERR_OK);

    // Call OnSocketConnected, which should trigger the OnConnect callback
    ChannelManager::GetInstance().OnSocketConnected(socketId, info);
}

/**
 * @tc.name: OnSocketConnected_InvalidChannelNameFormat_WithCallback
 * @tc.desc: Test for OnSocketConnected when the channel name Format is invalid and cannot be parsed,
 *           and the OnError callback is triggered.
 * @tc.type: FUNC
 */
HWTEST_F(ChannelManagerTest, OnSocketConnected_InvalidChannelNameFormat_WithCallback, TestSize.Level1)
{
    // Step 1: Create Server Channel
    std::string channelName = "TestChannel";
    ChannelDataType dataType = ChannelDataType::MESSAGE;
    ChannelPeerInfo peerInfo = { "peerName", "networkId" };
    int32_t channelId = ChannelManager::GetInstance().CreateServerChannel(channelName, dataType, peerInfo);
    EXPECT_EQ(channelId, MESSAGE_START_ID); // Assuming MESSAGE_START_ID is defined

    // Step 2: Prepare PeerSocketInfo with invalid name
    std::string name = "ohos.distributedschedule.dms.InvalidChannelName";
    PeerSocketInfo info = {
        .name = const_cast<char*>(name.c_str()), // invalid name
        .networkId = nullptr,  // network ID
        .pkgName = nullptr,  // package name
        .dataType = DATA_TYPE_MESSAGE  // channel data type
    };

    int32_t socketId = NUM_1234; // valid socketId

    // Mock the listener and expect
    auto mockListener = std::make_shared<MockChannelListener>();
    EXPECT_CALL(*mockListener, OnConnect(channelId)).Times(0);

    // Register listener for the channelId
    int32_t result = ChannelManager::GetInstance().RegisterChannelListener(channelId, mockListener);
    EXPECT_EQ(result, ERR_OK);

    // Call OnSocketConnected, which should trigger the OnError callback due to invalid channel name
    ChannelManager::GetInstance().OnSocketConnected(socketId, info);
}

/**
 * @tc.name: OnSocketConnected_InvalidChannelType_WithCallback
 * @tc.desc: Test for OnSocketConnected when the channelId Type invalid, and the OnError callback is triggered.
 * @tc.type: FUNC
 */
HWTEST_F(ChannelManagerTest, OnSocketConnected_InvalidChannelType_WithCallback, TestSize.Level1)
{
    // Step 1: Create Server Channel
    std::string channelName = "TestChannel";
    ChannelDataType dataType = ChannelDataType::MESSAGE;
    ChannelPeerInfo peerInfo = { "peerName", "networkId" };
    int32_t channelId = ChannelManager::GetInstance().CreateServerChannel(channelName, dataType, peerInfo);
    EXPECT_EQ(channelId, MESSAGE_START_ID); // Assuming MESSAGE_START_ID is defined

    // Step 2: Prepare PeerSocketInfo with valid name but invalid channelId
    std::string prefix = "ssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssss";
    std::string name = prefix + "_IVA_" + channelName;
    PeerSocketInfo info = {
        .name = const_cast<char*>(name.c_str()), // invalid type
        .networkId = nullptr,  // network ID
        .pkgName = nullptr,  // package name
        .dataType = DATA_TYPE_MESSAGE  // channel data type
    };

    int32_t socketId = NUM_1234; // valid socketId

    // Mock the listener and expect the OnError callback to be triggered
    auto mockListener = std::make_shared<MockChannelListener>();
    EXPECT_CALL(*mockListener, OnConnect(channelId)).Times(0);

    // Register listener for the channelId
    int32_t result = ChannelManager::GetInstance().RegisterChannelListener(channelId, mockListener);
    EXPECT_EQ(result, ERR_OK);

    // Call OnSocketConnected, which should trigger the OnError callback due to invalid channelId
    ChannelManager::GetInstance().OnSocketConnected(socketId, info);
}

/**
 * @tc.name: OnSocketConnected_InvalidChannelName_WithCallback
 * @tc.desc: Test for OnSocketConnected when registering the socket fails,
 *           and verify if the OnError callback is triggered.
 * @tc.type: FUNC
 */
HWTEST_F(ChannelManagerTest, OnSocketConnected_InvalidChannelName_WithCallback, TestSize.Level1)
{
    // Step 1: Create Server Channel
    std::string channelName = "TestChannel";
    ChannelDataType dataType = ChannelDataType::MESSAGE;
    ChannelPeerInfo peerInfo = { "peerName", "networkId" };
    int32_t channelId = ChannelManager::GetInstance().CreateServerChannel(channelName, dataType, peerInfo);
    EXPECT_EQ(channelId, MESSAGE_START_ID); // Assuming MESSAGE_START_ID is defined

    // Step 2: Prepare PeerSocketInfo with correct name
    std::string prefix = "ssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssss";
    std::string name = prefix + "_M_" + channelName + "invalid";
    PeerSocketInfo info = {
        .name = const_cast<char*>(name.c_str()), // invalid name
        .networkId = nullptr,  // network ID
        .pkgName = nullptr,  // package name
        .dataType = DATA_TYPE_MESSAGE  // channel data type
    };

    int32_t socketId = NUM_1234; // valid socketId

    // Mock the listener and expect the OnError callback to be triggered
    auto mockListener = std::make_shared<MockChannelListener>();
    EXPECT_CALL(*mockListener, OnConnect(channelId)).Times(0);

    // Register listener for the channelId
    int32_t result = ChannelManager::GetInstance().RegisterChannelListener(channelId, mockListener);
    EXPECT_EQ(result, ERR_OK);

    ChannelManager::GetInstance().OnSocketConnected(socketId, info);
}

/**
 * @tc.name: OnSocketClosed_CallbackInvokedAndChannelDeleted
 * @tc.desc: Test for OnSocketClosed when the socket is closed and callback is invoked, and channel is deleted.
 * @tc.type: FUNC
 */
HWTEST_F(ChannelManagerTest, OnSocketClosed_CallbackInvokedAndChannelDeleted, TestSize.Level1)
{
    // Step 1: Initialize the ChannelManager
    EXPECT_CALL(mockSoftbus, Socket(testing::_))
        .WillRepeatedly(testing::Return(NUM_1234));
    EXPECT_CALL(mockSoftbus, Listen(testing::_, testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(ERR_OK)); // Mock Listen to return success

    int32_t initResult = ChannelManager::GetInstance().Init(ownerName);
    EXPECT_EQ(initResult, ERR_OK); // Ensure Init was successful

    // CreateClient
    // Setup the test data
    std::string channelName = "testClientChannel";
    ChannelDataType dataType = ChannelDataType::MESSAGE;
    ChannelPeerInfo peerInfo = { "peerName", "networkId" };
    int32_t channelId = ChannelManager::GetInstance().CreateClientChannel(channelName, dataType, peerInfo);
    EXPECT_EQ(channelId, MESSAGE_START_ID);  // Should return valid channelId
  
    auto mockListener = std::make_shared<MockChannelListener>();
    int32_t result = ChannelManager::GetInstance().RegisterChannelListener(channelId, mockListener);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_CALL(*mockListener, OnDisConnect(channelId)).Times(1);

    // Step 3: Mock Bind to succeed
    EXPECT_CALL(mockSoftbus, Bind(testing::_, testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(ERR_OK)); // Mock Bind to succeed

    // Call ConnectChannel and check the result
    result = ChannelManager::GetInstance().ConnectChannel(channelId);
    EXPECT_EQ(result, ERR_OK);

    ChannelManager::GetInstance().OnSocketClosed(NUM_1234, ShutdownReason::SHUTDOWN_REASON_LNN_OFFLINE);
}

/**
 * @tc.name: OnSocketClosed_WhenNoChannelID
 * @tc.desc: Test for OnSocketClosed when the socket is WhenNoChannelID.
 * @tc.type: FUNC
 */
HWTEST_F(ChannelManagerTest, OnSocketClosed_WhenNoChannelID, TestSize.Level1)
{
    EXPECT_CALL(mockSoftbus, Socket(testing::_))
        .WillRepeatedly(testing::Return(NUM_1234));
    // CreateClient
    // Setup the test data
    std::string channelName = "testClientChannel";
    ChannelDataType dataType = ChannelDataType::MESSAGE;
    ChannelPeerInfo peerInfo = { "peerName", "networkId" };
    int32_t channelId = ChannelManager::GetInstance().CreateClientChannel(channelName, dataType, peerInfo);
    EXPECT_EQ(channelId, MESSAGE_START_ID);  // Should return valid channelId
  
    auto mockListener = std::make_shared<MockChannelListener>();
    int32_t result = ChannelManager::GetInstance().RegisterChannelListener(channelId, mockListener);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_CALL(*mockListener, OnDisConnect(channelId)).Times(0);

    ChannelManager::GetInstance().OnSocketClosed(INVALID_CHANNEL_ID, ShutdownReason::SHUTDOWN_REASON_LNN_OFFLINE);
}

/**
 * @tc.name: OnSocketClosed_InvalidSocketIdWithChannelId
 * @tc.desc: Test for OnSocketClosed when the socket is InvalidSocketIdWithChannelId.
 * @tc.type: FUNC
 */
HWTEST_F(ChannelManagerTest, OnSocketClosed_InvalidSocketIdWithChannelId, TestSize.Level1)
{
    // Step 1: Initialize the ChannelManager
    EXPECT_CALL(mockSoftbus, Socket(testing::_))
        .WillRepeatedly(testing::Return(NUM_1234));
    EXPECT_CALL(mockSoftbus, Listen(testing::_, testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(ERR_OK)); // Mock Listen to return success

    int32_t initResult = ChannelManager::GetInstance().Init(ownerName);
    EXPECT_EQ(initResult, ERR_OK); // Ensure Init was successful

    // CreateClient
    // Setup the test data
    std::string channelName = "testClientChannel";
    ChannelDataType dataType = ChannelDataType::MESSAGE;
    ChannelPeerInfo peerInfo = { "peerName", "networkId" };
    int32_t channelId = ChannelManager::GetInstance().CreateClientChannel(channelName, dataType, peerInfo);
    EXPECT_EQ(channelId, MESSAGE_START_ID);  // Should return valid channelId
  
    auto mockListener = std::make_shared<MockChannelListener>();
    int32_t result = ChannelManager::GetInstance().RegisterChannelListener(channelId, mockListener);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_CALL(*mockListener, OnDisConnect(channelId)).Times(0);

    ChannelManager::GetInstance().OnSocketClosed(INVALID_CHANNEL_ID, ShutdownReason::SHUTDOWN_REASON_LNN_OFFLINE);
}

/**
 * @tc.name: SendBytes_Success
 * @tc.desc: Test for SendBytes when both channel and connection are successfully established.
 * @tc.type: FUNC
 */
HWTEST_F(ChannelManagerTest, SendBytes_Success, TestSize.Level1)
{
    // Step 1: Initialize the ChannelManager
    EXPECT_CALL(mockSoftbus, Socket(testing::_))
        .WillRepeatedly(testing::Return(NUM_1234)); // Mock Socket to return a valid socket ID
    EXPECT_CALL(mockSoftbus, Listen(testing::_, testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(ERR_OK)); // Mock Listen to return success

    int32_t initResult = ChannelManager::GetInstance().Init(ownerName);
    EXPECT_EQ(initResult, ERR_OK); // Ensure Init was successful

    // Step 2: Create Client Channel
    std::string channelName = "TestChannel";
    ChannelDataType dataType = ChannelDataType::MESSAGE;  // Use TransDataType for the data type
    ChannelPeerInfo peerInfo = { "peerName", "networkId" };

    int32_t channelId = ChannelManager::GetInstance().CreateClientChannel(channelName, dataType, peerInfo);
    EXPECT_EQ(channelId, MESSAGE_START_ID); // Verify the channel ID is correctly returned

    // Step 3: Mock Bind to succeed
    EXPECT_CALL(mockSoftbus, Bind(testing::_, testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(ERR_OK)); // Mock Bind to succeed

    // Step 4: Call ConnectChannel to establish the connection
    int32_t result = ChannelManager::GetInstance().ConnectChannel(channelId);
    EXPECT_EQ(result, ERR_OK); // Verify the connection was established

    // Step 5: Prepare data to send
    std::shared_ptr<AVTransDataBuffer> dataBuffer = std::make_shared<AVTransDataBuffer>(NUM_1234);
    EXPECT_CALL(mockSoftbus, GetSessionOption(NUM_1234, testing::_, testing::_, sizeof(uint32_t)))
        .WillOnce(testing::Invoke([&](int sessionId, SessionOption option,
            void* optionValue, uint32_t valueSize) {
            *reinterpret_cast<uint32_t*>(optionValue) = 4 * 1024 * 1024;
            return ERR_OK;
        }));
  
    EXPECT_CALL(mockSoftbus, SendBytes(NUM_1234, testing::_, dataBuffer->Size() + SessionDataHeader::HEADER_LEN))
        .WillOnce(testing::Return(ERR_OK));

    // Step 6: Send the data
    result = ChannelManager::GetInstance().SendBytes(channelId, dataBuffer);
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_FOR_INIT));
    // Validate the result of SendBytes - it should return ERR_OK as everything is valid
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: SendBytes_InvalidChannelId
 * @tc.desc: Test for SendBytes when channelId is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(ChannelManagerTest, SendBytes_InvalidChannelId, TestSize.Level1)
{
    // Prepare an invalid channelId
    int32_t invalidChannelId = INVALID_CHANNEL;  // Invalid channelId
    std::shared_ptr<AVTransDataBuffer> dataBuffer = std::make_shared<AVTransDataBuffer>(NUM_1234);

    // Step 1: Call SendBytes with invalid channelId
    int32_t result = ChannelManager::GetInstance().SendBytes(invalidChannelId, dataBuffer);

    // Validate result - should return INVALID_CHANNEL_ID
    EXPECT_EQ(result, INVALID_CHANNEL_ID);
}

/**
 * @tc.name: SendBytes_NullData
 * @tc.desc: Test for SendBytes when data is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(ChannelManagerTest, SendBytes_NullData, TestSize.Level1)
{
    std::shared_ptr<AVTransDataBuffer> nullData = nullptr;
    int32_t result = ChannelManager::GetInstance().SendBytes(MESSAGE_START_ID, nullData);

    // Validate the result - should return INVALID_CHANNEL_ID as data is null
    EXPECT_EQ(result, INVALID_CHANNEL_ID);
}

/**
 * @tc.name: SendBytes_NotConnect
 * @tc.desc: Test for SendBytes when NotConnect.
 * @tc.type: FUNC
 */
HWTEST_F(ChannelManagerTest, SendBytes_NotConnect, TestSize.Level1)
{
    // Step 1: Initialize the ChannelManager
    EXPECT_CALL(mockSoftbus, Socket(testing::_))
        .WillRepeatedly(testing::Return(NUM_1234)); // Mock Socket to return a valid socket ID
    EXPECT_CALL(mockSoftbus, Listen(testing::_, testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(ERR_OK)); // Mock Listen to return success

    int32_t initResult = ChannelManager::GetInstance().Init(ownerName);
    EXPECT_EQ(initResult, ERR_OK); // Ensure Init was successful

    // Step 2: Create Client Channel
    std::string channelName = "TestChannel";
    ChannelDataType dataType = ChannelDataType::MESSAGE;
    ChannelPeerInfo peerInfo = { "peerName", "networkId" };

    int32_t channelId = ChannelManager::GetInstance().CreateClientChannel(channelName, dataType, peerInfo);
    EXPECT_EQ(channelId, MESSAGE_START_ID); // Verify the channel ID is correctly returned

    // Step 3: Mock Bind to succeed
    EXPECT_CALL(mockSoftbus, Bind(testing::_, testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(-1)); // Mock Bind to succeed

    // Step 4: Call ConnectChannel to establish the connection
    int32_t result = ChannelManager::GetInstance().ConnectChannel(channelId);
    EXPECT_EQ(result, CONNECT_CHANNEL_FAILED); // Verify the connection was established

    std::shared_ptr<AVTransDataBuffer> dataBuffer = std::make_shared<AVTransDataBuffer>(NUM_1234);

    result = ChannelManager::GetInstance().SendBytes(channelId, dataBuffer);
}

/**
 * @tc.name: SendStream_Success
 * @tc.desc: Test for SendStream when both channel and connection are successfully established.
 * @tc.type: FUNC
 */
HWTEST_F(ChannelManagerTest, SendStream_Success, TestSize.Level1)
{
    // Step 1: Initialize the ChannelManager
    EXPECT_CALL(mockSoftbus, Socket(testing::_))
        .WillRepeatedly(testing::Return(NUM_1234)); // Mock Socket to return a valid socket ID
    EXPECT_CALL(mockSoftbus, Listen(testing::_, testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(ERR_OK)); // Mock Listen to return success

    int32_t initResult = ChannelManager::GetInstance().Init(ownerName);
    EXPECT_EQ(initResult, ERR_OK); // Ensure Init was successful

    // Step 2: Create Client Channel
    std::string channelName = "TestStreamChannel";
    ChannelDataType dataType = ChannelDataType::MESSAGE;  // Using raw stream type for the data
    ChannelPeerInfo peerInfo = { "peerName", "networkId" };

    int32_t channelId = ChannelManager::GetInstance().CreateClientChannel(channelName, dataType, peerInfo);
    EXPECT_EQ(channelId, MESSAGE_START_ID); // Verify the channel ID is correctly returned

    // Step 3: Mock Bind to succeed
    EXPECT_CALL(mockSoftbus, Bind(testing::_, testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(ERR_OK)); // Mock Bind to succeed

    // Step 4: Call ConnectChannel to establish the connection
    int32_t result = ChannelManager::GetInstance().ConnectChannel(channelId);
    EXPECT_EQ(result, ERR_OK); // Verify the connection was established

    // Step 5: Prepare data for stream
    std::shared_ptr<AVTransDataBuffer> dataBuffer = std::make_shared<AVTransDataBuffer>(NUM_1024);

    AVTransStreamDataExt extData;
    extData.flag_ = AvCodecBufferFlag::AVCODEC_BUFFER_FLAG_CODEC_DATA;
    extData.index_ = NUM_1;
    extData.pts_ = NUM_200;
    extData.startEncodeT_ = NUM_200;
    extData.finishEncodeT_ = NUM_200;
    extData.sendEncodeT_ = NUM_200;

    std::shared_ptr<AVTransStreamData> streamData = std::make_shared<AVTransStreamData>(dataBuffer, extData);

    // Step 6: Call SendStream
    EXPECT_CALL(mockSoftbus, SendStream(NUM_1234, testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(ERR_OK));
    result = ChannelManager::GetInstance().SendStream(channelId, streamData);
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_FOR_INIT));
    // Validate the result - it should return ERR_OK as everything is valid
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: SendStream_InvalidChannelId
 * @tc.desc: Test for SendStream when channelId is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(ChannelManagerTest, SendStream_InvalidChannelId, TestSize.Level1)
{
    // Prepare an invalid channelId
    int32_t invalidChannelId = -1;  // Invalid channelId
    std::shared_ptr<AVTransDataBuffer> dataBuffer = std::make_shared<AVTransDataBuffer>(NUM_1024);

    AVTransStreamDataExt extData;
    extData.flag_ = AvCodecBufferFlag::AVCODEC_BUFFER_FLAG_CODEC_DATA;
    extData.index_ = NUM_1;
    extData.pts_ = NUM_200;
    extData.startEncodeT_ = NUM_200;
    extData.finishEncodeT_ = NUM_200;
    extData.sendEncodeT_ = NUM_200;

    std::shared_ptr<AVTransStreamData> streamData = std::make_shared<AVTransStreamData>(dataBuffer, extData);

    // Step 1: Call SendStream with invalid channelId
    int32_t result = ChannelManager::GetInstance().SendStream(invalidChannelId, streamData);

    // Validate result - should return INVALID_CHANNEL_ID
    EXPECT_EQ(result, INVALID_CHANNEL_ID);
}

/**
 * @tc.name: SendStream_NullData
 * @tc.desc: Test for SendStream when data is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(ChannelManagerTest, SendStream_NullData, TestSize.Level1)
{
    // Prepare valid channelId
    int32_t validChannelId = MESSAGE_START_ID;  // Valid channelId
    std::shared_ptr<AVTransDataBuffer> dataBuffer = nullptr;  // Set data to nullptr

    // Step 1: Call SendStream with nullptr data
    int32_t result = ChannelManager::GetInstance().SendStream(validChannelId, nullptr);

    // Validate result - should return INVALID_CHANNEL_ID as data is null
    EXPECT_EQ(result, INVALID_CHANNEL_ID);
}

/**
 * @tc.name: SendStream_NotConnect
 * @tc.desc: Test for SendStream when NotConnect.
 * @tc.type: FUNC
 */
HWTEST_F(ChannelManagerTest, SendStream_NotConnect, TestSize.Level1)
{
    // Step 1: Initialize the ChannelManager
    EXPECT_CALL(mockSoftbus, Socket(testing::_))
        .WillRepeatedly(testing::Return(NUM_1234)); // Mock Socket to return a valid socket ID
    EXPECT_CALL(mockSoftbus, Listen(testing::_, testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(ERR_OK)); // Mock Listen to return success

    int32_t initResult = ChannelManager::GetInstance().Init(ownerName);
    EXPECT_EQ(initResult, ERR_OK); // Ensure Init was successful

    // Step 2: Create Client Channel
    std::string channelName = "TestStreamChannel";
    ChannelDataType dataType = ChannelDataType::MESSAGE;  // Using raw stream type for the data
    ChannelPeerInfo peerInfo = { "peerName", "networkId" };

    int32_t channelId = ChannelManager::GetInstance().CreateClientChannel(channelName, dataType, peerInfo);
    EXPECT_EQ(channelId, MESSAGE_START_ID); // Verify the channel ID is correctly returned

    // Step 3: Mock Bind to succeed
    EXPECT_CALL(mockSoftbus, Bind(testing::_, testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(-1)); // Mock Bind to succeed

    // Step 4: Call ConnectChannel to establish the connection
    int32_t result = ChannelManager::GetInstance().ConnectChannel(channelId);
    EXPECT_EQ(result, CONNECT_CHANNEL_FAILED); // Verify the connection was established


    // Step 6: Prepare data for stream
    std::shared_ptr<AVTransDataBuffer> dataBuffer = std::make_shared<AVTransDataBuffer>(NUM_1024);

    AVTransStreamDataExt extData;
    extData.flag_ = AvCodecBufferFlag::AVCODEC_BUFFER_FLAG_CODEC_DATA;
    extData.index_ = NUM_1;
    extData.pts_ = NUM_200;
    extData.startEncodeT_ = NUM_200;
    extData.finishEncodeT_ = NUM_200;
    extData.sendEncodeT_ = NUM_200;

    std::shared_ptr<AVTransStreamData> streamData = std::make_shared<AVTransStreamData>(dataBuffer, extData);

    // Step 7: Call SendStream
    result = ChannelManager::GetInstance().SendStream(channelId, streamData);
}

/**
 * @tc.name: SendMessage_Success
 * @tc.desc: Test for SendMessage when channelId is valid and PostTask succeeds.
 * @tc.type: FUNC
 */
HWTEST_F(ChannelManagerTest, SendMessage_Success, TestSize.Level1)
{
    // Step 1: Initialize the ChannelManager
    EXPECT_CALL(mockSoftbus, Socket(testing::_))
        .WillRepeatedly(testing::Return(NUM_1234)); // Mock Socket to return a valid socket ID
    EXPECT_CALL(mockSoftbus, Listen(testing::_, testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(ERR_OK)); // Mock Listen to return success

    int32_t initResult = ChannelManager::GetInstance().Init(ownerName);
    EXPECT_EQ(initResult, ERR_OK); // Ensure Init was successful

    // Step 2: Create Client Channel
    std::string channelName = "TestMessageChannel";
    ChannelDataType dataType = ChannelDataType::MESSAGE;  // Using message type for the data
    ChannelPeerInfo peerInfo = { "peerName", "networkId" };

    int32_t channelId = ChannelManager::GetInstance().CreateClientChannel(channelName, dataType, peerInfo);
    EXPECT_EQ(channelId, MESSAGE_START_ID); // Verify the channel ID is correctly returned

    // Step 3: Mock Bind to succeed
    EXPECT_CALL(mockSoftbus, Bind(testing::_, testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(ERR_OK)); // Mock Bind to succeed

    // Step 4: Call ConnectChannel to establish the connection
    int32_t result = ChannelManager::GetInstance().ConnectChannel(channelId);
    EXPECT_EQ(result, ERR_OK); // Verify the connection is established

    // Step 5: Prepare data for message
    std::shared_ptr<AVTransDataBuffer> dataBuffer = std::make_shared<AVTransDataBuffer>(NUM_1024); // Set buffer size
    EXPECT_CALL(mockSoftbus, SendMessage(NUM_1234, testing::_, testing::_))
        .WillOnce(testing::Return(ERR_OK));
      
    // Step 6: Call SendMessage
    result = ChannelManager::GetInstance().SendMessage(channelId, dataBuffer);
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_FOR_INIT));

    EXPECT_EQ(result, ERR_OK); // Verify that message was sent successfully
}

/**
 * @tc.name: SendMessage_InvalidChannelId
 * @tc.desc: Test for SendMessage when channelId is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(ChannelManagerTest, SendMessage_InvalidChannelId, TestSize.Level1)
{
    int32_t invalidChannelId = -1; // Simulating an invalid channelId

    // Step 3: Prepare data for message
    std::shared_ptr<AVTransDataBuffer> dataBuffer = std::make_shared<AVTransDataBuffer>(NUM_1024); // Set buffer size

    // Step 4: Call SendMessage with invalid channelId
    int32_t result = ChannelManager::GetInstance().SendMessage(invalidChannelId, dataBuffer);
    EXPECT_EQ(result, INVALID_CHANNEL_ID); // Verify that invalid channelId returns INVALID_CHANNEL_ID
}

/**
 * @tc.name: SendMessage_NullData
 * @tc.desc: Test for SendMessage when data is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(ChannelManagerTest, SendMessage_NullData, TestSize.Level1)
{
    int32_t result = ChannelManager::GetInstance().SendMessage(MESSAGE_START_ID, nullptr);
    EXPECT_EQ(result, INVALID_CHANNEL_ID); // Verify that passing nullptr data returns INVALID_CHANNEL_ID
}

/**
 * @tc.name: SendMessage_NotConnect
 * @tc.desc: Test for SendMessage when NotConnect
 * @tc.type: FUNC
 */
HWTEST_F(ChannelManagerTest, SendMessage_NotConnect, TestSize.Level1)
{
    // Step 1: Initialize the ChannelManager
    EXPECT_CALL(mockSoftbus, Socket(testing::_))
        .WillRepeatedly(testing::Return(NUM_1234)); // Mock Socket to return a valid socket ID
    EXPECT_CALL(mockSoftbus, Listen(testing::_, testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(ERR_OK)); // Mock Listen to return success

    int32_t initResult = ChannelManager::GetInstance().Init(ownerName);
    EXPECT_EQ(initResult, ERR_OK); // Ensure Init was successful

    // Step 2: Create Client Channel
    std::string channelName = "TestMessageChannel";
    ChannelDataType dataType = ChannelDataType::MESSAGE;  // Using message type for the data
    ChannelPeerInfo peerInfo = { "peerName", "networkId" };

    int32_t channelId = ChannelManager::GetInstance().CreateClientChannel(channelName, dataType, peerInfo);
    EXPECT_EQ(channelId, MESSAGE_START_ID); // Verify the channel ID is correctly returned

    // Step 3: Mock Bind to succeed
    EXPECT_CALL(mockSoftbus, Bind(testing::_, testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(-1)); // Mock Bind to succeed

    // Step 4: Call ConnectChannel to establish the connection
    int32_t result = ChannelManager::GetInstance().ConnectChannel(channelId);
    EXPECT_EQ(result, CONNECT_CHANNEL_FAILED); // Verify the connection is established

    // Step 6: Call SendMessage
    result = ChannelManager::GetInstance().SendMessage(channelId, nullptr);
}

/**
 * @tc.name: OnMessageReceived_Success_WithCallback
 * @tc.desc: Test for OnMessageReceived when the socket is valid and data is received successfully,
 *           and the OnMessage callback is triggered correctly with the received data.
 * @tc.type: FUNC
 */
HWTEST_F(ChannelManagerTest, OnMessageReceived_Success_WithCallback, TestSize.Level1)
{
    // Step 1: Initialize the ChannelManager
    EXPECT_CALL(mockSoftbus, Socket(testing::_))
        .WillRepeatedly(testing::Return(NUM_1234));  // 模拟返回一个有效的 socketId
    EXPECT_CALL(mockSoftbus, Listen(testing::_, testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(ERR_OK));  // 模拟监听成功
 
    int32_t initResult = ChannelManager::GetInstance().Init(ownerName);
    EXPECT_EQ(initResult, ERR_OK); // 确保初始化成功

    // Step 2: Create a server channel
    std::string channelName = "TestChannel";  // 定义测试的通道名称
    ChannelDataType dataType = ChannelDataType::MESSAGE;  // 设置通道数据类型为 MESSAGE
    ChannelPeerInfo peerInfo = { "peerName", "networkId" };  // 创建测试用的 peer 信息
    int32_t channelId = ChannelManager::GetInstance().CreateClientChannel(channelName, dataType, peerInfo);
    EXPECT_EQ(channelId, MESSAGE_START_ID);  // 假设 MESSAGE_START_ID 已定义，验证通道创建成功

    int32_t socketId = NUM_1234;

    // Step 4: Mock the listener and expect the OnMessage callback to be triggered
    auto mockListener = std::make_shared<MockChannelListener>();
    EXPECT_CALL(*mockListener, OnMessage(channelId, testing::_)).Times(1);  // 确保 OnMessage 被调用一次

    // 注册监听器
    int32_t result = ChannelManager::GetInstance().RegisterChannelListener(channelId, mockListener);
    EXPECT_EQ(result, ERR_OK);  // 确保注册监听器成功

    // Step 5: Prepare test data for OnMessageReceived
    const char* testData = "Hello, ChannelManager!";  // 模拟消息数据
    uint32_t dataLen = static_cast<uint32_t>(strlen(testData) + 1);  // 数据长度，包括结束符

    // Step 6: Call OnMessageReceived and expect OnMessage callback
    ChannelManager::GetInstance().OnMessageReceived(socketId, testData, dataLen);
}

/**
 * @tc.name: OnMessageReceived_Failure_InvalidData
 * @tc.desc: Test for OnMessageReceived when invalid data (nullptr or zero length) is provided,
 *           and the OnError callback is triggered correctly with the appropriate error code.
 * @tc.type: FUNC
 */
HWTEST_F(ChannelManagerTest, OnMessageReceived_Failure_InvalidData, TestSize.Level1)
{
    // Step 1: Initialize the ChannelManager
    EXPECT_CALL(mockSoftbus, Socket(testing::_))
        .WillRepeatedly(testing::Return(NUM_1234));  // 模拟返回一个有效的 socketId
    EXPECT_CALL(mockSoftbus, Listen(testing::_, testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(ERR_OK));  // 模拟监听成功
 
    // 初始化 ChannelManager，验证初始化结果为 ERR_OK
    int32_t initResult = ChannelManager::GetInstance().Init(ownerName);
    EXPECT_EQ(initResult, ERR_OK); // 确保初始化成功

    // Step 2: Create a server channel
    std::string channelName = "TestChannel";
    ChannelDataType dataType = ChannelDataType::MESSAGE;
    ChannelPeerInfo peerInfo = { "peerName", "networkId" };
    int32_t channelId = ChannelManager::GetInstance().CreateClientChannel(channelName, dataType, peerInfo);
    EXPECT_EQ(channelId, MESSAGE_START_ID);

    int32_t socketId = NUM_1234;  // 使用模拟的有效 socketId

    // Step 4: Mock the listener and expect the OnError callback to be triggered on failure
    auto mockListener = std::make_shared<MockChannelListener>();
    EXPECT_CALL(*mockListener, OnError(channelId, RECV_DATA_EMPTY)).Times(1);  // 确保 OnError 被调用一次
    EXPECT_CALL(*mockListener, OnMessage(channelId, testing::_)).Times(0);

    // 注册监听器
    int32_t result = ChannelManager::GetInstance().RegisterChannelListener(channelId, mockListener);
    EXPECT_EQ(result, ERR_OK);

    // Step 5: Simulate invalid data (nullptr or zero length)
    const void* invalidData = nullptr;
    uint32_t invalidDataLen = 0;

    // Step 6: Call OnMessageReceived with invalid data, expecting an error callback
    ChannelManager::GetInstance().OnMessageReceived(socketId, invalidData, invalidDataLen);
}

/**
 * @tc.name: OnMessageReceived_InvalidChannelId
 * @tc.desc: Test for OnMessageReceived when InvalidChannelId.
 * @tc.type: FUNC
 */
HWTEST_F(ChannelManagerTest, OnMessageReceived_InvalidChannelId, TestSize.Level1)
{
    // Step 1: Initialize the ChannelManager
    EXPECT_CALL(mockSoftbus, Socket(testing::_))
        .WillRepeatedly(testing::Return(NUM_1234));  // 模拟返回一个有效的 socketId
    EXPECT_CALL(mockSoftbus, Listen(testing::_, testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(ERR_OK));  // 模拟监听成功
 
    // 初始化 ChannelManager，验证初始化结果为 ERR_OK
    int32_t initResult = ChannelManager::GetInstance().Init(ownerName);
    EXPECT_EQ(initResult, ERR_OK); // 确保初始化成功

    const char* testData = "Hello, ChannelManager!";  // 模拟消息数据
    uint32_t dataLen = static_cast<uint32_t>(strlen(testData) + 1);  // 数据长度，包括结束符

    ChannelManager::GetInstance().OnMessageReceived(NUM_1234, testData, dataLen);
}

/**
 * @tc.name: OnStreamReceived_Success
 * @tc.desc: Test for OnStreamReceived when valid data is received and processed successfully,
 *           and the DoStreamReceiveCallback is triggered correctly with the received data.
 * @tc.type: FUNC
 */
HWTEST_F(ChannelManagerTest, OnStreamReceived_Success, TestSize.Level1)
{
    // Step 1: Initialize the ChannelManager
    EXPECT_CALL(mockSoftbus, Socket(testing::_))
        .WillRepeatedly(testing::Return(NUM_1234));  // 模拟返回一个有效的 socketId
    EXPECT_CALL(mockSoftbus, Listen(testing::_, testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(ERR_OK));  // 模拟监听成功
 
    // 初始化 ChannelManager，验证初始化结果为 ERR_OK
    int32_t initResult = ChannelManager::GetInstance().Init(ownerName);
    EXPECT_EQ(initResult, ERR_OK); // 确保初始化成功

    // Step 2: Create a server channel
    std::string channelName = "TestChannel";
    ChannelDataType dataType = ChannelDataType::VIDEO_STREAM;
    ChannelPeerInfo peerInfo = { "peerName", "networkId" };
    int32_t channelId = ChannelManager::GetInstance().CreateClientChannel(channelName, dataType, peerInfo);
    EXPECT_EQ(channelId, STREAM_START_ID);

    int32_t socketId = NUM_1234;
    std::shared_ptr<AVTransDataBuffer> dataBuffer = std::make_shared<AVTransDataBuffer>(NUM_1024);

    AVTransStreamDataExt extData;
    extData.flag_ = AvCodecBufferFlag::AVCODEC_BUFFER_FLAG_CODEC_DATA;
    extData.index_ = NUM_1;
    extData.pts_ = NUM_200;
    extData.startEncodeT_ = NUM_200;
    extData.finishEncodeT_ = NUM_200;
    extData.sendEncodeT_ = NUM_200;

    std::shared_ptr<AVTransStreamData> streamData = std::make_shared<AVTransStreamData>(dataBuffer, extData);
    StreamData data = {
        .buf = reinterpret_cast<char*>(streamData->StreamData()->Data()),
        .bufLen = streamData->StreamData()->Size()
    };
    cJSON* extInfo = streamData->SerializeStreamDataExt();
    char* jsonString = cJSON_PrintUnformatted(extInfo);
    const StreamData ext = {
        .buf = jsonString,
        .bufLen = strlen(jsonString)
    };
    StreamFrameInfo param = {
        .frameType = NUM_1,
        .timeStamp = NUM_200,
        .seqNum = NUM_1,
        .seqSubNum = NUM_1,
        .level = NUM_1,
        .bitMap = NUM_1,
        .tvCount = NUM_1
    };

    // Step 4: Mock the listener and expect the DoStreamReceiveCallback to be triggered
    auto mockListener = std::make_shared<MockChannelListener>();
    EXPECT_CALL(*mockListener, OnStream(channelId, testing::_)).Times(1);  // 确保 OnStreamReceived 被调用一次

    // 注册监听器
    int32_t result = ChannelManager::GetInstance().RegisterChannelListener(channelId, mockListener);
    EXPECT_EQ(result, ERR_OK);  // 确保注册监听器成功

    // Step 5: Call OnStreamReceived and expect the callback
    ChannelManager::GetInstance().OnStreamReceived(socketId, &data, &ext, &param);
}

/**
 * @tc.name: OnStreamReceived_Failure_RecvDataEmpty
 * @tc.desc: Test for OnStreamReceived when data copy to buffer fails,
 *           and the error callback is triggered with RecvDataEmpty.
 * @tc.type: FUNC
 */
HWTEST_F(ChannelManagerTest, OnStreamReceived_Failure_RecvDataEmpty, TestSize.Level1)
{
    // Step 1: Initialize the ChannelManager
    EXPECT_CALL(mockSoftbus, Socket(testing::_))
        .WillRepeatedly(testing::Return(NUM_1234));  // 模拟返回一个有效的 socketId
    EXPECT_CALL(mockSoftbus, Listen(testing::_, testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(ERR_OK));  // 模拟监听成功
 
    // 初始化 ChannelManager，验证初始化结果为 ERR_OK
    int32_t initResult = ChannelManager::GetInstance().Init(ownerName);
    EXPECT_EQ(initResult, ERR_OK); // 确保初始化成功

    // Step 2: Create a server channel
    std::string channelName = "TestChannel";
    ChannelDataType dataType = ChannelDataType::VIDEO_STREAM;
    ChannelPeerInfo peerInfo = { "peerName", "networkId" };
    int32_t channelId = ChannelManager::GetInstance().CreateClientChannel(channelName, dataType, peerInfo);
    EXPECT_EQ(channelId, STREAM_START_ID);

    int32_t socketId = NUM_1234;
    std::shared_ptr<AVTransDataBuffer> dataBuffer = std::make_shared<AVTransDataBuffer>(NUM_1024);

    AVTransStreamDataExt extData;
    extData.flag_ = AvCodecBufferFlag::AVCODEC_BUFFER_FLAG_CODEC_DATA;
    extData.index_ = NUM_1;
    extData.pts_ = NUM_200;
    extData.startEncodeT_ = NUM_200;
    extData.finishEncodeT_ = NUM_200;
    extData.sendEncodeT_ = NUM_200;

    std::shared_ptr<AVTransStreamData> streamData = std::make_shared<AVTransStreamData>(dataBuffer, extData);
    cJSON* extInfo = streamData->SerializeStreamDataExt();
    char* jsonString = cJSON_PrintUnformatted(extInfo);
    const StreamData ext = {
        .buf = jsonString,
        .bufLen = strlen(jsonString)
    };
    StreamFrameInfo param = {
        .frameType = NUM_1,
        .timeStamp = NUM_200,
        .seqNum = NUM_1,
        .seqSubNum = NUM_1,
        .level = NUM_1,
        .bitMap = NUM_1,
        .tvCount = NUM_1
    };

    auto mockListener = std::make_shared<MockChannelListener>();
    EXPECT_CALL(*mockListener, OnStream(channelId, testing::_)).Times(0);  // 确保 OnStreamReceived 被调用一次

    // 注册监听器
    int32_t result = ChannelManager::GetInstance().RegisterChannelListener(channelId, mockListener);
    EXPECT_EQ(result, ERR_OK);  // 确保注册监听器成功
    EXPECT_CALL(*mockListener, OnError(channelId, RECV_DATA_EMPTY)).Times(1);

    ChannelManager::GetInstance().OnStreamReceived(socketId, nullptr, &ext, &param);
}

/**
 * @tc.name: OnStreamReceived_Failure_ParseStreamExtFailed
 * @tc.desc: Test for OnStreamReceived when parsing the stream extension fails,
 *           and the error callback is triggered with PARSE_AV_TRANS_STREAM_EXT_FAILED.
 * @tc.type: FUNC
 */
HWTEST_F(ChannelManagerTest, OnStreamReceived_Failure_ParseStreamExtFailed, TestSize.Level1)
{
    // Step 1: Initialize the ChannelManager
    EXPECT_CALL(mockSoftbus, Socket(testing::_))
        .WillRepeatedly(testing::Return(NUM_1234));  // 模拟返回一个有效的 socketId
    EXPECT_CALL(mockSoftbus, Listen(testing::_, testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(ERR_OK));  // 模拟监听成功
 
    // 初始化 ChannelManager，验证初始化结果为 ERR_OK
    int32_t initResult = ChannelManager::GetInstance().Init(ownerName);
    EXPECT_EQ(initResult, ERR_OK); // 确保初始化成功

    // Step 2: Create a server channel
    std::string channelName = "TestChannel";
    ChannelDataType dataType = ChannelDataType::VIDEO_STREAM;
    ChannelPeerInfo peerInfo = { "peerName", "networkId" };
    int32_t channelId = ChannelManager::GetInstance().CreateClientChannel(channelName, dataType, peerInfo);
    EXPECT_EQ(channelId, STREAM_START_ID);

    int32_t socketId = NUM_1234;
    std::shared_ptr<AVTransDataBuffer> dataBuffer = std::make_shared<AVTransDataBuffer>(NUM_1024);

    AVTransStreamDataExt extData;
    extData.flag_ = AvCodecBufferFlag::AVCODEC_BUFFER_FLAG_CODEC_DATA;
    extData.index_ = NUM_1;
    extData.pts_ = NUM_200;
    extData.startEncodeT_ = NUM_200;
    extData.finishEncodeT_ = NUM_200;
    extData.sendEncodeT_ = NUM_200;

    std::shared_ptr<AVTransStreamData> streamData = std::make_shared<AVTransStreamData>(dataBuffer, extData);
    StreamData data = {
        .buf = reinterpret_cast<char*>(streamData->StreamData()->Data()),
        .bufLen = streamData->StreamData()->Size()
    };
    const StreamData ext = {
        .buf = nullptr,
        .bufLen = NUM_1
    };
    StreamFrameInfo param = {
        .frameType = NUM_1,
        .timeStamp = NUM_200,
        .seqNum = NUM_1,
        .seqSubNum = NUM_1,
        .level = NUM_1,
        .bitMap = NUM_1,
        .tvCount = NUM_1
    };

    // 模拟反序列化失败
    auto mockListener = std::make_shared<MockChannelListener>();
    EXPECT_CALL(*mockListener, OnStream(channelId, testing::_)).Times(0);  // 确保 OnStreamReceived 被调用一次

    // 注册监听器
    int32_t result = ChannelManager::GetInstance().RegisterChannelListener(channelId, mockListener);
    EXPECT_EQ(result, ERR_OK);  // 确保注册监听器成功
    EXPECT_CALL(*mockListener, OnError(channelId, PARSE_AV_TRANS_STREAM_EXT_FAILED)).Times(1);

    // Step 4: Call OnStreamReceived and expect error callback to be triggered
    ChannelManager::GetInstance().OnStreamReceived(socketId, &data, &ext, &param);
}

/**
 * @tc.name: OnBytesReceived_Success
 * @tc.desc: Test for OnBytesReceived when valid data is received and processed successfully,
 *           and the DoBytesReceiveCallback is triggered correctly with the processed data.
 * @tc.type: FUNC
 */
HWTEST_F(ChannelManagerTest, OnBytesReceived_Success, TestSize.Level1)
{
    // Step 1: Initialize the ChannelManager
    EXPECT_CALL(mockSoftbus, Socket(testing::_))
        .WillRepeatedly(testing::Return(NUM_1234));  // 模拟返回一个有效的 socketId
    EXPECT_CALL(mockSoftbus, Listen(testing::_, testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(ERR_OK));  // 模拟监听成功
  
    // 初始化 ChannelManager，验证初始化结果为 ERR_OK
    int32_t initResult = ChannelManager::GetInstance().Init(ownerName);
    EXPECT_EQ(initResult, ERR_OK); // 确保初始化成功

    // Step 2: Create a server channel
    std::string channelName = "TestChannel";
    ChannelDataType dataType = ChannelDataType::BYTES;
    ChannelPeerInfo peerInfo = { "peerName", "networkId" };
    int32_t channelId = ChannelManager::GetInstance().CreateClientChannel(channelName, dataType, peerInfo);
    EXPECT_EQ(channelId, BYTES_START_ID);

    int32_t socketId = NUM_1234;

    // Step 3: Prepare test data for OnBytesReceived
    auto buffer = std::make_unique<AVTransDataBuffer>(NUM_1024);
    uint32_t dataLen = buffer->Size();
    
    // 构造发送的数据包头（使用 SessionDataHeader 格式）
    SessionDataHeader headerPara(
        NUM_1,
        FRAG_TYPE::FRAG_START_END,
        static_cast<int32_t>(ChannelDataType::BYTES),  // 这里的 dataType 应该与发送的数据类型一致
        0, // seqNum
        dataLen + SessionDataHeader::HEADER_LEN,  // totalLen
        dataLen + SessionDataHeader::HEADER_LEN,  // packetLen
        dataLen,  // payloadLen
        0  // subSeq
    );

    auto headerBuffer = headerPara.Serialize();
    auto sendBuffer = std::make_unique<AVTransDataBuffer>(SessionDataHeader::HEADER_LEN + dataLen);
    uint8_t* header = sendBuffer->Data();

    // copy header
    memcpy_s(header, sendBuffer->Size(),
        headerBuffer->Data(), SessionDataHeader::HEADER_LEN);
    
    // copy data
    memcpy_s(header + SessionDataHeader::HEADER_LEN,
        sendBuffer->Size() - SessionDataHeader::HEADER_LEN,
            buffer->Data(), dataLen);

    // Step 4: Prepare the mock listener for verifying callback
    auto mockListener = std::make_shared<MockChannelListener>();
    EXPECT_CALL(*mockListener, OnBytes(channelId, testing::_)).Times(1);  // 确保回调被调用一次

    // 注册监听器
    int32_t result = ChannelManager::GetInstance().RegisterChannelListener(channelId, mockListener);
    EXPECT_EQ(result, ERR_OK);  // 确保注册监听器成功

    // Step 5: Call OnBytesReceived and expect the callback
    ChannelManager::GetInstance().OnBytesReceived(socketId, header, dataLen);
}

/**
 * @tc.name: OnBytesReceived_Failure_DataEmpty
 * @tc.desc: Test for OnBytesReceived when an invalid channel ID is provided,
 *           and the error callback is triggered with DataEmpty.
 * @tc.type: FUNC
 */
HWTEST_F(ChannelManagerTest, OnBytesReceived_Failure_DataEmpty, TestSize.Level1)
{
    // Step 1: Initialize the ChannelManager
    EXPECT_CALL(mockSoftbus, Socket(testing::_))
        .WillRepeatedly(testing::Return(NUM_1234));  // 模拟返回一个有效的 socketId
    EXPECT_CALL(mockSoftbus, Listen(testing::_, testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(ERR_OK));  // 模拟监听成功
  
    // 初始化 ChannelManager，验证初始化结果为 ERR_OK
    int32_t initResult = ChannelManager::GetInstance().Init(ownerName);
    EXPECT_EQ(initResult, ERR_OK); // 确保初始化成功

    // Step 2: Create a server channel
    std::string channelName = "TestChannel";
    ChannelDataType dataType = ChannelDataType::BYTES;
    ChannelPeerInfo peerInfo = { "peerName", "networkId" };
    int32_t channelId = ChannelManager::GetInstance().CreateClientChannel(channelName, dataType, peerInfo);
    EXPECT_EQ(channelId, BYTES_START_ID);

    int32_t socketId = NUM_1234;

    // Step 4: Prepare the mock listener for verifying callback
    auto mockListener = std::make_shared<MockChannelListener>();
    EXPECT_CALL(*mockListener, OnBytes(channelId, testing::_)).Times(0);  // 确保回调被调用一次

    // 注册监听器
    int32_t result = ChannelManager::GetInstance().RegisterChannelListener(channelId, mockListener);
    EXPECT_EQ(result, ERR_OK);  // 确保注册监听器成功

    // Step 4: Mock error callback for invalid channelId
    EXPECT_CALL(*mockListener, OnError(channelId, RECV_DATA_EMPTY)).Times(1);

    // Step 5: Call OnBytesReceived with invalid channelId and expect error callback
    ChannelManager::GetInstance().OnBytesReceived(socketId, nullptr, NUM_1024);
}

/**
 * @tc.name: OnBytesReceived_Failure_PackRecvPacketDataFailed
 * @tc.desc: Test for OnBytesReceived when the packet data processing fails in ProcessRecvData,
 *           and the error callback is triggered with the appropriate error code.
 * @tc.type: FUNC
 */
HWTEST_F(ChannelManagerTest, OnBytesReceived_Failure_PackRecvPacketDataFailed, TestSize.Level1)
{
    // Step 1: Initialize the ChannelManager
    EXPECT_CALL(mockSoftbus, Socket(testing::_))
        .WillRepeatedly(testing::Return(NUM_1234));  // 模拟返回一个有效的 socketId
    EXPECT_CALL(mockSoftbus, Listen(testing::_, testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(ERR_OK));  // 模拟监听成功
  
    // 初始化 ChannelManager，验证初始化结果为 ERR_OK
    int32_t initResult = ChannelManager::GetInstance().Init(ownerName);
    EXPECT_EQ(initResult, ERR_OK); // 确保初始化成功

    // Step 2: Create a server channel
    std::string channelName = "TestChannel";
    ChannelDataType dataType = ChannelDataType::BYTES;
    ChannelPeerInfo peerInfo = { "peerName", "networkId" };
    int32_t channelId = ChannelManager::GetInstance().CreateClientChannel(channelName, dataType, peerInfo);
    EXPECT_EQ(channelId, BYTES_START_ID);

    int32_t socketId = NUM_1234;
    auto buffer = std::make_unique<AVTransDataBuffer>(NUM_1024);
    uint32_t dataLen = buffer->Size();
    // Step 3: Prepare test data for OnBytesReceived
    SessionDataHeader headerPara(
        NUM_1,
        FRAG_TYPE::FRAG_START_END,
        static_cast<int32_t>(ChannelDataType::BYTES),  // 这里的 dataType 应该与发送的数据类型一致
        10, // seqNum
        dataLen + SessionDataHeader::HEADER_LEN,  // totalLen
        dataLen + SessionDataHeader::HEADER_LEN,  // packetLen
        dataLen,  // payloadLen
        0  // subSeq
    );

    auto headerBuffer = headerPara.Serialize();
    auto sendBuffer = std::make_unique<AVTransDataBuffer>(SessionDataHeader::HEADER_LEN + dataLen);
    uint8_t* header = sendBuffer->Data();

    // copy header
    memcpy_s(header, sendBuffer->Size(),
        headerBuffer->Data(), SessionDataHeader::HEADER_LEN);
    
    // copy data
    memcpy_s(header + SessionDataHeader::HEADER_LEN,
        sendBuffer->Size() - SessionDataHeader::HEADER_LEN,
            buffer->Data(), dataLen);

    // Step 4: Prepare the mock listener for verifying callback
    auto mockListener = std::make_shared<MockChannelListener>();
    EXPECT_CALL(*mockListener, OnBytes(channelId, testing::_)).Times(0);  // 确保回调被调用一次

    // 注册监听器
    int32_t result = ChannelManager::GetInstance().RegisterChannelListener(channelId, mockListener);
    EXPECT_EQ(result, ERR_OK);  // 确保注册监听器成功
    // Step 5: Simulate failure in `PackRecvPacketData` and call OnBytesReceived
    ChannelManager::GetInstance().OnBytesReceived(socketId, header, dataLen);
}


} // namespace DistributedCollab
} // namespace OHOS
