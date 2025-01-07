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
    static constexpr int32_t CHANNGE_GAP = 1000;
    static constexpr int32_t INVALID_CHANNEL = 9999;
    static constexpr int32_t SLEEP_FOR_INIT = 100;
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
    EXPECT_CALL(mockSoftbus, Bind(testing::_ , testing::_, testing::_, testing::_))
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
    EXPECT_CALL(mockSoftbus, Bind(testing::_ , testing::_, testing::_, testing::_))
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
    EXPECT_CALL(mockSoftbus, Bind(testing::_ , testing::_, testing::_, testing::_))
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
} // namespace DistributedCollab
} // namespace OHOS
