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

#include "softbus_transport_test.h"

#include "softbus_adapter/mock_softbus_adapter.h"
#include "dtbschedmgr_device_info_storage.h"
#include "dsched_transport_softbus_adapter.h"
#include "test_log.h"
#include "dtbschedmgr_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {
namespace {
constexpr size_t SIZE_1 = 1;
constexpr size_t SIZE_2 = 2;
constexpr uint16_t SIZE_4 = 4;
constexpr uint32_t SIZE_6 = 6;
constexpr size_t OFFSET_1 = 1;
constexpr size_t OFFSET_2 = 2;
constexpr size_t OFFSET_3 = 3;
constexpr int32_t COUNT = 2;
constexpr int32_t SESSIONID = 0;
constexpr uint32_t SEQ_1 = 3;
constexpr uint32_t SEQ_2 = 4;
constexpr uint32_t TOTALLEN_1 = 5;
constexpr uint32_t TOTALLEN_2 = 8;
const std::string MYDEVIDEID = "myDeviceId";
const std::string PEERDEVICEID = "peerDeviceId";
const std::string SESSIONNAME = "sessionName";
constexpr uint32_t SHIFT_8 = 8;
constexpr uint16_t UINT16_SHIFT_MASK_TEST = 0x00ff;
const uint32_t DSCHED_BUFFER_SIZE_100 = 100;
constexpr uint32_t HEADERLEN = 49;
constexpr uint32_t SIZE_50 = 50;
constexpr uint32_t MAXSENDSIZE = 513;
constexpr uint32_t TOTALLEN = 600;
constexpr int32_t INVALID_SESSION_ID = -1;
}

// DSchedDataBufferTest
void DSchedDataBufferTest::SetUpTestCase()
{
    DTEST_LOG << "DSchedDataBufferTest::SetUpTestCase" << std::endl;
}

void DSchedDataBufferTest::TearDownTestCase()
{
    DTEST_LOG << "DSchedDataBufferTest::TearDownTestCase" << std::endl;
}

void DSchedDataBufferTest::TearDown()
{
    dataBufferTest_ = nullptr;
    DTEST_LOG << "DSchedDataBufferTest::TearDown" << std::endl;
}

void DSchedDataBufferTest::SetUp()
{
    dataBufferTest_ = std::make_shared<DSchedDataBuffer>(SIZE_2);
    DTEST_LOG << "DSchedDataBufferTest::SetUp" << std::endl;
}

//DSchedSoftbusSessionTest
void DSchedSoftbusSessionTest::SetUpTestCase()
{
    DTEST_LOG << "DSchedSoftbusSessionTest::SetUpTestCase" << std::endl;
}

void DSchedSoftbusSessionTest::TearDownTestCase()
{
    DTEST_LOG << "DSchedSoftbusSessionTest::TearDownTestCase" << std::endl;
}

void DSchedSoftbusSessionTest::TearDown()
{
    DTEST_LOG << "DSchedSoftbusSessionTest::TearDown" << std::endl;
}

void DSchedSoftbusSessionTest::SetUp()
{
    DTEST_LOG << "DSchedSoftbusSessionTest::SetUp" << std::endl;
}

//DSchedTransportSoftbusAdapterTest
void DSchedTransportSoftbusAdapterTest::SetUpTestCase()
{
    DTEST_LOG << "DSchedTransportSoftbusAdapterTest::SetUpTestCase" << std::endl;
}

void DSchedTransportSoftbusAdapterTest::TearDownTestCase()
{
    DTEST_LOG << "DSchedTransportSoftbusAdapterTest::TearDownTestCase" << std::endl;
}

void DSchedTransportSoftbusAdapterTest::TearDown()
{
    DTEST_LOG << "DSchedTransportSoftbusAdapterTest::TearDown" << std::endl;
}

void DSchedTransportSoftbusAdapterTest::SetUp()
{
    DTEST_LOG << "DSchedTransportSoftbusAdapterTest::SetUp" << std::endl;
}

/**
 * @tc.name: Size_001
 * @tc.desc: call Size
 * @tc.type: FUNC
 */
HWTEST_F(DSchedDataBufferTest, Size_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedDataBufferTest Size_001 begin" << std::endl;
    ASSERT_NE(dataBufferTest_, nullptr);
    size_t ret = dataBufferTest_->Size();
    EXPECT_EQ(ret, SIZE_2);
    DTEST_LOG << "DSchedDataBufferTest Size_001 end" << std::endl;
}

/**
 * @tc.name: Offset_001
 * @tc.desc: call Offset
 * @tc.type: FUNC
 */
HWTEST_F(DSchedDataBufferTest, Offset_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedDataBufferTest Offset_001 begin" << std::endl;
    ASSERT_NE(dataBufferTest_, nullptr);
    dataBufferTest_->rangeOffset_ = SIZE_2;
    size_t ret = dataBufferTest_->Offset();
    EXPECT_EQ(ret, SIZE_2);
    DTEST_LOG << "DSchedDataBufferTest Offset_001 end" << std::endl;
}

/**
 * @tc.name: Capacity_001
 * @tc.desc: call Capacity
 * @tc.type: FUNC
 */
HWTEST_F(DSchedDataBufferTest, Capacity_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedDataBufferTest Capacity_001 begin" << std::endl;
    ASSERT_NE(dataBufferTest_, nullptr);
    size_t ret = dataBufferTest_->Capacity();
    EXPECT_EQ(ret, SIZE_2);
    DTEST_LOG << "DSchedDataBufferTest Capacity_001 end" << std::endl;
}

/**
 * @tc.name: Data_001
 * @tc.desc: call Data
 * @tc.type: FUNC
 */
HWTEST_F(DSchedDataBufferTest, Data_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedDataBufferTest Data_001 begin" << std::endl;
    ASSERT_NE(dataBufferTest_, nullptr);
    uint8_t *ret = dataBufferTest_->Data();
    EXPECT_NE(ret, nullptr);
    DTEST_LOG << "DSchedDataBufferTest Data_001 end" << std::endl;
}

/**
 * @tc.name: Data_002
 * @tc.desc: call Data
 * @tc.type: FUNC
 */
HWTEST_F(DSchedDataBufferTest, Data_002, TestSize.Level3)
{
    DTEST_LOG << "DSchedDataBufferTest Data_002 begin" << std::endl;
    ASSERT_NE(dataBufferTest_, nullptr);
    dataBufferTest_->data_ = nullptr;
    uint8_t *ret = dataBufferTest_->Data();
    EXPECT_EQ(ret, nullptr);
    DTEST_LOG << "DSchedDataBufferTest Data_002 end" << std::endl;
}

/**
 * @tc.name: SetRange_001
 * @tc.desc: call SetRange
 * @tc.type: FUNC
 */
HWTEST_F(DSchedDataBufferTest, SetRange_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedDataBufferTest SetRange_001 begin" << std::endl;
    ASSERT_NE(dataBufferTest_, nullptr);
    int32_t ret = dataBufferTest_->SetRange(OFFSET_2, SIZE_1);
    EXPECT_EQ(ret, -1);
    DTEST_LOG << "DSchedDataBufferTest SetRange_001 end" << std::endl;
}

/**
 * @tc.name: SetRange_002
 * @tc.desc: call SetRange
 * @tc.type: FUNC
 */
HWTEST_F(DSchedDataBufferTest, SetRange_002, TestSize.Level3)
{
    DTEST_LOG << "DSchedDataBufferTest SetRange_002 begin" << std::endl;
    ASSERT_NE(dataBufferTest_, nullptr);
    int32_t ret = dataBufferTest_->SetRange(OFFSET_3, SIZE_1);
    EXPECT_EQ(ret, -1);
    DTEST_LOG << "DSchedDataBufferTest SetRange_002 end" << std::endl;
}

/**
 * @tc.name: SetRange_003
 * @tc.desc: call SetRange
 * @tc.type: FUNC
 */
HWTEST_F(DSchedDataBufferTest, SetRange_003, TestSize.Level3)
{
    DTEST_LOG << "DSchedDataBufferTest SetRange_002 begin" << std::endl;
    ASSERT_NE(dataBufferTest_, nullptr);
    int32_t ret = dataBufferTest_->SetRange(OFFSET_2, 0);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedDataBufferTest SetRange_003 end" << std::endl;
}

/**
 * @tc.name: OnDisconnect_001
 * @tc.desc: call OnDisconnect
 * @tc.type: FUNC
 */
HWTEST_F(DSchedSoftbusSessionTest, OnDisconnect_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedSoftbusSessionTest OnDisconnect_001 begin" << std::endl;
    softbusSessionTest_ = std::make_shared<DSchedSoftbusSession>();
    ASSERT_NE(softbusSessionTest_, nullptr);
    softbusSessionTest_->OnConnect();

    softbusSessionTest_->refCount_ = 0;
    bool ret = softbusSessionTest_->OnDisconnect();
    EXPECT_EQ(ret, true);

    softbusSessionTest_->refCount_ = COUNT;
    ret = softbusSessionTest_->OnDisconnect();
    EXPECT_EQ(ret, false);
    softbusSessionTest_ = nullptr;
    DTEST_LOG << "DSchedSoftbusSessionTest OnDisconnect_001 end" << std::endl;
}

/**
 * @tc.name: OnBytesReceived_001
 * @tc.desc: call OnBytesReceived
 * @tc.type: FUNC
 */
HWTEST_F(DSchedSoftbusSessionTest, OnBytesReceived_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedSoftbusSessionTest OnBytesReceived_001 begin" << std::endl;
    softbusSessionTest_ = std::make_shared<DSchedSoftbusSession>();
    std::shared_ptr<DSchedDataBuffer> buffer = std::make_shared<DSchedDataBuffer>(SIZE_1);
    ASSERT_NE(softbusSessionTest_, nullptr);
    ASSERT_NE(buffer, nullptr);
    int32_t ret = softbusSessionTest_->OnBytesReceived(buffer);
    EXPECT_EQ(ret, ERR_OK);

    ret = softbusSessionTest_->OnBytesReceived(nullptr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    softbusSessionTest_ = nullptr;
    DTEST_LOG << "DSchedSoftbusSessionTest OnBytesReceived_001 end" << std::endl;
}

/**
 * @tc.name: SendData_001
 * @tc.desc: call SendData
 * @tc.type: FUNC
 */
HWTEST_F(DSchedSoftbusSessionTest, SendData_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedSoftbusSessionTest SendData_001 begin" << std::endl;
    softbusSessionTest_ = std::make_shared<DSchedSoftbusSession>();
    std::shared_ptr<DSchedDataBuffer> buffer = std::make_shared<DSchedDataBuffer>(SIZE_1);
    ASSERT_NE(softbusSessionTest_, nullptr);
    ASSERT_NE(buffer, nullptr);
    SoftbusMock mockSoftbus;
    int32_t socketId = 0;
    EXPECT_CALL(mockSoftbus, GetSessionOption(socketId, testing::_, testing::_, sizeof(uint32_t)))
        .WillOnce(testing::Return(-1));

    int32_t dataType = COUNT;
    int32_t ret = softbusSessionTest_->SendData(buffer, dataType);
    EXPECT_EQ(ret, ERR_OK);

    ret = softbusSessionTest_->SendData(nullptr, dataType);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    softbusSessionTest_ = nullptr;
    DTEST_LOG << "DSchedSoftbusSessionTest SendData_001 end" << std::endl;
}

/**
 * @tc.name: GetPeerDeviceId_001
 * @tc.desc: call GetPeerDeviceId
 * @tc.type: FUNC
 */
HWTEST_F(DSchedSoftbusSessionTest, GetPeerDeviceId_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedSoftbusSessionTest GetPeerDeviceId_001 begin" << std::endl;
    SessionInfo info = {0, MYDEVIDEID, PEERDEVICEID, SESSIONNAME, false};
    softbusSessionTest_ = std::make_shared<DSchedSoftbusSession>(info);
    ASSERT_NE(softbusSessionTest_, nullptr);
    std::string str = softbusSessionTest_->GetPeerDeviceId();
    EXPECT_EQ(str, PEERDEVICEID);
    softbusSessionTest_ = nullptr;
    DTEST_LOG << "DSchedSoftbusSessionTest GetPeerDeviceId_001 end" << std::endl;
}

/**
 * @tc.name: CheckUnPackBuffer_001
 * @tc.desc: call CheckUnPackBuffer
 * @tc.type: FUNC
 */
HWTEST_F(DSchedSoftbusSessionTest, CheckUnPackBuffer_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedSoftbusSessionTest CheckUnPackBuffer_001 begin" << std::endl;
    SessionInfo info = {0, MYDEVIDEID, PEERDEVICEID, SESSIONNAME, false};
    DSchedSoftbusSession::SessionDataHeader headerPara;
    softbusSessionTest_ = std::make_shared<DSchedSoftbusSession>(info);
    ASSERT_NE(softbusSessionTest_, nullptr);
    softbusSessionTest_->isWaiting_ = false;
    int32_t ret = softbusSessionTest_->CheckUnPackBuffer(headerPara);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    softbusSessionTest_->isWaiting_ = true;
    softbusSessionTest_->nowSeq_ = SEQ_1;
    ret = softbusSessionTest_->CheckUnPackBuffer(headerPara);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    softbusSessionTest_ = nullptr;
    DTEST_LOG << "DSchedSoftbusSessionTest CheckUnPackBuffer_001 end" << std::endl;
}

/**
 * @tc.name: CheckUnPackBuffer_002
 * @tc.desc: call CheckUnPackBuffer
 * @tc.type: FUNC
 */
HWTEST_F(DSchedSoftbusSessionTest, CheckUnPackBuffer_002, TestSize.Level3)
{
    DTEST_LOG << "DSchedSoftbusSessionTest CheckUnPackBuffer_002 begin" << std::endl;
    SessionInfo info = {0, MYDEVIDEID, PEERDEVICEID, SESSIONNAME, false};
    DSchedSoftbusSession::SessionDataHeader headerPara = {0, 0, 0, SEQ_1, 0, SEQ_2, TOTALLEN_1};
    softbusSessionTest_ = std::make_shared<DSchedSoftbusSession>(info);
    ASSERT_NE(softbusSessionTest_, nullptr);
    softbusSessionTest_->nowSeq_ = SEQ_1;
    softbusSessionTest_->nowSubSeq_ = SEQ_2;
    softbusSessionTest_->isWaiting_ = true;
    int32_t ret = softbusSessionTest_->CheckUnPackBuffer(headerPara);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    softbusSessionTest_->nowSeq_ = SEQ_1;
    softbusSessionTest_->nowSubSeq_ = SEQ_1;
    softbusSessionTest_->isWaiting_ = true;
    ret = softbusSessionTest_->CheckUnPackBuffer(headerPara);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    softbusSessionTest_ = nullptr;
    DTEST_LOG << "DSchedSoftbusSessionTest CheckUnPackBuffer_002 end" << std::endl;
}

/**
 * @tc.name: CheckUnPackBuffer_003
 * @tc.desc: call CheckUnPackBuffer
 * @tc.type: FUNC
 */
HWTEST_F(DSchedSoftbusSessionTest, CheckUnPackBuffer_003, TestSize.Level3)
{
    DTEST_LOG << "DSchedSoftbusSessionTest CheckUnPackBuffer_003 begin" << std::endl;
    SessionInfo info = {0, MYDEVIDEID, PEERDEVICEID, SESSIONNAME, false};
    DSchedSoftbusSession::SessionDataHeader headerPara = {0, 0, 0, SEQ_1, 0, SEQ_2, TOTALLEN_1};
    softbusSessionTest_ = std::make_shared<DSchedSoftbusSession>(info);
    ASSERT_NE(softbusSessionTest_, nullptr);
    softbusSessionTest_->nowSeq_ = SEQ_1;
    softbusSessionTest_->nowSubSeq_ = SEQ_1;
    softbusSessionTest_->totalLen_ = TOTALLEN_2;
    softbusSessionTest_->offset_ = SEQ_1;
    softbusSessionTest_->isWaiting_ = true;
    int32_t ret = softbusSessionTest_->CheckUnPackBuffer(headerPara);
    EXPECT_EQ(ret, ERR_OK);
    softbusSessionTest_ = nullptr;
    DTEST_LOG << "DSchedSoftbusSessionTest CheckUnPackBuffer_003 end" << std::endl;
}

/**
 * @tc.name: UnPackSendData_001
 * @tc.desc: call UnPackSendData
 * @tc.type: FUNC
 */
HWTEST_F(DSchedSoftbusSessionTest, UnPackSendData_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedSoftbusSessionTest UnPackSendData_001 begin" << std::endl;
    int32_t dataType = 0;
    softbusSessionTest_ = std::make_shared<DSchedSoftbusSession>();
    ASSERT_NE(softbusSessionTest_, nullptr);
    SoftbusMock mockSoftbus;
    int32_t socketId = 0;
    EXPECT_CALL(mockSoftbus, GetSessionOption(socketId, testing::_, testing::_, sizeof(uint32_t)))
        .WillOnce(testing::Return(-1));

    std::shared_ptr<DSchedDataBuffer> buffer = std::make_shared<DSchedDataBuffer>(SIZE_1);
    int32_t ret = softbusSessionTest_->UnPackSendData(buffer, dataType);
    EXPECT_NE(ret, ERR_OK);
    softbusSessionTest_ = nullptr;
    DTEST_LOG << "DSchedSoftbusSessionTest UnPackSendData_001 end" << std::endl;
}

/**
 * @tc.name: UnPackSendData_002
 * @tc.desc: call UnPackSendData
 * @tc.type: FUNC
 */
HWTEST_F(DSchedSoftbusSessionTest, UnPackSendData_002, TestSize.Level3)
{
    DTEST_LOG << "DSchedSoftbusSessionTest UnPackSendData_002 begin" << std::endl;
    int32_t dataType = 0;
    softbusSessionTest_ = std::make_shared<DSchedSoftbusSession>();
    ASSERT_NE(softbusSessionTest_, nullptr);

    SoftbusMock mockSoftbus;
    int32_t socketId = 0;
    EXPECT_CALL(mockSoftbus, GetSessionOption(socketId, testing::_, testing::_, sizeof(uint32_t)))
        .WillOnce(testing::Invoke([&](int sessionId, SessionOption option,
            void* optionValue, uint32_t valueSize) {
            *reinterpret_cast<uint32_t*>(optionValue) = DSchedSoftbusSession::BINARY_DATA_PACKET_RESERVED_BUFFER - 1;
            return ERR_OK;
        }));
    std::shared_ptr<DSchedDataBuffer> buffer = std::make_shared<DSchedDataBuffer>(
            DSchedSoftbusSession::BINARY_DATA_PACKET_RESERVED_BUFFER + 1);
    int32_t ret = softbusSessionTest_->UnPackSendData(buffer, dataType);
    EXPECT_NE(ret, ERR_OK);
    softbusSessionTest_ = nullptr;
    DTEST_LOG << "DSchedSoftbusSessionTest UnPackSendData_002 end" << std::endl;
}

/**
 * @tc.name: UnPackStartEndData_001
 * @tc.desc: call UnPackStartEndData
 * @tc.type: FUNC
 */
HWTEST_F(DSchedSoftbusSessionTest, UnPackStartEndData_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedSoftbusSessionTest UnPackStartEndData_001 begin" << std::endl;
    int32_t dataType = 0;
    softbusSessionTest_ = std::make_shared<DSchedSoftbusSession>();
    ASSERT_NE(softbusSessionTest_, nullptr);
    EXPECT_CALL(mockSoftbus, SendBytes(testing::_, testing::_, testing::_)).WillOnce(testing::Return(-1));
    std::shared_ptr<DSchedDataBuffer> buffer = std::make_shared<DSchedDataBuffer>(SIZE_1);
    int32_t ret = softbusSessionTest_->UnPackStartEndData(buffer, dataType);
    EXPECT_NE(ret, ERR_OK);

    ret = softbusSessionTest_->UnPackStartEndData(nullptr, dataType);
    EXPECT_EQ(ret, INVALID_SESSION_ID);
    softbusSessionTest_ = nullptr;
    DTEST_LOG << "DSchedSoftbusSessionTest UnPackStartEndData_001 end" << std::endl;
}

/**
 * @tc.name: GetFragDataHeader_001
 * @tc.desc: call GetFragDataHeader
 * @tc.type: FUNC
 */
HWTEST_F(DSchedSoftbusSessionTest, GetFragDataHeader_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedSoftbusSessionTest GetFragDataHeader_001 begin" << std::endl;
    int32_t dataType = 0;
    softbusSessionTest_ = std::make_shared<DSchedSoftbusSession>();
    ASSERT_NE(softbusSessionTest_, nullptr);

    std::shared_ptr<DSchedDataBuffer> buffer =
        std::make_shared<DSchedDataBuffer>(static_cast<size_t>(DSchedSoftbusSession::BINARY_HEADER_FRAG_LEN));

    auto ptr = buffer->Data();
    ASSERT_NE(ptr, nullptr);
    uint32_t i = 0;
    for (int32_t j = 0; j < SIZE_6; j++) {
        ptr[i++] = DSchedSoftbusSession::TLV_TYPE_SEQ_NUM >> SHIFT_8;
        ptr[i++] = DSchedSoftbusSession::TLV_TYPE_SEQ_NUM & UINT16_SHIFT_MASK_TEST;
        ptr[i++] = SIZE_4 >> SHIFT_8;
        ptr[i++] = SIZE_4 & UINT16_SHIFT_MASK_TEST;
        ptr[i++] = 1;
        ptr[i++] = 0;
        ptr[i++] = 0;
        ptr[i++] = 0;
    }

    DSchedSoftbusSession::SessionDataHeader headerPara;
    int32_t ret = softbusSessionTest_->GetFragDataHeader(ptr, headerPara);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    softbusSessionTest_ = nullptr;
    DTEST_LOG << "DSchedSoftbusSessionTest GetFragDataHeader_001 end" << std::endl;
}

/**
 * @tc.name: ReadTlvToHeader_001
 * @tc.desc: call ReadTlvToHeader
 * @tc.type: FUNC
 */
HWTEST_F(DSchedSoftbusSessionTest, ReadTlvToHeader_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedSoftbusSessionTest ReadTlvToHeader_001 begin" << std::endl;
    int32_t dataType = 0;
    softbusSessionTest_ = std::make_shared<DSchedSoftbusSession>();
    ASSERT_NE(softbusSessionTest_, nullptr);

    std::shared_ptr<DSchedDataBuffer> buffer =
        std::make_shared<DSchedDataBuffer>(static_cast<size_t>(DSchedSoftbusSession::BINARY_HEADER_FRAG_LEN));

    auto ptr = buffer->Data();
    ASSERT_NE(ptr, nullptr);
    uint32_t i = 0;
    ptr[i++] = DSchedSoftbusSession::TLV_TYPE_VERSION >> SHIFT_8;
    ptr[i++] = DSchedSoftbusSession::TLV_TYPE_VERSION & UINT16_SHIFT_MASK_TEST;
    ptr[i++] = SIZE_4 >> SHIFT_8;
    ptr[i++] = SIZE_4 & UINT16_SHIFT_MASK_TEST;
    ptr[i++] = 1;
    ptr[i++] = 0;
    ptr[i++] = 0;
    ptr[i++] = 0;

    uint16_t index = 0;
    DSchedSoftbusSession::SessionDataHeader headerPara;
    int32_t ret = softbusSessionTest_->ReadTlvToHeader(ptr, headerPara, index, i);
    EXPECT_NE(ret, ERR_OK);

    softbusSessionTest_ = nullptr;
    DTEST_LOG << "DSchedSoftbusSessionTest ReadTlvToHeader_001 end" << std::endl;
}

/**
 * @tc.name: ReadTlvToHeader_002
 * @tc.desc: call ReadTlvToHeader
 * @tc.type: FUNC
 */
HWTEST_F(DSchedSoftbusSessionTest, ReadTlvToHeader_002, TestSize.Level3)
{
    DTEST_LOG << "DSchedSoftbusSessionTest ReadTlvToHeader_002 begin" << std::endl;
    int32_t dataType = 0;
    softbusSessionTest_ = std::make_shared<DSchedSoftbusSession>();
    ASSERT_NE(softbusSessionTest_, nullptr);

    std::shared_ptr<DSchedDataBuffer> buffer =
        std::make_shared<DSchedDataBuffer>(static_cast<size_t>(DSchedSoftbusSession::BINARY_HEADER_FRAG_LEN));

    auto ptr = buffer->Data();
    ASSERT_NE(ptr, nullptr);
    uint32_t i = 0;
    ptr[i++] = DSchedSoftbusSession::TLV_TYPE_FRAG_FLAG >> SHIFT_8;
    ptr[i++] = DSchedSoftbusSession::TLV_TYPE_FRAG_FLAG & UINT16_SHIFT_MASK_TEST;
    ptr[i++] = SIZE_4 >> SHIFT_8;
    ptr[i++] = SIZE_4 & UINT16_SHIFT_MASK_TEST;
    ptr[i++] = 1;
    ptr[i++] = 0;
    ptr[i++] = 0;
    ptr[i++] = 0;

    uint16_t index = 0;
    DSchedSoftbusSession::SessionDataHeader headerPara;
    int32_t ret = softbusSessionTest_->ReadTlvToHeader(ptr, headerPara, index, i);
    EXPECT_NE(ret, ERR_OK);

    softbusSessionTest_ = nullptr;
    DTEST_LOG << "DSchedSoftbusSessionTest ReadTlvToHeader_002 end" << std::endl;
}

/**
 * @tc.name: ReadTlvToHeader_003
 * @tc.desc: call ReadTlvToHeader
 * @tc.type: FUNC
 */
HWTEST_F(DSchedSoftbusSessionTest, ReadTlvToHeader_003, TestSize.Level3)
{
    DTEST_LOG << "DSchedSoftbusSessionTest ReadTlvToHeader_003 begin" << std::endl;
    int32_t dataType = 0;
    softbusSessionTest_ = std::make_shared<DSchedSoftbusSession>();
    ASSERT_NE(softbusSessionTest_, nullptr);

    std::shared_ptr<DSchedDataBuffer> buffer =
        std::make_shared<DSchedDataBuffer>(static_cast<size_t>(DSchedSoftbusSession::BINARY_HEADER_FRAG_LEN));

    auto ptr = buffer->Data();
    ASSERT_NE(ptr, nullptr);
    uint32_t i = 0;
    ptr[i++] = DSchedSoftbusSession::TLV_TYPE_DATA_TYPE >> SHIFT_8;
    ptr[i++] = DSchedSoftbusSession::TLV_TYPE_DATA_TYPE & UINT16_SHIFT_MASK_TEST;
    ptr[i++] = SIZE_4 >> SHIFT_8;
    ptr[i++] = SIZE_4 & UINT16_SHIFT_MASK_TEST;
    ptr[i++] = 1;
    ptr[i++] = 0;
    ptr[i++] = 0;
    ptr[i++] = 0;

    uint16_t index = 0;
    DSchedSoftbusSession::SessionDataHeader headerPara;
    int32_t ret = softbusSessionTest_->ReadTlvToHeader(ptr, headerPara, index, i);
    EXPECT_EQ(ret, ERR_OK);

    softbusSessionTest_ = nullptr;
    DTEST_LOG << "DSchedSoftbusSessionTest ReadTlvToHeader_003 end" << std::endl;
}

/**
 * @tc.name: ReadTlvToHeader_004
 * @tc.desc: call ReadTlvToHeader
 * @tc.type: FUNC
 */
HWTEST_F(DSchedSoftbusSessionTest, ReadTlvToHeader_004, TestSize.Level3)
{
    DTEST_LOG << "DSchedSoftbusSessionTest ReadTlvToHeader_004 begin" << std::endl;
    int32_t dataType = 0;
    softbusSessionTest_ = std::make_shared<DSchedSoftbusSession>();
    ASSERT_NE(softbusSessionTest_, nullptr);

    std::shared_ptr<DSchedDataBuffer> buffer =
        std::make_shared<DSchedDataBuffer>(static_cast<size_t>(DSchedSoftbusSession::BINARY_HEADER_FRAG_LEN));

    auto ptr = buffer->Data();
    ASSERT_NE(ptr, nullptr);
    uint32_t i = 0;
    ptr[i++] = DSchedSoftbusSession::TLV_TYPE_TOTAL_LEN >> SHIFT_8;
    ptr[i++] = DSchedSoftbusSession::TLV_TYPE_TOTAL_LEN & UINT16_SHIFT_MASK_TEST;
    ptr[i++] = SIZE_4 >> SHIFT_8;
    ptr[i++] = SIZE_4 & UINT16_SHIFT_MASK_TEST;
    ptr[i++] = 1;
    ptr[i++] = 0;
    ptr[i++] = 0;
    ptr[i++] = 0;

    uint16_t index = 0;
    DSchedSoftbusSession::SessionDataHeader headerPara;
    int32_t ret = softbusSessionTest_->ReadTlvToHeader(ptr, headerPara, index, i);
    EXPECT_EQ(ret, ERR_OK);

    softbusSessionTest_ = nullptr;
    DTEST_LOG << "DSchedSoftbusSessionTest ReadTlvToHeader_004 end" << std::endl;
}

/**
 * @tc.name: ReadTlvToHeader_005
 * @tc.desc: call ReadTlvToHeader
 * @tc.type: FUNC
 */
HWTEST_F(DSchedSoftbusSessionTest, ReadTlvToHeader_005, TestSize.Level3)
{
    DTEST_LOG << "DSchedSoftbusSessionTest ReadTlvToHeader_005 begin" << std::endl;
    int32_t dataType = 0;
    softbusSessionTest_ = std::make_shared<DSchedSoftbusSession>();
    ASSERT_NE(softbusSessionTest_, nullptr);

    std::shared_ptr<DSchedDataBuffer> buffer =
        std::make_shared<DSchedDataBuffer>(static_cast<size_t>(DSchedSoftbusSession::BINARY_HEADER_FRAG_LEN));

    auto ptr = buffer->Data();
    ASSERT_NE(ptr, nullptr);
    uint32_t i = 0;
    ptr[i++] = DSchedSoftbusSession::TLV_TYPE_SUB_SEQ >> SHIFT_8;
    ptr[i++] = DSchedSoftbusSession::TLV_TYPE_SUB_SEQ & UINT16_SHIFT_MASK_TEST;
    ptr[i++] = SIZE_4 >> SHIFT_8;
    ptr[i++] = SIZE_4 & UINT16_SHIFT_MASK_TEST;
    ptr[i++] = 1;
    ptr[i++] = 0;
    ptr[i++] = 0;
    ptr[i++] = 0;

    uint16_t index = 0;
    DSchedSoftbusSession::SessionDataHeader headerPara;
    int32_t ret = softbusSessionTest_->ReadTlvToHeader(ptr, headerPara, index, i);
    EXPECT_NE(ret, ERR_OK);

    softbusSessionTest_ = nullptr;
    DTEST_LOG << "DSchedSoftbusSessionTest ReadTlvToHeader_005 end" << std::endl;
}

/**
 * @tc.name: ReadTlvToHeader_006
 * @tc.desc: call ReadTlvToHeader
 * @tc.type: FUNC
 */
HWTEST_F(DSchedSoftbusSessionTest, ReadTlvToHeader_006, TestSize.Level3)
{
    DTEST_LOG << "DSchedSoftbusSessionTest ReadTlvToHeader_006 begin" << std::endl;
    int32_t dataType = 0;
    softbusSessionTest_ = std::make_shared<DSchedSoftbusSession>();
    ASSERT_NE(softbusSessionTest_, nullptr);

    std::shared_ptr<DSchedDataBuffer> buffer =
        std::make_shared<DSchedDataBuffer>(static_cast<size_t>(DSchedSoftbusSession::BINARY_HEADER_FRAG_LEN));

    auto ptr = buffer->Data();
    ASSERT_NE(ptr, nullptr);
    uint32_t i = 0;
    ptr[i++] = DSchedSoftbusSession::TLV_TYPE_DATA_LEN >> SHIFT_8;
    ptr[i++] = DSchedSoftbusSession::TLV_TYPE_DATA_LEN & UINT16_SHIFT_MASK_TEST;
    ptr[i++] = SIZE_4 >> SHIFT_8;
    ptr[i++] = SIZE_4 & UINT16_SHIFT_MASK_TEST;
    ptr[i++] = 1;
    ptr[i++] = 0;
    ptr[i++] = 0;
    ptr[i++] = 0;

    uint16_t index = 0;
    DSchedSoftbusSession::SessionDataHeader headerPara;
    int32_t ret = softbusSessionTest_->ReadTlvToHeader(ptr, headerPara, index, i);
    EXPECT_EQ(ret, ERR_OK);

    softbusSessionTest_ = nullptr;
    DTEST_LOG << "DSchedSoftbusSessionTest ReadTlvToHeader_006 end" << std::endl;
}

/**
 * @tc.name: ReadTlvToHeader_007
 * @tc.desc: call ReadTlvToHeader
 * @tc.type: FUNC
 */
HWTEST_F(DSchedSoftbusSessionTest, ReadTlvToHeader_007, TestSize.Level3)
{
    DTEST_LOG << "DSchedSoftbusSessionTest ReadTlvToHeader_007 begin" << std::endl;
    softbusSessionTest_ = std::make_shared<DSchedSoftbusSession>();
    ASSERT_NE(softbusSessionTest_, nullptr);

    uint8_t *ptr = nullptr;
    uint16_t i = 0;

    uint16_t index = 0;
    DSchedSoftbusSession::SessionDataHeader headerPara;
    int32_t ret = softbusSessionTest_->ReadTlvToHeader(ptr, headerPara, index, i);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    uint8_t ptr1[] = {1, 2};
    ret = softbusSessionTest_->ReadTlvToHeader(ptr1, headerPara, index, i);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    i = 2;
    ret = softbusSessionTest_->ReadTlvToHeader(ptr1, headerPara, index, i);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    uint8_t high = SIZE_4 >> SHIFT_8;
    uint8_t low = SIZE_4 & UINT16_SHIFT_MASK_TEST;
    uint8_t ptr2[] = {1, 2, high, low};
    ret = softbusSessionTest_->ReadTlvToHeader(ptr2, headerPara, index, i);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    i = 4;
    ret = softbusSessionTest_->ReadTlvToHeader(ptr2, headerPara, index, i);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    uint8_t ptr3[] = {1, 2, high, low, 5, 6};
    ret = softbusSessionTest_->ReadTlvToHeader(ptr3, headerPara, index, i);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    i = 6;
    ret = softbusSessionTest_->ReadTlvToHeader(ptr3, headerPara, index, i);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    softbusSessionTest_ = nullptr;
    DTEST_LOG << "DSchedSoftbusSessionTest ReadTlvToHeader_007 end" << std::endl;
}

/**
 * @tc.name: PackRecvData_001
 * @tc.desc: call PackRecvData
 * @tc.type: FUNC
 */
HWTEST_F(DSchedSoftbusSessionTest, PackRecvData_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedSoftbusSessionTest PackRecvData_001 begin" << std::endl;
    std::shared_ptr<DSchedDataBuffer> buffer = std::make_shared<DSchedDataBuffer>(DSCHED_BUFFER_SIZE_100);
    softbusSessionTest_ = std::make_shared<DSchedSoftbusSession>();
    ASSERT_NE(softbusSessionTest_, nullptr);
    EXPECT_NO_FATAL_FAILURE(softbusSessionTest_->PackRecvData(buffer));

    std::shared_ptr<DSchedDataBuffer> bufferNull = nullptr;
    EXPECT_NO_FATAL_FAILURE(softbusSessionTest_->PackRecvData(bufferNull));
    DTEST_LOG << "DSchedSoftbusSessionTest PackRecvData_001 end" << std::endl;
}


/**
 * @tc.name: AssembleNoFrag_001
 * @tc.desc: call AssembleNoFrag
 * @tc.type: FUNC
 */
HWTEST_F(DSchedSoftbusSessionTest, AssembleNoFrag_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedSoftbusSessionTest AssembleFrag_001 begin" << std::endl;
    std::shared_ptr<DSchedDataBuffer> buffer = std::make_shared<DSchedDataBuffer>(SIZE_1);
    DSchedSoftbusSession::SessionDataHeader headerPara = {0, 0, 0, SEQ_1, 0, SEQ_2, TOTALLEN_1};
    softbusSessionTest_ = std::make_shared<DSchedSoftbusSession>();
    ASSERT_NE(softbusSessionTest_, nullptr);
    softbusSessionTest_->AssembleNoFrag(buffer, headerPara);

    headerPara.totalLen = TOTALLEN_1;
    EXPECT_NO_FATAL_FAILURE(softbusSessionTest_->AssembleNoFrag(buffer, headerPara));

    std::shared_ptr<DSchedDataBuffer> bufferNull = nullptr;
    EXPECT_NO_FATAL_FAILURE(softbusSessionTest_->AssembleNoFrag(bufferNull, headerPara));
    DTEST_LOG << "DSchedSoftbusSessionTest AssembleNoFrag_001 end" << std::endl;
}

/**
 * @tc.name: AssembleFrag_001
 * @tc.desc: call AssembleFrag
 * @tc.type: FUNC
 */
HWTEST_F(DSchedSoftbusSessionTest, AssembleFrag_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedSoftbusSessionTest AssembleFrag_001 begin" << std::endl;
    std::shared_ptr<DSchedDataBuffer> buffer = std::make_shared<DSchedDataBuffer>(SIZE_1);
    DSchedSoftbusSession::SessionDataHeader headerPara =
        {0, DSchedSoftbusSession::FRAG_START, 0, SEQ_1, 0, SEQ_2, TOTALLEN_1};
    softbusSessionTest_ = std::make_shared<DSchedSoftbusSession>();
    ASSERT_NE(softbusSessionTest_, nullptr);
    softbusSessionTest_->AssembleFrag(buffer, headerPara);
    headerPara.fragFlag = DSchedSoftbusSession::FRAG_MID;
    softbusSessionTest_->AssembleFrag(buffer, headerPara);
    headerPara.fragFlag = DSchedSoftbusSession::FRAG_END;
    EXPECT_NO_FATAL_FAILURE(softbusSessionTest_->AssembleFrag(buffer, headerPara));
    DTEST_LOG << "DSchedSoftbusSessionTest AssembleFrag_001 end" << std::endl;
}

/**
 * @tc.name: SetHeadParaDataLen_001
 * @tc.desc: call SetHeadParaDataLen
 * @tc.type: FUNC
 */
HWTEST_F(DSchedSoftbusSessionTest, SetHeadParaDataLen_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedSoftbusSessionTest SetHeadParaDataLen_001 begin" << std::endl;
    DSchedSoftbusSession::SessionDataHeader headerPara = {0, 0, 0, SEQ_1, 0, SEQ_2, TOTALLEN_1};
    uint32_t totalLen = TOTALLEN;
    uint32_t offset = OFFSET_1;
    uint32_t maxSendSize = MAXSENDSIZE;
    softbusSessionTest_ = std::make_shared<DSchedSoftbusSession>();
    ASSERT_NE(softbusSessionTest_, nullptr);
    softbusSessionTest_->SetHeadParaDataLen(headerPara, totalLen, offset, maxSendSize);
    offset = DSCHED_BUFFER_SIZE_100;
    softbusSessionTest_->SetHeadParaDataLen(headerPara, totalLen, offset, maxSendSize);
    EXPECT_NO_FATAL_FAILURE(softbusSessionTest_->GetNowTimeStampUs());
    DTEST_LOG << "DSchedSoftbusSessionTest SetHeadParaDataLen_001 end" << std::endl;
}

/**
 * @tc.name: MakeFragDataHeader_001
 * @tc.desc: call MakeFragDataHeader
 * @tc.type: FUNC
 */
HWTEST_F(DSchedSoftbusSessionTest, MakeFragDataHeader_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedSoftbusSessionTest MakeFragDataHeader_001 begin" << std::endl;
    DSchedSoftbusSession::SessionDataHeader headerPara = {0};
    uint8_t *header = new uint8_t[DSCHED_BUFFER_SIZE_100] {0};
    uint32_t len = HEADERLEN;
    softbusSessionTest_ = std::make_shared<DSchedSoftbusSession>();
    ASSERT_NE(softbusSessionTest_, nullptr);
    softbusSessionTest_->MakeFragDataHeader(headerPara, header, len);
    uint8_t *header1 = new uint8_t[HEADERLEN] {0};
    EXPECT_NO_FATAL_FAILURE(softbusSessionTest_->MakeFragDataHeader(headerPara, header1, len));

    EXPECT_NO_FATAL_FAILURE(softbusSessionTest_->MakeFragDataHeader(headerPara, nullptr, len));
    EXPECT_NO_FATAL_FAILURE(softbusSessionTest_->MakeFragDataHeader(headerPara, header1, 0));
    delete[] header;
    delete[] header1;
    DTEST_LOG << "DSchedSoftbusSessionTest MakeFragDataHeader_001 end" << std::endl;
}

/**
 * @tc.name: WriteTlvToBuffer_001
 * @tc.desc: call WriteTlvToBuffer
 * @tc.type: FUNC
 */
HWTEST_F(DSchedSoftbusSessionTest, WriteTlvToBuffer_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedSoftbusSessionTest WriteTlvToBuffer_001 begin" << std::endl;
    DSchedSoftbusSession::TlvItem tlvItem = {SIZE_4, SIZE_4, SEQ_2};
    uint8_t *buffer = new uint8_t[SIZE_50] {0};
    uint32_t bufLen = SIZE_50;
    softbusSessionTest_ = std::make_shared<DSchedSoftbusSession>();
    ASSERT_NE(softbusSessionTest_, nullptr);
    softbusSessionTest_->WriteTlvToBuffer(tlvItem, buffer, bufLen);
    uint8_t *buffer1 = new uint8_t[SEQ_1] {0};
    uint32_t bufLen1 = SIZE_1;
    EXPECT_NO_FATAL_FAILURE(softbusSessionTest_->WriteTlvToBuffer(tlvItem, buffer1, bufLen1));

    uint8_t *bufferNull = nullptr;
    EXPECT_NO_FATAL_FAILURE(softbusSessionTest_->WriteTlvToBuffer(tlvItem, bufferNull, bufLen1));
    delete[] buffer;
    delete[] buffer1;
    DTEST_LOG << "DSchedSoftbusSessionTest WriteTlvToBuffer_001 end" << std::endl;
}

/**
 * @tc.name: InitChannel_001
 * @tc.desc: call InitChannel
 * @tc.type: FUNC
 */
HWTEST_F(DSchedTransportSoftbusAdapterTest, InitChannel_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedTransportSoftbusAdapterTest InitChannel_001 begin" << std::endl;
    DSchedTransportSoftbusAdapter::GetInstance().serverSocket_ = COUNT;
    EXPECT_CALL(mockSoftbus, Socket(testing::_)).WillOnce(testing::Return(-1));
    int32_t ret = DSchedTransportSoftbusAdapter::GetInstance().InitChannel();
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DSchedTransportSoftbusAdapterTest InitChannel_001 end" << std::endl;
}

/**
 * @tc.name: GetSessionIdByDeviceId_001
 * @tc.desc: call GetSessionIdByDeviceId
 * @tc.type: FUNC
 */
HWTEST_F(DSchedTransportSoftbusAdapterTest, GetSessionIdByDeviceId_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedTransportSoftbusAdapterTest GetSessionIdByDeviceId_001 begin" << std::endl;
    int32_t sessionId = 0;
    DSchedTransportSoftbusAdapter::GetInstance().OnBind(sessionId, PEERDEVICEID);
    std::shared_ptr<DSchedDataBuffer> dataBuffer = std::make_shared<DSchedDataBuffer>(SIZE_1);
    ASSERT_NE(dataBuffer, nullptr);
    uint32_t dataType = 0;
    std::shared_ptr<IDataListener> listener = nullptr;
    DSchedTransportSoftbusAdapter::GetInstance().OnDataReady(sessionId, dataBuffer, dataType);
    DSchedTransportSoftbusAdapter::GetInstance().listeners_.clear();
    DSchedTransportSoftbusAdapter::GetInstance().OnDataReady(sessionId, dataBuffer, dataType);

    int32_t serviceType = 0;
    DSchedTransportSoftbusAdapter::GetInstance().RegisterListener(serviceType, listener);
    DSchedTransportSoftbusAdapter::GetInstance().UnregisterListener(serviceType, listener);

    bool ret = DSchedTransportSoftbusAdapter::GetInstance().GetSessionIdByDeviceId(PEERDEVICEID, sessionId);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DSchedTransportSoftbusAdapterTest GetSessionIdByDeviceId_001 end" << std::endl;
}

/**
 * @tc.name: GetSessionIdByDeviceId_002
 * @tc.desc: call GetSessionIdByDeviceId
 * @tc.type: FUNC
 */
HWTEST_F(DSchedTransportSoftbusAdapterTest, GetSessionIdByDeviceId_002, TestSize.Level3)
{
    DTEST_LOG << "DSchedTransportSoftbusAdapterTest GetSessionIdByDeviceId_002 begin" << std::endl;
    std::string peerDeviceId = "peerDeviceId";
    int32_t sessionId = 0;
    int32_t rightSession = 2;
    SessionInfo info = {0, "deviceid", "peerDeviceId", "sessionName", false};
    std::shared_ptr<DSchedSoftbusSession> ptr = std::make_shared<DSchedSoftbusSession>(info);
    DSchedTransportSoftbusAdapter::GetInstance().sessions_.clear();
    DSchedTransportSoftbusAdapter::GetInstance().sessions_[1] = nullptr;
    DSchedTransportSoftbusAdapter::GetInstance().sessions_[rightSession] = ptr;

    std::string peer = "peer";
    auto ret = DSchedTransportSoftbusAdapter::GetInstance().GetSessionIdByDeviceId(peer, sessionId);
    EXPECT_FALSE(ret);

    ret = DSchedTransportSoftbusAdapter::GetInstance().GetSessionIdByDeviceId(peerDeviceId, sessionId);
    EXPECT_TRUE(ret);
    EXPECT_EQ(sessionId, rightSession);
    DSchedTransportSoftbusAdapter::GetInstance().sessions_.clear();
    DTEST_LOG << "DSchedTransportSoftbusAdapterTest GetSessionIdByDeviceId_002 end" << std::endl;
}

/**
 * @tc.name: ReleaseChannel_001
 * @tc.desc: call ReleaseChannel
 * @tc.type: FUNC
 */
HWTEST_F(DSchedTransportSoftbusAdapterTest, ReleaseChannel_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedTransportSoftbusAdapterTest ReleaseChannel_001 begin" << std::endl;
    int32_t sessionId = 0;
    bool isSelfcalled = false;
    DSchedTransportSoftbusAdapter::GetInstance().OnShutdown(sessionId, isSelfcalled);
    DSchedTransportSoftbusAdapter::GetInstance().NotifyListenersSessionShutdown(sessionId, isSelfcalled);
    DSchedTransportSoftbusAdapter::GetInstance().OnBytes(sessionId, nullptr, 0);
    int32_t ret = DSchedTransportSoftbusAdapter::GetInstance().ReleaseChannel();
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedTransportSoftbusAdapterTest ReleaseChannel_001 end" << std::endl;
}

/**
 * @tc.name: SendBytesBySoftbus_001
 * @tc.desc: call SendBytesBySoftbus
 * @tc.type: FUNC
 */
HWTEST_F(DSchedTransportSoftbusAdapterTest, SendBytesBySoftbus_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedTransportSoftbusAdapterTest SendBytesBySoftbus_001 begin" << std::endl;
    int32_t sessionId = 0;
    int32_t ret = DSchedTransportSoftbusAdapter::GetInstance().SendBytesBySoftbus(sessionId, nullptr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedTransportSoftbusAdapterTest SendBytesBySoftbus_001 end" << std::endl;
}

/**
 * @tc.name: SendBytesBySoftbus_002
 * @tc.desc: call SendBytesBySoftbus
 * @tc.type: FUNC
 */
HWTEST_F(DSchedTransportSoftbusAdapterTest, SendBytesBySoftbus_002, TestSize.Level3)
{
    DTEST_LOG << "DSchedTransportSoftbusAdapterTest SendBytesBySoftbus_002 begin" << std::endl;
    int32_t sessionId = 0;
    auto dataBuffer = std::make_shared<DSchedDataBuffer>(SIZE_2);
    EXPECT_CALL(mockSoftbus, SendBytes(testing::_, testing::_, testing::_)).WillOnce(testing::Return(-1));
    auto ret = DSchedTransportSoftbusAdapter::GetInstance().SendBytesBySoftbus(sessionId, dataBuffer);
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DSchedTransportSoftbusAdapterTest SendBytesBySoftbus_002 end" << std::endl;
}


/**
 * @tc.name: AddNewPeerSession_001
 * @tc.desc: call AddNewPeerSession
 * @tc.type: FUNC
 */
HWTEST_F(DSchedTransportSoftbusAdapterTest, AddNewPeerSession_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedTransportSoftbusAdapterTest AddNewPeerSession_001 begin" << std::endl;
    std::string peerDeviceId = "peerDeviceId";
    int32_t sessionId = 0;
    EXPECT_CALL(mockSoftbus, Socket(testing::_)).WillOnce(testing::Return(-1));
    int32_t ret = DSchedTransportSoftbusAdapter::GetInstance().AddNewPeerSession(peerDeviceId, sessionId,
        SERVICE_TYPE_CONTINUE);
    EXPECT_EQ(ret, REMOTE_DEVICE_BIND_ABILITY_ERR);
    DTEST_LOG << "DSchedTransportSoftbusAdapterTest AddNewPeerSession_001 end" << std::endl;
}

/**
 * @tc.name: ConnectDevice_001
 * @tc.desc: call ConnectDevice
 * @tc.type: FUNC
 */
HWTEST_F(DSchedTransportSoftbusAdapterTest, ConnectDevice_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedTransportSoftbusAdapterTest ConnectDevice_001 begin" << std::endl;
    std::string peerDeviceId = "peerDeviceId";
    int32_t sessionId = 0;
    SessionInfo info = {0, "deviceid", "peerDeviceId", "sessionName", false};
    std::shared_ptr<DSchedSoftbusSession> ptr = std::make_shared<DSchedSoftbusSession>(info);
    DSchedTransportSoftbusAdapter::GetInstance().sessions_.clear();
    DSchedTransportSoftbusAdapter::GetInstance().sessions_[1] = nullptr;
    DSchedTransportSoftbusAdapter::GetInstance().sessions_[0] = ptr;
    int32_t ret = DSchedTransportSoftbusAdapter::GetInstance().ConnectDevice("peer", sessionId);

    ret = DSchedTransportSoftbusAdapter::GetInstance().ConnectDevice(peerDeviceId, sessionId);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedTransportSoftbusAdapterTest ConnectDevice_001 end" << std::endl;
}

/**
 * @tc.name: OnShutdown_001
 * @tc.desc: call OnShutdown
 * @tc.type: FUNC
 */
HWTEST_F(DSchedTransportSoftbusAdapterTest, OnShutdown_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedTransportSoftbusAdapterTest OnShutdown_001 begin" << std::endl;
    DSchedTransportSoftbusAdapter::GetInstance().sessions_.clear();
    int32_t sessionId = 0;
    DSchedTransportSoftbusAdapter::GetInstance().OnShutdown(sessionId, false);

    DSchedTransportSoftbusAdapter::GetInstance().sessions_[1] = nullptr;
    DSchedTransportSoftbusAdapter::GetInstance().OnShutdown(sessionId, false);
    EXPECT_FALSE(DSchedTransportSoftbusAdapter::GetInstance().sessions_.empty());

    DSchedTransportSoftbusAdapter::GetInstance().sessions_[0] = nullptr;
    DSchedTransportSoftbusAdapter::GetInstance().OnShutdown(sessionId, false);
    EXPECT_EQ(DSchedTransportSoftbusAdapter::GetInstance().sessions_.count(sessionId), 1);

    std::string peerDeviceId = "peerDeviceId";
    SessionInfo info = {0, "deviceid", "peerDeviceId", "sessionName", false};
    std::shared_ptr<DSchedSoftbusSession> ptr = std::make_shared<DSchedSoftbusSession>(info);
    DSchedTransportSoftbusAdapter::GetInstance().sessions_.clear();
    DSchedTransportSoftbusAdapter::GetInstance().sessions_[0] = ptr;
    DSchedTransportSoftbusAdapter::GetInstance().OnShutdown(sessionId, false);

    EXPECT_EQ(DSchedTransportSoftbusAdapter::GetInstance().sessions_.count(sessionId), 0);
    EXPECT_TRUE(DSchedTransportSoftbusAdapter::GetInstance().sessions_.empty());
    DTEST_LOG << "DSchedTransportSoftbusAdapterTest OnShutdown_001 end" << std::endl;
}

/**
 * @tc.name: SendData_001
 * @tc.desc: call SendData
 * @tc.type: FUNC
 */
HWTEST_F(DSchedTransportSoftbusAdapterTest, SendData_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedTransportSoftbusAdapterTest SendData_001 begin" << std::endl;
    DSchedTransportSoftbusAdapter::GetInstance().sessions_.clear();
    int32_t sessionId = 0;
    auto dataBuffer = std::make_shared<DSchedDataBuffer>(SIZE_2);
    int32_t dataType = 2;

    SoftbusMock mockSoftbus;
    int32_t socketId = 0;
    EXPECT_CALL(mockSoftbus, GetSessionOption(socketId, testing::_, testing::_, sizeof(uint32_t)))
        .WillOnce(testing::Return(-1));
    auto ret = DSchedTransportSoftbusAdapter::GetInstance().SendData(sessionId, dataType, dataBuffer);
    EXPECT_EQ(ret, INVALID_SESSION_ID);

    DSchedTransportSoftbusAdapter::GetInstance().sessions_[0] = nullptr;
    ret = DSchedTransportSoftbusAdapter::GetInstance().SendData(sessionId, dataType, dataBuffer);
    EXPECT_EQ(ret, INVALID_SESSION_ID);

    std::string peerDeviceId = "peerDeviceId";
    SessionInfo info = {0, "deviceid", "peerDeviceId", "sessionName", false};
    std::shared_ptr<DSchedSoftbusSession> ptr = std::make_shared<DSchedSoftbusSession>(info);
    DSchedTransportSoftbusAdapter::GetInstance().sessions_.clear();
    DSchedTransportSoftbusAdapter::GetInstance().sessions_[0] = ptr;
    ret = DSchedTransportSoftbusAdapter::GetInstance().SendData(sessionId, dataType, dataBuffer);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedTransportSoftbusAdapterTest SendData_001 end" << std::endl;
}

/**
 * @tc.name: OnBytes_001
 * @tc.desc: call OnBytes
 * @tc.type: FUNC
 */
HWTEST_F(DSchedTransportSoftbusAdapterTest, OnBytes_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedTransportSoftbusAdapterTest OnBytes_001 begin" << std::endl;
    int32_t sessionId = 0;
    uint32_t dataLen = 0;
    DSchedTransportSoftbusAdapter::GetInstance().sessions_.clear();
    EXPECT_NO_FATAL_FAILURE(DSchedTransportSoftbusAdapter::GetInstance().OnBytes(sessionId, nullptr, dataLen));

    dataLen = DSCHED_MAX_RECV_DATA_LEN + 1;
    EXPECT_NO_FATAL_FAILURE(DSchedTransportSoftbusAdapter::GetInstance().OnBytes(sessionId, nullptr, dataLen));

    dataLen = 5;
    EXPECT_NO_FATAL_FAILURE(DSchedTransportSoftbusAdapter::GetInstance().OnBytes(sessionId, nullptr, dataLen));
    char data[] = "test";
    EXPECT_NO_FATAL_FAILURE(DSchedTransportSoftbusAdapter::GetInstance().OnBytes(
        sessionId, data, dataLen));

    DSchedTransportSoftbusAdapter::GetInstance().sessions_[sessionId] = nullptr;
    EXPECT_NO_FATAL_FAILURE(DSchedTransportSoftbusAdapter::GetInstance().OnBytes(
        sessionId, data, dataLen));
    DSchedTransportSoftbusAdapter::GetInstance().sessions_.clear();
    DTEST_LOG << "DSchedTransportSoftbusAdapterTest OnBytes_001 end" << std::endl;
}

/**
 * @tc.name: DisconnectDevice_001
 * @tc.desc: call DisconnectDevice
 * @tc.type: FUNC
 */
HWTEST_F(DSchedTransportSoftbusAdapterTest, DisconnectDevice_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedTransportSoftbusAdapterTest DisconnectDevice_001 begin" << std::endl;
    std::string peerDeviceId = "peerDeviceId";
    int32_t sessionId = 0;
    int32_t rightSession = 2;
    SessionInfo info = {0, "deviceid", "peerDeviceId", "sessionName", false};
    std::shared_ptr<DSchedSoftbusSession> ptr = std::make_shared<DSchedSoftbusSession>(info);
    ptr->refCount_ = 2;
    DSchedTransportSoftbusAdapter::GetInstance().sessions_.clear();
    DSchedTransportSoftbusAdapter::GetInstance().sessions_[1] = nullptr;
    DSchedTransportSoftbusAdapter::GetInstance().sessions_[rightSession] = ptr;

    std::string peer = "peer";
    EXPECT_NO_FATAL_FAILURE(DSchedTransportSoftbusAdapter::GetInstance().DisconnectDevice(peer));
    EXPECT_NO_FATAL_FAILURE(DSchedTransportSoftbusAdapter::GetInstance().DisconnectDevice(peerDeviceId));
    EXPECT_EQ(DSchedTransportSoftbusAdapter::GetInstance().sessions_.count(rightSession), 1);

    EXPECT_NO_FATAL_FAILURE(DSchedTransportSoftbusAdapter::GetInstance().DisconnectDevice(peerDeviceId));
    EXPECT_EQ(DSchedTransportSoftbusAdapter::GetInstance().sessions_.count(rightSession), 0);
    DTEST_LOG << "DSchedTransportSoftbusAdapterTest DisconnectDevice_001 end" << std::endl;
}

/**
 * @tc.name: AddNewPeerSession_002
 * @tc.desc: call AddNewPeerSession
 * @tc.type: FUNC
 */
HWTEST_F(DSchedTransportSoftbusAdapterTest, AddNewPeerSession_002, TestSize.Level3)
{
    DTEST_LOG << "DSchedTransportSoftbusAdapterTest AddNewPeerSession_002 begin" << std::endl;
    int32_t sessionId = 0;
    DSchedServiceType type = SERVICE_TYPE_COLLAB;
    std::string peerDeviceId = "peerDeviceId";
    DtbschedmgrDeviceInfoStorage::GetInstance().remoteDevices_.clear();
    std::shared_ptr<DmsDeviceInfo> info = std::make_shared<DmsDeviceInfo>("", 0, "");
    info->osType_ = Constants::HO_OS_TYPE_EX;
    DtbschedmgrDeviceInfoStorage::GetInstance().remoteDevices_[peerDeviceId] = info;
    EXPECT_CALL(mockSoftbus, Socket(testing::_)).WillOnce(testing::Return(1));
    int32_t ret = DSchedTransportSoftbusAdapter::GetInstance().AddNewPeerSession(peerDeviceId, sessionId,
        SERVICE_TYPE_CONTINUE);
    EXPECT_EQ(ret, DMS_PERMISSION_DENIED);

    peerDeviceId = "peerDeviceId1";
    std::shared_ptr<DmsDeviceInfo> info1 = std::make_shared<DmsDeviceInfo>("", 0, "");
    DtbschedmgrDeviceInfoStorage::GetInstance().remoteDevices_[peerDeviceId] = info1;
    EXPECT_CALL(mockSoftbus, Socket(testing::_)).WillOnce(testing::Return(1));
    ret = DSchedTransportSoftbusAdapter::GetInstance().AddNewPeerSession(peerDeviceId, sessionId,
        SERVICE_TYPE_CONTINUE);
    EXPECT_NE(ret, DMS_PERMISSION_DENIED);
    DTEST_LOG << "DSchedTransportSoftbusAdapterTest AddNewPeerSession_002 end" << std::endl;
}

/**
 * @tc.name: OnBind_001
 * @tc.desc: call OnBind
 * @tc.type: FUNC
 */
HWTEST_F(DSchedTransportSoftbusAdapterTest, OnBind_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedTransportSoftbusAdapterTest OnBind_001 begin" << std::endl;
    int32_t sessionId = 0;
    std::string peerDeviceId = "peerDeviceId";
    DtbschedmgrDeviceInfoStorage::GetInstance().remoteDevices_.clear();
    std::shared_ptr<DmsDeviceInfo> info = std::make_shared<DmsDeviceInfo>("", 0, "");
    info->osType_ = Constants::HO_OS_TYPE_EX;
    DtbschedmgrDeviceInfoStorage::GetInstance().remoteDevices_[peerDeviceId] = info;
    EXPECT_NO_FATAL_FAILURE(DSchedTransportSoftbusAdapter::GetInstance().OnBind(sessionId, peerDeviceId));

    peerDeviceId = "peerDeviceId1";
    std::shared_ptr<DmsDeviceInfo> info1 = std::make_shared<DmsDeviceInfo>("", 0, "");
    DtbschedmgrDeviceInfoStorage::GetInstance().remoteDevices_[peerDeviceId] = info1;
    EXPECT_NO_FATAL_FAILURE(DSchedTransportSoftbusAdapter::GetInstance().OnBind(sessionId, peerDeviceId));
    DTEST_LOG << "DSchedTransportSoftbusAdapterTest OnBind_001 end" << std::endl;
}
}
}