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
#include "data_sender_receiver_test.h"
#include "dtbcollabmgr_log.h"
#include "session_data_header.h"

namespace OHOS {
namespace DistributedCollab {
namespace {
    static const std::string TAG = "DSchedCollabDataSenderReceiverTest";
    using namespace testing;
    using namespace testing::ext;
}
void DataSenderReceiverTest::SetUpTestCase()
{
    HILOGI("DataSenderReceiverTest::SetUpTestCase");
}

void DataSenderReceiverTest::TearDownTestCase()
{
    HILOGI("DataSenderReceiverTest::TearDownTestCase");
}

void DataSenderReceiverTest::SetUp()
{
    HILOGI("DataSenderReceiverTest::SetUp");
}

void DataSenderReceiverTest::TearDown()
{
    HILOGI("DataSenderReceiverTest::TearDown");
}

/**
 * @tc.name: SendStreamData_Success
 * @tc.desc: Test for SendStreamData when SendStream succeeds
 * @tc.type: FUNC
 */
HWTEST_F(DataSenderReceiverTest, SendStreamData_Success, TestSize.Level1)
{
    EXPECT_CALL(mockSoftbus, SendStream(socketId, testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(ERR_OK)); // 假设 SendStream 返回 0，表示成功

    int32_t result = dataSenderReceiver.SendStreamData(streamData);

    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: SendStreamData_Failure
 * @tc.desc: Test for SendStreamData when SendStream fails
 * @tc.type: FUNC
 */
HWTEST_F(DataSenderReceiverTest, SendStreamData_Failure, TestSize.Level1)
{
    EXPECT_CALL(mockSoftbus, SendStream(socketId, testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(-1)); // 假设 SendStream 返回 -1，表示失败

    int32_t result = dataSenderReceiver.SendStreamData(streamData);

    EXPECT_EQ(result, -1);
}

/**
 * @tc.name: SendStreamData_ParameterCheck
 * @tc.desc: Test for SendStreamData parameter check when calling SendStream
 * @tc.type: FUNC
 */
HWTEST_F(DataSenderReceiverTest, SendStreamData_ParameterCheck, TestSize.Level1)
{
    EXPECT_CALL(mockSoftbus, SendStream(socketId, testing::_, testing::_, testing::_))
        .WillOnce(testing::Invoke([](int32_t socket, const StreamData* data, const StreamData* ext, const StreamFrameInfo* param) -> int32_t {
            if (data == nullptr || ext == nullptr || param == nullptr) {
                return -1;
            }
            return ERR_OK;
        }));

    int32_t result = dataSenderReceiver.SendStreamData(streamData);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: SendMessageData_Success
 * @tc.desc: Test for SendMessageData when SendMessage succeeds
 * @tc.type: FUNC
 */
HWTEST_F(DataSenderReceiverTest, SendMessageData_Success, TestSize.Level1)
{
    EXPECT_CALL(mockSoftbus, SendMessage(socketId, testing::_, testing::_))
        .WillOnce(testing::Return(ERR_OK));

    int32_t result = dataSenderReceiver.SendMessageData(buffer);

    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: SendMessageData_Failure
 * @tc.desc: Test for SendMessageData when SendMessage fails
 * @tc.type: FUNC
 */
HWTEST_F(DataSenderReceiverTest, SendMessageData_Failure, TestSize.Level1)
{
    EXPECT_CALL(mockSoftbus, SendMessage(socketId, testing::_, testing::_))
        .WillOnce(testing::Return(-1));
    int32_t result = dataSenderReceiver.SendMessageData(buffer);
    EXPECT_EQ(result, -1);
}

/**
 * @tc.name: SendMessageData_ParameterCheck
 * @tc.desc: Test for SendMessageData parameter check when calling SendMessage
 * @tc.type: FUNC
 */
HWTEST_F(DataSenderReceiverTest, SendMessageData_ParameterCheck, TestSize.Level1)
{
    std::shared_ptr<AVTransDataBuffer> sendData = std::make_shared<AVTransDataBuffer>(4 * 1024 + 1);
    int32_t result = dataSenderReceiver.SendMessageData(sendData);
    EXPECT_EQ(result, DATA_SIZE_EXCEED_LIMIT);
}

/**
 * @tc.name: SendBytesData_Success
 * @tc.desc: Test for SendBytesData when both SendBytes and GetSessionOption succeed
 * @tc.type: FUNC
 */
HWTEST_F(DataSenderReceiverTest, SendBytesData_Success, TestSize.Level1)
{
    EXPECT_CALL(mockSoftbus, GetSessionOption(socketId, testing::_, testing::_, sizeof(uint32_t)))
        .WillOnce(testing::Invoke([&](int sessionId, SessionOption option, void* optionValue, uint32_t valueSize) {
            *reinterpret_cast<uint32_t*>(optionValue) = 4 * 1024 * 1024;
            return ERR_OK;
        })); // 假设成功

    EXPECT_CALL(mockSoftbus, SendBytes(socketId, testing::_, buffer->Size() + SessionDataHeader::HEADER_LEN))
        .WillOnce(testing::Return(ERR_OK));

    int32_t result = dataSenderReceiver.SendBytesData(buffer);

    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: SendBytesData_Failure_GetSessionOption
 * @tc.desc: Test for SendBytesData when GetSessionOption fails
 * @tc.type: FUNC
 */
HWTEST_F(DataSenderReceiverTest, SendBytesData_Failure_GetSessionOption, TestSize.Level1)
{
    EXPECT_CALL(mockSoftbus, GetSessionOption(socketId, testing::_, testing::_, sizeof(uint32_t)))
        .WillOnce(testing::Return(-1)); // 假设失败

    EXPECT_CALL(mockSoftbus, SendBytes(testing::_, testing::_, testing::_)).Times(0);

    int32_t result = dataSenderReceiver.SendBytesData(buffer);

    EXPECT_EQ(result, GET_SESSION_OPTION_FAILED);
}

/**
 * @tc.name: SendBytesData_Failure_SendBytes
 * @tc.desc: Test for SendBytesData when SendBytes fails
 * @tc.type: FUNC
 */
HWTEST_F(DataSenderReceiverTest, SendBytesData_Failure_SendBytes, TestSize.Level1)
{
    EXPECT_CALL(mockSoftbus, GetSessionOption(socketId, testing::_, testing::_, sizeof(uint32_t)))
        .WillOnce(testing::Invoke([&](int sessionId, SessionOption option, void* optionValue, uint32_t valueSize) {
            *reinterpret_cast<uint32_t*>(optionValue) = 4 * 1024 * 1024;
            return ERR_OK;
        })); // 假设成功

    EXPECT_CALL(mockSoftbus, SendBytes(socketId, testing::_, buffer->Size() + SessionDataHeader::HEADER_LEN))
        .WillOnce(testing::Return(-1));

    int32_t result = dataSenderReceiver.SendBytesData(buffer);

    EXPECT_EQ(result, SEND_DATA_BY_SOFTBUS_FAILED);
}

/**
 * @tc.name: SendBytesData_ParameterCheck
 * @tc.desc: Test for SendBytesData parameter check when calling SendBytes
 * @tc.type: FUNC
 */
HWTEST_F(DataSenderReceiverTest, SendBytesData_ParameterCheck, TestSize.Level1)
{
    EXPECT_CALL(mockSoftbus, GetSessionOption(socketId, testing::_, testing::_, sizeof(uint32_t)))
        .WillOnce(testing::Invoke([&](int sessionId, SessionOption option, void* optionValue, uint32_t valueSize) {
            *reinterpret_cast<uint32_t*>(optionValue) = 4 * 1024 * 1024;
            return ERR_OK;
        }));

    EXPECT_CALL(mockSoftbus, SendBytes(socketId, testing::_, buffer->Size() + SessionDataHeader::HEADER_LEN))
        .WillOnce(testing::Invoke([](int32_t socket, const void* data, uint32_t len) -> int32_t {
            const uint8_t* header = static_cast<const uint8_t*>(data);
            auto headerPara = SessionDataHeader::Deserialize(header, len);
            if (headerPara->fragFlag_ != FRAG_TYPE::FRAG_START_END) {
                return -1;
            }
            return ERR_OK;
        }));

    int32_t result = dataSenderReceiver.SendBytesData(buffer);

    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: SendBytesData_MultiSendParameterCheck
 * @tc.desc: Test for SendBytesData parameter check when calling SendBytes
 * @tc.type: FUNC
 */
HWTEST_F(DataSenderReceiverTest, SendBytesData_MultiSendParameterCheck, TestSize.Level1)
{
    EXPECT_CALL(mockSoftbus, GetSessionOption(socketId, testing::_, testing::_, sizeof(uint32_t)))
        .WillRepeatedly(testing::Invoke([&](int sessionId, SessionOption option, void* optionValue, uint32_t valueSize) {
            *reinterpret_cast<uint32_t*>(optionValue) = 100;
            return ERR_OK;
        }));

    EXPECT_CALL(mockSoftbus, SendBytes(socketId, testing::_, testing::_))
        .WillOnce(testing::Invoke([](int32_t socket, const void* data, uint32_t len) -> int32_t {
            const uint8_t* header = static_cast<const uint8_t*>(data);
            auto headerPara = SessionDataHeader::Deserialize(header, len);
            if (headerPara->fragFlag_ != FRAG_TYPE::FRAG_START && headerPara->subSeq_ == 0) {
                return -1;
            }
            return ERR_OK;
        }))
        .WillOnce(testing::Invoke([](int32_t socket, const void* data, uint32_t len) -> int32_t {
            const uint8_t* header = static_cast<const uint8_t*>(data);
            auto headerPara = SessionDataHeader::Deserialize(header, len);
            if (headerPara->fragFlag_ != FRAG_TYPE::FRAG_MID && headerPara->subSeq_ == 1) {
                return -1;
            }
            return ERR_OK;
        }))
        .WillOnce(testing::Invoke([](int32_t socket, const void* data, uint32_t len) -> int32_t {
            const uint8_t* header = static_cast<const uint8_t*>(data);
            auto headerPara = SessionDataHeader::Deserialize(header, len);
            if (headerPara->fragFlag_ != FRAG_TYPE::FRAG_END && headerPara->subSeq_ == 2) {
                return -1;
            }
            return ERR_OK;
        }));

    std::shared_ptr<AVTransDataBuffer> sendData = std::make_shared<AVTransDataBuffer>((100 - SessionDataHeader::HEADER_LEN) * 3);
    int32_t result = dataSenderReceiver.SendBytesData(sendData);

    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: PackRecvPacketData_Success
 * @tc.desc: Test for PackRecvPacketData when it successfully processes the serialized header and data and decodes correctly
 * @tc.type: FUNC
 */
HWTEST_F(DataSenderReceiverTest, PackRecvPacketData_Success, TestSize.Level1)
{
    uint8_t data[100 - SessionDataHeader::HEADER_LEN];
    uint32_t dataLen = sizeof(data);
    SessionDataHeader headerPara(1, FRAG_TYPE::FRAG_START_END, 0, 0, 100, 100, 100 - SessionDataHeader::HEADER_LEN, 0);
    auto serializedHeader = headerPara.Serialize();
    
    std::vector<uint8_t> combinedData;
    combinedData.insert(combinedData.end(), serializedHeader->Data(), serializedHeader->Data() + serializedHeader->Size());
    combinedData.insert(combinedData.end(), data, data + dataLen);

    int32_t result = dataSenderReceiver.PackRecvPacketData(combinedData.data(), combinedData.size());

    EXPECT_EQ(result, ERR_OK);
    auto decodedData = dataSenderReceiver.GetPacketedData();
    ASSERT_NE(decodedData, nullptr);
    EXPECT_EQ(decodedData->Size(), dataLen);
}

/**
 * @tc.name: PackRecvPacketData_MultiRecvSuccess
 * @tc.desc: Test for PackRecvPacketData when it successfully processes the serialized header and data and decodes correctly
 * @tc.type: FUNC
 */
HWTEST_F(DataSenderReceiverTest, PackRecvPacketData_MultiRecvSuccess, TestSize.Level1)
{
    uint8_t data[100 - SessionDataHeader::HEADER_LEN];
    uint32_t dataLen = sizeof(data);
    SessionDataHeader headerPara1(1, FRAG_TYPE::FRAG_START, 0, 0, 3 * (100 - SessionDataHeader::HEADER_LEN), 100, 100 - SessionDataHeader::HEADER_LEN, 0);
    auto serializedHeader1 = headerPara1.Serialize();
    std::vector<uint8_t> combinedData1;
    combinedData1.insert(combinedData1.end(), serializedHeader1->Data(), serializedHeader1->Data() + serializedHeader1->Size());
    combinedData1.insert(combinedData1.end(), data, data + dataLen);

    SessionDataHeader headerPara2(1, FRAG_TYPE::FRAG_MID, 0, 0, 3 * (100 - SessionDataHeader::HEADER_LEN), 100, 100 - SessionDataHeader::HEADER_LEN, 1);
    auto serializedHeader2 = headerPara2.Serialize();
    std::vector<uint8_t> combinedData2;
    combinedData2.insert(combinedData2.end(), serializedHeader2->Data(), serializedHeader2->Data() + serializedHeader2->Size());
    combinedData2.insert(combinedData2.end(), data, data + dataLen);

    SessionDataHeader headerPara3(1, FRAG_TYPE::FRAG_END, 0, 0, 3 * (100 - SessionDataHeader::HEADER_LEN), 100, 100 - SessionDataHeader::HEADER_LEN, 2);
    auto serializedHeader3 = headerPara3.Serialize();
    std::vector<uint8_t> combinedData3;
    combinedData3.insert(combinedData3.end(), serializedHeader3->Data(), serializedHeader3->Data() + serializedHeader3->Size());
    combinedData3.insert(combinedData3.end(), data, data + dataLen);

    int32_t result1 = dataSenderReceiver.PackRecvPacketData(combinedData1.data(), combinedData1.size());
    int32_t result2 = dataSenderReceiver.PackRecvPacketData(combinedData2.data(), combinedData2.size());
    int32_t result3 = dataSenderReceiver.PackRecvPacketData(combinedData3.data(), combinedData3.size());

    EXPECT_EQ(result1, ERR_OK);
    EXPECT_EQ(result2, ERR_OK);
    EXPECT_EQ(result3, ERR_OK);

    auto decodedData = dataSenderReceiver.GetPacketedData();
    ASSERT_NE(decodedData, nullptr);
    EXPECT_EQ(decodedData->Size(), dataLen * 3);
}

/**
 * @tc.name: PackRecvPacketData_WhenInvalidHeader
 * @tc.desc: Test for PackRecvPacketData when it recv invalid header
 * @tc.type: FUNC
 */
HWTEST_F(DataSenderReceiverTest, PackRecvPacketData_WhenInvalidHeader, TestSize.Level1)
{
    SessionDataHeader headerPara(1, FRAG_TYPE::FRAG_START_END, 0, 0, 100, 200, 100 - SessionDataHeader::HEADER_LEN, 0);
    auto serializedHeader = headerPara.Serialize();

    uint8_t data[100 - SessionDataHeader::HEADER_LEN];
    uint32_t dataLen = sizeof(data);

    std::vector<uint8_t> combinedData;
    combinedData.insert(combinedData.end(), serializedHeader->Data(), serializedHeader->Data() + serializedHeader->Size());
    combinedData.insert(combinedData.end(), data, data + dataLen);

    int32_t result = dataSenderReceiver.PackRecvPacketData(combinedData.data(), combinedData.size());

    EXPECT_EQ(result, WRITE_SESSION_HEADER_FAILED);
}

/**
 * @tc.name: PackRecvPacketData_WhenHeaderParamSubSeqInvalid
 * @tc.desc: Test for PackRecvPacketData when it recv invalid header
 * @tc.type: FUNC
 */
HWTEST_F(DataSenderReceiverTest, PackRecvPacketData_WhenHeaderParamSubSeqInvalid, TestSize.Level1)
{
    SessionDataHeader headerPara(1, FRAG_TYPE::FRAG_START_END, 0, 0, 100, 100, 100 - SessionDataHeader::HEADER_LEN, 10);
    auto serializedHeader = headerPara.Serialize();

    uint8_t data[100 - SessionDataHeader::HEADER_LEN];
    uint32_t dataLen = sizeof(data);

    std::vector<uint8_t> combinedData;
    combinedData.insert(combinedData.end(), serializedHeader->Data(), serializedHeader->Data() + serializedHeader->Size());
    combinedData.insert(combinedData.end(), data, data + dataLen);

    int32_t result = dataSenderReceiver.PackRecvPacketData(combinedData.data(), combinedData.size());

    EXPECT_EQ(result, INVALID_SESSION_HEADER_SUB_SEQ);
}

/**
 * @tc.name: PackRecvPacketData_WhenHeaderParamSeqNumInvalid
 * @tc.desc: Test for PackRecvPacketData when it recv invalid header
 * @tc.type: FUNC
 */
HWTEST_F(DataSenderReceiverTest, PackRecvPacketData_WhenHeaderParamSeqNumInvalid, TestSize.Level1)
{
    SessionDataHeader headerPara(1, FRAG_TYPE::FRAG_START_END, 0, 1, 100, 100, 100 - SessionDataHeader::HEADER_LEN, 0);
    auto serializedHeader = headerPara.Serialize();

    uint8_t data[100 - SessionDataHeader::HEADER_LEN];
    uint32_t dataLen = sizeof(data);

    std::vector<uint8_t> combinedData;
    combinedData.insert(combinedData.end(), serializedHeader->Data(), serializedHeader->Data() + serializedHeader->Size());
    combinedData.insert(combinedData.end(), data, data + dataLen);

    int32_t result = dataSenderReceiver.PackRecvPacketData(combinedData.data(), combinedData.size());

    EXPECT_EQ(result, INVALID_SESSION_HEADER_SEQ_NUM);
}

/**
 * @tc.name: PackRecvPacketData_RecvInvalidMidData
 * @tc.desc: Test for PackRecvPacketData when it recv mid data
 * @tc.type: FUNC
 */
HWTEST_F(DataSenderReceiverTest, PackRecvPacketData_RecvInvalidMidData, TestSize.Level1)
{
    uint8_t data[100 - SessionDataHeader::HEADER_LEN];
    uint32_t dataLen = sizeof(data);

    SessionDataHeader headerPara2(1, FRAG_TYPE::FRAG_MID, 0, 0, 100, 100, 100 - SessionDataHeader::HEADER_LEN, 1);
    auto serializedHeader2 = headerPara2.Serialize();
    std::vector<uint8_t> combinedData2;
    combinedData2.insert(combinedData2.end(), serializedHeader2->Data(), serializedHeader2->Data() + serializedHeader2->Size());
    combinedData2.insert(combinedData2.end(), data, data + dataLen);

    int32_t result2 = dataSenderReceiver.PackRecvPacketData(combinedData2.data(), combinedData2.size());

    EXPECT_EQ(result2, FLAG_TYPE_NOT_MATCH_BUFFER_STATE);

    auto decodedData = dataSenderReceiver.GetPacketedData();
    EXPECT_TRUE(decodedData == nullptr);
}

/**
 * @tc.name: PackRecvPacketData_RecvInvalidEndData
 * @tc.desc: Test for PackRecvPacketData when it recv end data
 * @tc.type: FUNC
 */
HWTEST_F(DataSenderReceiverTest, PackRecvPacketData_RecvInvalidEndData, TestSize.Level1)
{
    uint8_t data[100 - SessionDataHeader::HEADER_LEN];
    uint32_t dataLen = sizeof(data);

    SessionDataHeader headerPara3(1, FRAG_TYPE::FRAG_END, 0, 0, 100, 100, 100 - SessionDataHeader::HEADER_LEN, 0);
    auto serializedHeader3 = headerPara3.Serialize();
    std::vector<uint8_t> combinedData3;
    combinedData3.insert(combinedData3.end(), serializedHeader3->Data(), serializedHeader3->Data() + serializedHeader3->Size());
    combinedData3.insert(combinedData3.end(), data, data + dataLen);

    int32_t result3 = dataSenderReceiver.PackRecvPacketData(combinedData3.data(), combinedData3.size());
    EXPECT_EQ(result3, FLAG_TYPE_NOT_MATCH_BUFFER_STATE);

    auto decodedData = dataSenderReceiver.GetPacketedData();
    EXPECT_TRUE(decodedData == nullptr);
}

/**
 * @tc.name: PackRecvPacketData_MultiRecvWithDiffTotalLen_001
 * @tc.desc: Test for PackRecvPacketData when it recv invalid multi data
 * @tc.type: FUNC
 */
HWTEST_F(DataSenderReceiverTest, PackRecvPacketData_MultiRecvWithDiffTotalLen_001, TestSize.Level1)
{
    uint8_t data[100 - SessionDataHeader::HEADER_LEN];
    uint32_t dataLen = sizeof(data);
    SessionDataHeader headerPara1(1, FRAG_TYPE::FRAG_START, 0, 0, 3 * (100 - SessionDataHeader::HEADER_LEN), 100, 100 - SessionDataHeader::HEADER_LEN, 0);
    auto serializedHeader1 = headerPara1.Serialize();
    std::vector<uint8_t> combinedData1;
    combinedData1.insert(combinedData1.end(), serializedHeader1->Data(), serializedHeader1->Data() + serializedHeader1->Size());
    combinedData1.insert(combinedData1.end(), data, data + dataLen);

    SessionDataHeader headerPara2(1, FRAG_TYPE::FRAG_MID, 0, 0, 100, 100, 100 - SessionDataHeader::HEADER_LEN, 1);
    auto serializedHeader2 = headerPara2.Serialize();
    std::vector<uint8_t> combinedData2;
    combinedData2.insert(combinedData2.end(), serializedHeader2->Data(), serializedHeader2->Data() + serializedHeader2->Size());
    combinedData2.insert(combinedData2.end(), data, data + dataLen);

    int32_t result1 = dataSenderReceiver.PackRecvPacketData(combinedData1.data(), combinedData1.size());
    int32_t result2 = dataSenderReceiver.PackRecvPacketData(combinedData2.data(), combinedData2.size());

    EXPECT_EQ(result1, ERR_OK);
    EXPECT_EQ(result2, INVALID_SESSION_HEADER_TOTAL_LEN);

    auto decodedData = dataSenderReceiver.GetPacketedData();
    EXPECT_TRUE(decodedData == nullptr);
}

/**
 * @tc.name: PackRecvPacketData_MultiRecvWithDiffTotalLen_002
 * @tc.desc: Test for PackRecvPacketData when it recv invalid multi data
 * @tc.type: FUNC
 */
HWTEST_F(DataSenderReceiverTest, PackRecvPacketData_MultiRecvWithDiffTotalLen_002, TestSize.Level1)
{
    uint8_t data[100 - SessionDataHeader::HEADER_LEN];
    uint32_t dataLen = sizeof(data);
    SessionDataHeader headerPara1(1, FRAG_TYPE::FRAG_START, 0, 0, 3 * (100 - SessionDataHeader::HEADER_LEN), 100, 100 - SessionDataHeader::HEADER_LEN, 0);
    auto serializedHeader1 = headerPara1.Serialize();
    std::vector<uint8_t> combinedData1;
    combinedData1.insert(combinedData1.end(), serializedHeader1->Data(), serializedHeader1->Data() + serializedHeader1->Size());
    combinedData1.insert(combinedData1.end(), data, data + dataLen);

    SessionDataHeader headerPara3(1, FRAG_TYPE::FRAG_END, 0, 0, 100, 100, 100 - SessionDataHeader::HEADER_LEN, 1);
    auto serializedHeader3 = headerPara3.Serialize();
    std::vector<uint8_t> combinedData3;
    combinedData3.insert(combinedData3.end(), serializedHeader3->Data(), serializedHeader3->Data() + serializedHeader3->Size());
    combinedData3.insert(combinedData3.end(), data, data + dataLen);

    int32_t result1 = dataSenderReceiver.PackRecvPacketData(combinedData1.data(), combinedData1.size());
    int32_t result3 = dataSenderReceiver.PackRecvPacketData(combinedData3.data(), combinedData3.size());

    EXPECT_EQ(result1, ERR_OK);
    EXPECT_EQ(result3, INVALID_SESSION_HEADER_TOTAL_LEN);

    auto decodedData = dataSenderReceiver.GetPacketedData();
    EXPECT_TRUE(decodedData == nullptr);
}

} // namespace  DistributedCollab
} // namespace OHOS
