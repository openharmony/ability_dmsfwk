/*
* Copyright (c) 2024 Huawei Device Co., Ltd.
* Licensed under the Apache License, Version NUM_2.0 (the "License");
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
#include "session_data_header_test.h"
#include "dtbcollabmgr_log.h"

namespace OHOS {
namespace DistributedCollab {
namespace {
    static const std::string TAG = "DSchedCollabSessionDataHeaderTest";
    using namespace testing;
    using namespace testing::ext;
    static constexpr int32_t NUM_2 = 2;
    static constexpr int32_t NUM_3 = 3;
    static constexpr int32_t NUM_5 = 5;
    static constexpr int32_t NUM_10 = 10;
    static constexpr int32_t NUM_64 = 64;
    static constexpr int32_t NUM_100 = 100;
    static constexpr int32_t NUM_128 = 128;
    static constexpr int32_t NUM_500 = 500;
    static constexpr int32_t NUM_600 = 5;
}

void SessionDataHeaderTest::SetUpTestCase()
{
    HILOGI("SessionDataHeaderTest::SetUpTestCase");
}

void SessionDataHeaderTest::TearDownTestCase()
{
    HILOGI("SessionDataHeaderTest::TearDownTestCase");
}

void SessionDataHeaderTest::SetUp()
{
    HILOGI("SessionDataHeaderTest::SetUp");
    version = 1;
    fragFlag = FRAG_TYPE::FRAG_START;
    dataType = NUM_2;
    seqNum = NUM_100;
    totalLen = NUM_500;
    packetLen = NUM_128;
    payloadLen = NUM_64;
    subSeq = 0;

    header = std::make_unique<SessionDataHeader>(
        version, fragFlag,
        dataType, seqNum, totalLen,
        packetLen, payloadLen, subSeq);
}

void SessionDataHeaderTest::TearDown()
{
    HILOGI("SessionDataHeaderTest::TearDown");
    header.reset();
}

/**
 * @tc.name: SerializeAndDeserialize_001
 * @tc.desc: Test serialization and deserialization of SessionDataHeader
 * @tc.type: FUNC
 * @tc.level: TestSize.Level1
 */
HWTEST_F(SessionDataHeaderTest, SerializeAndDeserialize_001, TestSize.Level1)
{
    auto serializedBuffer = header->Serialize();
    ASSERT_NE(serializedBuffer, nullptr);

    auto deserializedHeader = SessionDataHeader::Deserialize(
            serializedBuffer->Data(), serializedBuffer->Size());
    ASSERT_TRUE(deserializedHeader.has_value());

    EXPECT_EQ(deserializedHeader->version_, version);
    EXPECT_EQ(deserializedHeader->fragFlag_, fragFlag);
    EXPECT_EQ(deserializedHeader->dataType_, dataType);
    EXPECT_EQ(deserializedHeader->seqNum_, seqNum);
    EXPECT_EQ(deserializedHeader->totalLen_, totalLen);
    EXPECT_EQ(deserializedHeader->packetLen_, packetLen);
    EXPECT_EQ(deserializedHeader->payloadLen_, payloadLen);
    EXPECT_EQ(deserializedHeader->subSeq_, subSeq);
}

/**
 * @tc.name: DeserializeInvalidData_whenNullptr
 * @tc.desc: Test deserialization with invalid data
 * @tc.type: FUNC
 * @tc.level: TestSize.Level1
 */
HWTEST_F(SessionDataHeaderTest, DeserializeInvalidData_whenNullptr, TestSize.Level1)
{
    auto deserializedHeader = SessionDataHeader::Deserialize(nullptr, 0);
    ASSERT_FALSE(deserializedHeader.has_value());
}

/**
 * @tc.name: DeserializeInvalidData_whenHeaderLenTooSmall
 * @tc.desc: Test deserialization with invalid data
 * @tc.type: FUNC
 * @tc.level: TestSize.Level1
 */
HWTEST_F(SessionDataHeaderTest, DeserializeInvalidData_whenHeaderLenTooSmall, TestSize.Level1)
{
    const uint8_t* header = new uint8_t[1] { 1 };
    auto deserializedHeader = SessionDataHeader::Deserialize(header, 0);
    ASSERT_FALSE(deserializedHeader.has_value());
}

/**
 * @tc.name: Deserialize_InsufficientReservedBytes
 * @tc.desc: Test deserialization when reserved bytes are insufficient
 * @tc.type: FUNC
 * @tc.level: TestSize.Level1
 */
HWTEST_F(SessionDataHeaderTest, Deserialize_InsufficientReservedBytes, TestSize.Level1)
{
    uint8_t buffer[SessionDataHeader::HEADER_LEN] = { 0 };
    uint16_t typeInt = static_cast<uint16_t>(TLV_TYPE::TLV_TYPE_VERSION);
    buffer[0] = typeInt >> 8;
    buffer[1] = typeInt & 0xFF;
    buffer[2] = 0;
    buffer[3] = SessionDataHeader::HEADER_LEN + NUM_10; // exceed max size

    auto result = SessionDataHeader::Deserialize(buffer, sizeof(buffer));
    ASSERT_FALSE(result.has_value());
}

/**
 * @tc.name: Deserialize_InvalidType
 * @tc.desc: Test deserialization when an invalid TLV type is provided
 * @tc.type: FUNC
 * @tc.level: TestSize.Level1
 */
HWTEST_F(SessionDataHeaderTest, Deserialize_InvalidType, TestSize.Level1)
{
    uint8_t buffer[SessionDataHeader::HEADER_LEN] = { 0 };
    uint16_t invalidType = 9999;
    buffer[0] = invalidType >> 8;
    buffer[1] = invalidType & 0xFF;
    buffer[2] = 0;
    buffer[3] = sizeof(uint32_t);

    auto result = SessionDataHeader::Deserialize(buffer, sizeof(buffer));
    ASSERT_FALSE(result.has_value());
}

/**
 * @tc.name: Deserialize_ReadVersionFailure
 * @tc.desc: Test deserialization where ReadVersionFromBuffer fails
 * @tc.type: FUNC
 * @tc.level: TestSize.Level1
 */
HWTEST_F(SessionDataHeaderTest, Deserialize_ReadVersionFailure, TestSize.Level1)
{
    uint8_t buffer[SessionDataHeader::HEADER_LEN] = { 0 };
    uint16_t versionType = static_cast<uint16_t>(TLV_TYPE::TLV_TYPE_VERSION);
    buffer[0] = versionType >> 8;
    buffer[1] = versionType & 0xFF;
    buffer[2] = 0;
    buffer[3] = NUM_3;

    auto result = SessionDataHeader::Deserialize(buffer, sizeof(buffer));
    ASSERT_FALSE(result.has_value());
}

/**
 * @tc.name: Deserialize_ReadFragFlagFailure
 * @tc.desc: Test deserialization where ReadFragFlagFromBuffer fails
 * @tc.type: FUNC
 * @tc.level: TestSize.Level1
 */
HWTEST_F(SessionDataHeaderTest, Deserialize_ReadFragFlagFailure, TestSize.Level1)
{
    uint8_t buffer[SessionDataHeader::HEADER_LEN] = { 0 };
    uint16_t fragFlagType = static_cast<uint16_t>(TLV_TYPE::TLV_TYPE_FRAG_FLAG);
    buffer[0] = fragFlagType >> 8;
    buffer[1] = fragFlagType & 0xFF;
    buffer[2] = 0;
    buffer[3] = NUM_3;

    auto result = SessionDataHeader::Deserialize(buffer, sizeof(buffer));
    ASSERT_FALSE(result.has_value());
}

/**
 * @tc.name: Deserialize_ReadDataTypeFailure
 * @tc.desc: Test deserialization where ReadDataTypeFromBuffer fails
 * @tc.type: FUNC
 * @tc.level: TestSize.Level1
 */
HWTEST_F(SessionDataHeaderTest, Deserialize_ReadDataTypeFailure, TestSize.Level1)
{
    uint8_t buffer[SessionDataHeader::HEADER_LEN] = { 0 };
    uint16_t dataType = static_cast<uint16_t>(TLV_TYPE::TLV_TYPE_DATA_TYPE);
    

    buffer[0] = dataType >> 8;
    buffer[1] = dataType & 0xFF;
    buffer[2] = 0;
    buffer[3] = NUM_3;

    auto result = SessionDataHeader::Deserialize(buffer, sizeof(buffer));
    ASSERT_FALSE(result.has_value());
}

/**
 * @tc.name: Deserialize_ReadPayloadLenFailure
 * @tc.desc: Test deserialization where ReadPayloadLenFromBuffer fails
 * @tc.type: FUNC
 * @tc.level: TestSize.Level1
 */
HWTEST_F(SessionDataHeaderTest, Deserialize_ReadPayloadLenFailure, TestSize.Level1)
{
    uint8_t buffer[SessionDataHeader::HEADER_LEN] = { 0 };
    uint16_t payloadLenType = static_cast<uint16_t>(TLV_TYPE::TLV_TYPE_PAYLOAD_LEN);
    buffer[0] = payloadLenType >> 8;
    buffer[1] = payloadLenType & 0xFF;
    buffer[2] = 0;
    buffer[3] = NUM_5;

    auto result = SessionDataHeader::Deserialize(buffer, sizeof(buffer));
    ASSERT_FALSE(result.has_value());
}

/**
 * @tc.name: Deserialize_ReadPacketLenFailure
 * @tc.desc: Test deserialization where ReadPacketLenFromBuffer fails
 * @tc.type: FUNC
 * @tc.level: TestSize.Level1
 */
HWTEST_F(SessionDataHeaderTest, Deserialize_ReadPacketLenFailure, TestSize.Level1)
{
    uint8_t buffer[SessionDataHeader::HEADER_LEN] = { 0 };
    uint16_t packetLenType = static_cast<uint16_t>(TLV_TYPE::TLV_TYPE_PACKET_LEN);
    buffer[0] = packetLenType >> 8;
    buffer[1] = packetLenType & 0xFF;
    buffer[2] = 0;
    buffer[3] = NUM_5;

    auto result = SessionDataHeader::Deserialize(buffer, sizeof(buffer));
    ASSERT_FALSE(result.has_value());
}

/**
 * @tc.name: Deserialize_ReadTotalLenFailure
 * @tc.desc: Test deserialization where ReadTotalLenFromBuffer fails
 * @tc.type: FUNC
 * @tc.level: TestSize.Level1
 */
HWTEST_F(SessionDataHeaderTest, Deserialize_ReadTotalLenFailure, TestSize.Level1)
{
    uint8_t buffer[SessionDataHeader::HEADER_LEN] = { 0 };
    uint16_t totalLenType = static_cast<uint16_t>(TLV_TYPE::TLV_TYPE_TOTAL_LEN);
    buffer[0] = totalLenType >> 8;
    buffer[1] = totalLenType & 0xFF;
    buffer[2] = 0;
    buffer[3] = NUM_5;

    auto result = SessionDataHeader::Deserialize(buffer, sizeof(buffer));
    ASSERT_FALSE(result.has_value());
}

/**
 * @tc.name: Deserialize_ReadSeqNumFailure
 * @tc.desc: Test deserialization where ReadSeqNumFromBuffer fails
 * @tc.type: FUNC
 * @tc.level: TestSize.Level1
 */
HWTEST_F(SessionDataHeaderTest, Deserialize_ReadSeqNumFailure, TestSize.Level1)
{
    uint8_t buffer[SessionDataHeader::HEADER_LEN] = { 0 };
    uint16_t seqNumType = static_cast<uint16_t>(TLV_TYPE::TLV_TYPE_SEQ_NUM);
    buffer[0] = seqNumType >> 8;
    buffer[1] = seqNumType & 0xFF;
    buffer[2] = 0;
    buffer[3] = NUM_5;

    auto result = SessionDataHeader::Deserialize(buffer, sizeof(buffer));
    ASSERT_FALSE(result.has_value());
}

/**
 * @tc.name: Deserialize_ReadSubSeqFailure
 * @tc.desc: Test deserialization where ReadSubSeqFromBuffer fails
 * @tc.type: FUNC
 * @tc.level: TestSize.Level1
 */
HWTEST_F(SessionDataHeaderTest, Deserialize_ReadSubSeqFailure, TestSize.Level1)
{
    uint8_t buffer[SessionDataHeader::HEADER_LEN] = { 0 };
    uint16_t subSeqType = static_cast<uint16_t>(TLV_TYPE::TLV_TYPE_SUB_SEQ);
    buffer[0] = subSeqType >> 8;
    buffer[1] = subSeqType & 0xFF;
    buffer[2] = 0;
    buffer[3] = NUM_5;

    auto result = SessionDataHeader::Deserialize(buffer, sizeof(buffer));
    ASSERT_FALSE(result.has_value());
}

/**
 * @tc.name: Deserialize_InvalidPayloadLength
 * @tc.desc: Test deserialization where payload length exceeds max limit
 * @tc.type: FUNC
 * @tc.level: TestSize.Level1
 */
HWTEST_F(SessionDataHeaderTest, Deserialize_InvalidPayloadLength, TestSize.Level1)
{
    payloadLen = SessionDataHeader::BINARY_PAYLOAD_MAX_LEN + 1;
    version = 1;
    fragFlag = FRAG_TYPE::FRAG_START;
    dataType = NUM_2;
    seqNum = NUM_100;
    totalLen = NUM_500;
    packetLen = NUM_128;
    subSeq = 0;

    header = std::make_unique<SessionDataHeader>(
        version, fragFlag,
        dataType, seqNum, totalLen,
        packetLen, payloadLen, subSeq);
    auto serializedBuffer = header->Serialize();
    ASSERT_NE(serializedBuffer, nullptr);

    auto result = SessionDataHeader::Deserialize(
            serializedBuffer->Data(), serializedBuffer->Size());
    ASSERT_FALSE(result.has_value());
}

/**
 * @tc.name: Deserialize_InvalidPacketLength
 * @tc.desc: Test deserialization where packet length exceeds max limit
 * @tc.type: FUNC
 * @tc.level: TestSize.Level1
 */
HWTEST_F(SessionDataHeaderTest, Deserialize_InvalidPacketLength, TestSize.Level1)
{
    payloadLen = NUM_64;
    version = 1;
    fragFlag = FRAG_TYPE::FRAG_START;
    dataType = NUM_2;
    seqNum = NUM_100;
    totalLen = NUM_500;
    packetLen = SessionDataHeader::BINARY_DATA_MAX_TOTAL_LEN + 1;
    subSeq = 0;

    header = std::make_unique<SessionDataHeader>(
        version, fragFlag,
        dataType, seqNum, totalLen,
        packetLen, payloadLen, subSeq);
    auto serializedBuffer = header->Serialize();
    ASSERT_NE(serializedBuffer, nullptr);

    auto result = SessionDataHeader::Deserialize(
            serializedBuffer->Data(), serializedBuffer->Size());
    ASSERT_FALSE(result.has_value());
}

/**
 * @tc.name: Deserialize_TotalLenTooSmall
 * @tc.desc: Test deserialization where total length is less than sum of packet and payload lengths
 * @tc.type: FUNC
 * @tc.level: TestSize.Level1
 */
HWTEST_F(SessionDataHeaderTest, Deserialize_TotalLenTooSmall, TestSize.Level1)
{
    payloadLen = NUM_64;
    version = 1;
    fragFlag = FRAG_TYPE::FRAG_START;
    dataType = NUM_2;
    seqNum = NUM_100;
    totalLen = NUM_10;
    packetLen = NUM_128;
    subSeq = 0;

    header = std::make_unique<SessionDataHeader>(
        version, fragFlag,
        dataType, seqNum, totalLen,
        packetLen, payloadLen, subSeq);
    auto serializedBuffer = header->Serialize();
    ASSERT_NE(serializedBuffer, nullptr);

    auto result = SessionDataHeader::Deserialize(
            serializedBuffer->Data(), serializedBuffer->Size());
    ASSERT_FALSE(result.has_value());
}

/**
 * @tc.name: Deserialize_UnmatchedVersion
 * @tc.desc: Test deserialization with unmatched version number
 * @tc.type: FUNC
 * @tc.level: TestSize.Level1
 */
HWTEST_F(SessionDataHeaderTest, Deserialize_UnmatchedVersion, TestSize.Level1)
{
    payloadLen = NUM_64;
    version = NUM_2;
    fragFlag = FRAG_TYPE::FRAG_START;
    dataType = NUM_2;
    seqNum = NUM_100;
    totalLen = NUM_600;
    packetLen = NUM_100;
    subSeq = 0;

    header = std::make_unique<SessionDataHeader>(
        version, fragFlag,
        dataType, seqNum, totalLen,
        packetLen, payloadLen, subSeq);
    auto serializedBuffer = header->Serialize();
    ASSERT_NE(serializedBuffer, nullptr);

    auto result = SessionDataHeader::Deserialize(
            serializedBuffer->Data(), serializedBuffer->Size());
    ASSERT_FALSE(result.has_value());
}

} // namespace DistributedCollab
} // namespace OHOS
