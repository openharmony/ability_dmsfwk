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

#include "dschedsoftbussession_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include <securec.h>

#include "dsched_data_buffer.h"
#include "dsched_softbus_session.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
constexpr size_t FOO_MAX_LEN = 1024;
constexpr size_t U32_AT_SIZE = 4;
constexpr int32_t POS_0 = 0;
constexpr int32_t POS_1 = 1;
constexpr int32_t POS_2 = 2;
constexpr int32_t POS_3 = 3;
constexpr int32_t OFFSET_24 = 24;
constexpr int32_t OFFSET_16 = 16;
constexpr int32_t OFFSET_8 = 8;
constexpr int32_t MAX_DATALEN = 2048;
constexpr int32_t MAX_FDP_RANGE = 1024;
constexpr size_t MIN_FRAG_BUFFER_SIZE = 16;
constexpr size_t MIN_NO_FRAG_BUFFER_SIZE = 8;
constexpr size_t MIN_NO_FRAG_BUF_SIZE = 8;
constexpr size_t MAX_NO_FRAG_BUF_SIZE = 256;
constexpr size_t MIN_FRAG_BUF_SIZE = 16;
constexpr size_t MAX_FRAG_BUF_SIZE = 512;
constexpr uint8_t MIN_FRAG_FLAG = 0;
constexpr uint8_t MAX_FRAG_FLAG = 3;
constexpr uint32_t MIN_DATA_LEN = 0;
constexpr int32_t TOTAL_LEN_MULTIPLIER = 2;


inline uint32_t ConsumeDataLen(FuzzedDataProvider& fdp)
{
    return fdp.ConsumeIntegralInRange<uint32_t>(1, MAX_FDP_RANGE);
}

inline uint32_t ConsumeTotalLen(FuzzedDataProvider& fdp, uint32_t dataLen)
{
    return fdp.ConsumeIntegralInRange<uint32_t>(dataLen, MAX_DATALEN);
}

inline uint32_t ConsumeSessionTotalLen(FuzzedDataProvider& fdp, uint32_t dataLen)
{
    return fdp.ConsumeIntegralInRange<uint32_t>(dataLen, MAX_DATALEN);
}
}

int32_t Get32Data(const uint8_t* ptr, size_t size)
{
    if (size > FOO_MAX_LEN || size < U32_AT_SIZE) {
        return 0;
    }
    char *ch = static_cast<char*>(malloc(size + 1));
    if (ch == nullptr) {
        return 0;
    }
    (void)memset_s(ch, size + 1, 0x00, size + 1);
    if (memcpy_s(ch, size + 1, ptr, size) != EOK) {
        free(ch);
        ch = nullptr;
        return 0;
    }
    int32_t data = (ch[POS_0] << OFFSET_24) | (ch[POS_1] << OFFSET_16) | (ch[POS_2] << OFFSET_8) | ch[POS_3];
    free(ch);
    ch = nullptr;
    return data;
}

void FuzzOnBytesReceived(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < U32_AT_SIZE)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);

    size_t bufSize = fdp.ConsumeIntegralInRange<size_t>(MIN_FRAG_BUF_SIZE, MAX_FRAG_BUF_SIZE);
    std::shared_ptr<DSchedDataBuffer> buffer = std::make_shared<DSchedDataBuffer>(bufSize);
    std::vector<uint8_t> bufContent = fdp.ConsumeBytes<uint8_t>(bufSize);
    if (memcpy_s(buffer->Data(), bufSize, bufContent.data(), bufContent.size()) != EOK) {
        return;
    }
    DSchedSoftbusSession dschedSoftbusSession;
    dschedSoftbusSession.OnBytesReceived(buffer);
    dschedSoftbusSession.OnConnect();
    dschedSoftbusSession.GetPeerDeviceId();
    int32_t dataType = Get32Data(data, size);
    dschedSoftbusSession.SendData(buffer, dataType);
    dschedSoftbusSession.OnDisconnect();
}

void FuzzAssembleNoFrag(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < U32_AT_SIZE)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);

    size_t bufSize = fdp.ConsumeIntegralInRange<size_t>(MIN_FRAG_BUF_SIZE, MAX_FRAG_BUF_SIZE);
    std::shared_ptr<DSchedDataBuffer> buffer = std::make_shared<DSchedDataBuffer>(bufSize);
    std::vector<uint8_t> bufContent = fdp.ConsumeBytes<uint8_t>(bufSize);
    if (memcpy_s(buffer->Data(), bufSize, bufContent.data(), bufContent.size()) != EOK) {
        return;
    }
    int32_t accountId = *(reinterpret_cast<const int32_t*>(data));
    DSchedSoftbusSession dschedSoftbusSession;
    dschedSoftbusSession.ResetAssembleFrag();

    dschedSoftbusSession.UnPackSendData(buffer, accountId);
    dschedSoftbusSession.UnPackStartEndData(buffer, accountId);
}

void FuzzDSchedSoftbusSessionConstructor(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < U32_AT_SIZE)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    SessionInfo sessionInfo;
    sessionInfo.sessionId = fdp.ConsumeIntegral<int32_t>();
    sessionInfo.myDeviceId = fdp.ConsumeRandomLengthString();
    sessionInfo.peerDeviceId = fdp.ConsumeRandomLengthString();
    sessionInfo.sessionName = fdp.ConsumeRandomLengthString();
    sessionInfo.isServer = fdp.ConsumeBool();

    DSchedSoftbusSession dschedSoftbusSession(sessionInfo);
    dschedSoftbusSession.OnConnect();
    dschedSoftbusSession.OnDisconnect();
    dschedSoftbusSession.GetPeerDeviceId();
}

void FuzzCheckUnPackBuffer(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < U32_AT_SIZE)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);

    DSchedSoftbusSession::SessionDataHeader headerPara;
    headerPara.seqNum = fdp.ConsumeIntegral<uint32_t>();
    headerPara.subSeq = fdp.ConsumeIntegral<uint16_t>();
    headerPara.dataLen = ConsumeDataLen(fdp);
    headerPara.totalLen = ConsumeTotalLen(fdp, headerPara.dataLen);

    DSchedSoftbusSession dschedSoftbusSession;

    dschedSoftbusSession.isWaiting_ = fdp.ConsumeBool();
    dschedSoftbusSession.nowSeq_ = fdp.ConsumeIntegral<uint32_t>();
    dschedSoftbusSession.nowSubSeq_ = fdp.ConsumeIntegral<uint16_t>();
    dschedSoftbusSession.totalLen_ = ConsumeSessionTotalLen(fdp, headerPara.dataLen);
    dschedSoftbusSession.offset_ = fdp.ConsumeIntegralInRange<uint32_t>(0, dschedSoftbusSession.totalLen_);

    dschedSoftbusSession.CheckUnPackBuffer(headerPara);
}

void AssembleNoFragFuzzTest(const uint8_t* data, size_t size)
{
    if (!data || size < MIN_NO_FRAG_BUFFER_SIZE) {
        return;
    }
    FuzzedDataProvider fdp(data, size);

    size_t bufSize = fdp.ConsumeIntegralInRange<size_t>(MIN_NO_FRAG_BUF_SIZE, MAX_NO_FRAG_BUF_SIZE);
    std::shared_ptr<DSchedDataBuffer> buffer = std::make_shared<DSchedDataBuffer>(bufSize);
    std::vector<uint8_t> bufContent = fdp.ConsumeBytes<uint8_t>(bufSize);
    if (memcpy_s(buffer->Data(), bufSize, bufContent.data(), bufContent.size()) != EOK) {
        return;
    }

    DSchedSoftbusSession::SessionDataHeader headerPara;
    headerPara.dataLen = fdp.ConsumeIntegralInRange<uint32_t>(MIN_DATA_LEN, bufSize);
    headerPara.totalLen = headerPara.dataLen;
    headerPara.dataType = fdp.ConsumeIntegral<uint32_t>();

    DSchedSoftbusSession session;
    session.AssembleNoFrag(buffer, headerPara);
}

void AssembleFragFuzzTest(const uint8_t* data, size_t size)
{
    if (!data || size < MIN_FRAG_BUFFER_SIZE) {
        return;
    }
    FuzzedDataProvider fdp(data, size);

    size_t bufSize = fdp.ConsumeIntegralInRange<size_t>(MIN_FRAG_BUF_SIZE, MAX_FRAG_BUF_SIZE);
    std::shared_ptr<DSchedDataBuffer> buffer = std::make_shared<DSchedDataBuffer>(bufSize);
    std::vector<uint8_t> bufContent = fdp.ConsumeBytes<uint8_t>(bufSize);
    if (memcpy_s(buffer->Data(), bufSize, bufContent.data(), bufContent.size()) != EOK) {
        return;
    }
    DSchedSoftbusSession::SessionDataHeader headerPara;
    headerPara.fragFlag = fdp.ConsumeIntegralInRange<uint8_t>(MIN_FRAG_FLAG, MAX_FRAG_FLAG);
    headerPara.seqNum = fdp.ConsumeIntegral<uint32_t>();
    headerPara.subSeq = fdp.ConsumeIntegral<uint16_t>();
    headerPara.dataLen = fdp.ConsumeIntegralInRange<uint32_t>(MIN_DATA_LEN, bufSize);
    headerPara.totalLen = fdp.ConsumeIntegralInRange<uint32_t>(headerPara.dataLen, bufSize * TOTAL_LEN_MULTIPLIER);
    headerPara.dataType = fdp.ConsumeIntegral<uint32_t>();

    DSchedSoftbusSession session;
    session.AssembleFrag(buffer, headerPara);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DistributedSchedule::FuzzOnBytesReceived(data, size);
    OHOS::DistributedSchedule::FuzzAssembleNoFrag(data, size);
    OHOS::DistributedSchedule::FuzzDSchedSoftbusSessionConstructor(data, size);
    OHOS::DistributedSchedule::FuzzCheckUnPackBuffer(data, size);
    OHOS::DistributedSchedule::AssembleNoFragFuzzTest(data, size);
    OHOS::DistributedSchedule::AssembleFragFuzzTest(data, size);
    return 0;
}
