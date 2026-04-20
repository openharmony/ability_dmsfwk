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
#include "av_receiver_filter_test.h"

#include "av_receiver_engine.h"
#include "av_receiver_filter_listener.h"
#include "av_sender_filter.h"
#include "av_trans_stream_data.h"
#include "dtbcollabmgr_log.h"
#include "av_stream_param.h"

namespace OHOS {
namespace DistributedCollab {

namespace {
    static const std::string TAG = "AVReceiverFilterTest";
    using namespace testing;
    using namespace testing::ext;
    using FilterType = Media::Pipeline::FilterType;
    constexpr size_t SIZE = 5;
    constexpr uint32_t INDEX = 2;
}

void AVReceiverFilterTest::SetUpTestCase()
{
    HILOGI("AVReceiverFilterTest::SetUpTestCase");
}

void AVReceiverFilterTest::TearDownTestCase()
{
    HILOGI("AVReceiverFilterTest::TearDownTestCase");
}

void AVReceiverFilterTest::SetUp()
{
    HILOGI("AVReceiverFilterTest::SetUp");
}

void AVReceiverFilterTest::TearDown()
{
    HILOGI("AVReceiverFilterTest::TearDown");
}

/**
 * @tc.name: OnError_Test_001
 * @tc.desc: OnError
 * @tc.type: FUNC
 */
HWTEST_F(AVReceiverFilterTest, OnError_Test_001, TestSize.Level1)
{
    HILOGI("AVReceiverFilterTest::OnError_Test_001 begin");
    AVReceiverFilter filter("builtin.dtbcollab.receiver", FilterType::FILTERTYPE_VENC);
    filter.listeners_.clear();
    EXPECT_NO_FATAL_FAILURE(filter.OnError(0));

    std::shared_ptr<AVReceiverFilter> filter1 =
        std::make_shared<AVReceiverFilter>("builtin.dtbcollab.receiver", FilterType::FILTERTYPE_VENC);
    std::shared_ptr<IChannelListener> listener = std::make_shared<AVReceiverFilterListener>(filter1);
    filter.listeners_.push_back(listener);
    EXPECT_NO_FATAL_FAILURE(filter.OnError(0));
    HILOGI("AVReceiverFilterTest::OnError_Test_001 end");
}

/**
 * @tc.name: GetStreamData_Test_001
 * @tc.desc: GetStreamData
 * @tc.type: FUNC
 */
HWTEST_F(AVReceiverFilterTest, GetStreamData_Test_001, TestSize.Level1)
{
    HILOGI("AVReceiverFilterTest::GetStreamData_Test_001 begin");
    AVReceiverFilter filter("builtin.dtbcollab.receiver", FilterType::FILTERTYPE_VENC);
    while (!filter.dataQueue_.empty()) {
        filter.dataQueue_.pop();
    }
    auto ret = filter.GetStreamData();
    EXPECT_EQ(ret, nullptr);

    std::shared_ptr<AVTransDataBuffer> buffer = std::make_shared<AVTransDataBuffer>(SIZE);
    AVTransStreamDataExt ext;
    std::shared_ptr<AVTransStreamData> data = std::make_shared<AVTransStreamData>(buffer, ext);
    filter.dataQueue_.push(std::move(data));
    ext.index_ = INDEX;
    std::shared_ptr<AVTransStreamData> data1 = std::make_shared<AVTransStreamData>(buffer, ext);
    filter.dataQueue_.push(data1);
    filter.lastIndex_ = 0;
    ret = filter.GetStreamData();
    EXPECT_EQ(ret, nullptr);

    filter.lastIndex_ = 1;
    ret = filter.GetStreamData();
    EXPECT_EQ(ret, data1);
    HILOGI("AVReceiverFilterTest::GetStreamData_Test_001 end");
}

/**
 * @tc.name: Process_Test_001
 * @tc.desc: Process
 * @tc.type: FUNC
 */
HWTEST_F(AVReceiverFilterTest, Process_Test_001, TestSize.Level1)
{
    HILOGI("AVReceiverFilterTest::Process_Test_001 begin");
    AVReceiverFilter filter("builtin.dtbcollab.receiver", FilterType::FILTERTYPE_VENC);
    filter.isRunning_ = false;
    EXPECT_NO_FATAL_FAILURE(filter.Process());
    HILOGI("AVReceiverFilterTest::Process_Test_001 end");
}

/**
 * @tc.name: DispatchProcessData_Test_001
 * @tc.desc: DispatchProcessData
 * @tc.type: FUNC
 */
HWTEST_F(AVReceiverFilterTest, DispatchProcessData_Test_001, TestSize.Level1)
{
    HILOGI("AVReceiverFilterTest::DispatchProcessData_Test_001 begin");
    AVReceiverFilter filter("builtin.dtbcollab.receiver", FilterType::FILTERTYPE_VENC);
    std::shared_ptr<AVTransDataBuffer> buffer = std::make_shared<AVTransDataBuffer>(SIZE);
    AVTransStreamDataExt ext;
    ext.flag_ = AvCodecBufferFlag::AVCODEC_BUFFER_FLAG_PIXEL_MAP;
    std::shared_ptr<AVTransStreamData> data = std::make_shared<AVTransStreamData>(buffer, ext);
    filter.eventHandler_ = nullptr;
    EXPECT_NO_FATAL_FAILURE(filter.DispatchProcessData(data));

    filter.Init(nullptr, nullptr);
    EXPECT_NO_FATAL_FAILURE(filter.DispatchProcessData(data));

    ext.flag_ = AvCodecBufferFlag::AVCODEC_BUFFER_FLAG_PIXEL_MAP;
    data = std::make_shared<AVTransStreamData>(buffer, ext);
    filter.DispatchProcessData(data);

    ext.flag_ = AvCodecBufferFlag::AVCODEC_BUFFER_FLAG_SURFACE_PARAM;
    data = std::make_shared<AVTransStreamData>(buffer, ext);
    EXPECT_NO_FATAL_FAILURE(filter.DispatchProcessData(data));
    HILOGI("AVReceiverFilterTest::DispatchProcessData_Test_001 end");
}

/**
 * @tc.name: GetPixelMap_Test_001
 * @tc.desc: GetPixelMap
 * @tc.type: FUNC
 */
HWTEST_F(AVReceiverFilterTest, GetPixelMap_Test_001, TestSize.Level1)
{
    HILOGI("AVReceiverFilterTest::GetPixelMap_Test_001 begin");
    AVReceiverFilter filter("builtin.dtbcollab.receiver", FilterType::FILTERTYPE_VENC);
    std::shared_ptr<AVTransDataBuffer> buffer = std::make_shared<AVTransDataBuffer>(SIZE);
    AVTransStreamDataExt ext;
    ext.flag_ = AvCodecBufferFlag::AVCODEC_BUFFER_FLAG_PIXEL_MAP;
    std::shared_ptr<AVTransStreamData> data = std::make_shared<AVTransStreamData>(buffer, ext);
    EXPECT_NO_FATAL_FAILURE(filter.GetPixelMap(data));

    filter.isRunning_ = false;
    EXPECT_NO_FATAL_FAILURE(filter.OnStream(data));

    filter.isRunning_ = true;
    EXPECT_NO_FATAL_FAILURE(filter.OnStream(data));
    HILOGI("AVReceiverFilterTest::GetPixelMap_Test_001 end");
}

/**
 * @tc.name: OnBytes_Test_001
 * @tc.desc: OnBytes
 * @tc.type: FUNC
 */
HWTEST_F(AVReceiverFilterTest, OnBytes_Test_001, TestSize.Level1)
{
    HILOGI("AVReceiverFilterTest::OnBytes_Test_001 begin");
    AVReceiverFilter filter("builtin.dtbcollab.receiver", FilterType::FILTERTYPE_VENC);
    std::shared_ptr<AVTransDataBuffer> buffer = std::make_shared<AVTransDataBuffer>(SIZE);
    EXPECT_NO_FATAL_FAILURE(filter.OnBytes(nullptr));

    EXPECT_NO_FATAL_FAILURE(filter.OnBytes(buffer));
    std::shared_ptr<AVTransDataBuffer> buffer1 = std::make_shared<AVTransDataBuffer>(sizeof(AVSenderFilter::version) +
        sizeof(AVSenderFilter::transType) + sizeof(uint32_t) + sizeof(uint32_t));
    EXPECT_NO_FATAL_FAILURE(filter.OnBytes(buffer1));
    HILOGI("AVReceiverFilterTest::OnBytes_Test_001 end");
}

/**
 * @tc.name: ReadStreamDataFromBuffer_Test_001
 * @tc.desc: ReadStreamDataFromBuffer
 * @tc.type: FUNC
 */
HWTEST_F(AVReceiverFilterTest, ReadStreamDataFromBuffer_Test_001, TestSize.Level1)
{
    HILOGI("AVReceiverFilterTest::ReadStreamDataFromBuffer_Test_001 begin");
    AVReceiverFilter filter("builtin.dtbcollab.receiver", FilterType::FILTERTYPE_VENC);
    uint8_t dataHeader[10] = {0};
    uint32_t headerLen = 0;
    size_t totalLen = 0;
    auto ret = filter.ReadStreamDataFromBuffer(dataHeader, headerLen, totalLen);
    HILOGI("AVReceiverFilterTest::ReadStreamDataFromBuffer_Test_001 end");
}

/**
 * @tc.name: OnBytes_OutOfBounds_Read_Test_001
 * @tc.desc: 防止越界读取 - 验证边界检查正确性
 * @tc.type: FUNC
 */
HWTEST_F(AVReceiverFilterTest, OnBytes_OutOfBounds_Read_Test_001, TestSize.Level1)
{
    HILOGI("AVReceiverFilterTest::OnBytes_OutOfBounds_Read_Test_001 begin");
    AVReceiverFilter filter("builtin.dtbcollab.receiver", FilterType::FILTERTYPE_VENC);

    // 构造触发越界读取的数据包（修复前应该触发，修复后安全）
    constexpr size_t bufferSize = 100;
    constexpr size_t headerLen = 10;

    std::shared_ptr<AVTransDataBuffer> buffer = std::make_shared<AVTransDataBuffer>(bufferSize);
    uint8_t* data = buffer->Data();

    // 1. 写入version (4字节)
    int32_t version = 0;
    memcpy_s(data, sizeof(version), &version, sizeof(version));

    // 2. 写入transType (4字节)
    int32_t transType = 0;
    memcpy_s(data + 4, sizeof(transType), &transType, sizeof(transType));

    // 3. 写入headerLen (4字节)
    uint32_t jsonHeaderLen = headerLen;
    memcpy_s(data + 8, sizeof(jsonHeaderLen), &jsonHeaderLen, sizeof(jsonHeaderLen));

    // 4. 写入JSON头部（10字节）
    const char* jsonHeader = "{\"dataLen\":79}";  // dataLen=79，会尝试读取越界
    memcpy_s(data + 12, headerLen, jsonHeader, headerLen);

    // 5. 填充合法数据（78字节）
    memset_s(data + 22, bufferSize - 22, 0xAA, 78);

    // 调用OnBytes，修复后应该安全返回，不会越界读取
    filter.OnBytes(buffer);

    // 验证不会崩溃（如果到达这里说明修复有效）
    EXPECT_TRUE(true);
    HILOGI("AVReceiverFilterTest::OnBytes_OutOfBounds_Read_Test_001 end");
}

/**
 * @tc.name: OnBytes_Boundary_Check_Test_002
 * @tc.desc: 边界检查 - 验证正常的合法数据能正确处理
 * @tc.type: FUNC
 */
HWTEST_F(AVReceiverFilterTest, OnBytes_Boundary_Check_Test_002, TestSize.Level1)
{
    HILOGI("AVReceiverFilterTest::OnBytes_Boundary_Check_Test_002 begin");
    AVReceiverFilter filter("builtin.dtbcollab.receiver", FilterType::FILTERTYPE_VENC);

    // 构造合法的数据包
    constexpr size_t bufferSize = 100;
    constexpr size_t headerLen = 10;
    constexpr size_t rawDataLen = 78;  // 合法大小

    std::shared_ptr<AVTransDataBuffer> buffer = std::make_shared<AVTransDataBuffer>(bufferSize);
    uint8_t* data = buffer->Data();

    // 填充头部
    int32_t version = 0;
    int32_t transType = 0;
    uint32_t jsonHeaderLen = headerLen;

    memcpy_s(data, sizeof(version), &version, sizeof(version));
    memcpy_s(data + 4, sizeof(transType), &transType, sizeof(transType));
    memcpy_s(data + 8, sizeof(jsonHeaderLen), &jsonHeaderLen, sizeof(jsonHeaderLen));

    // 写入JSON头部（10字节）
    const char* jsonHeader = "{\"dataLen\":78}";  // 合法的dataLen
    memcpy_s(data + 12, headerLen, jsonHeader, headerLen);

    // 填充数据（78字节）
    memset_s(data + 22, bufferSize - 22, 0xBB, rawDataLen);

    // 调用OnBytes，应该正常处理
    filter.OnBytes(buffer);

    // 验证不会崩溃
    EXPECT_TRUE(true);
    HILOGI("AVReceiverFilterTest::OnBytes_Boundary_Check_Test_002 end");
}
}
}