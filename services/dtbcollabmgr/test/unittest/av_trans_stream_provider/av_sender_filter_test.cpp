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
#include "av_sender_filter_test.h"

#include "dtbcollabmgr_log.h"
#include "av_stream_param.h"

namespace OHOS {
namespace DistributedCollab {

namespace {
    static const std::string TAG = "AVSenderFilterTest";
    using namespace testing;
    using namespace testing::ext;
    using AVBuffer = Media::AVBuffer;
    using FilterType = Media::Pipeline::FilterType;
    constexpr size_t SIZE = 5;
}

void AVSenderFilterTest::SetUpTestCase()
{
    HILOGI("AVSenderFilterTest::SetUpTestCase");
}

void AVSenderFilterTest::TearDownTestCase()
{
    HILOGI("AVSenderFilterTest::TearDownTestCase");
}

void AVSenderFilterTest::SetUp()
{
    HILOGI("AVSenderFilterTest::SetUp");
}

void AVSenderFilterTest::TearDown()
{
    HILOGI("AVSenderFilterTest::TearDown");
}

/**
 * @tc.name: Process_Test_001
 * @tc.desc: Process
 * @tc.type: FUNC
 */
HWTEST_F(AVSenderFilterTest, Process_Test_001, TestSize.Level1)
{
    HILOGI("AVSenderFilterTest::Process_Test_001 begin");
    std::string name = "test";
    AVSenderFilter filter(name, FilterType::FILTERTYPE_VIDEODEC);
    EXPECT_NO_FATAL_FAILURE(filter.Process());
    HILOGI("AVSenderFilterTest::Process_Test_001 end");
}

/**
 * @tc.name: SendStreamData_Test_001
 * @tc.desc: SendStreamData
 * @tc.type: FUNC
 */
HWTEST_F(AVSenderFilterTest, SendStreamData_Test_001, TestSize.Level1)
{
    HILOGI("AVSenderFilterTest::SendStreamData_Test_001 begin");
    std::string name = "test";
    AVSenderFilter filter(name, FilterType::FILTERTYPE_VIDEODEC);
    std::shared_ptr<AVTransDataBuffer> buffer = std::make_shared<AVTransDataBuffer>(SIZE);
    AVTransStreamDataExt ext;
    std::shared_ptr<AVTransStreamData> streamData = std::make_shared<AVTransStreamData>(buffer, ext);
    filter.channelType_ = ChannelDataType::BYTES;
    filter.SendStreamData(streamData);

    filter.channelType_ = ChannelDataType::VIDEO_STREAM;
    filter.SendStreamData(streamData);
    
    filter.channelType_ = static_cast<ChannelDataType>(-1);
    auto ret = filter.SendStreamData(streamData);
    EXPECT_EQ(ret, INVALID_CHANNEL_TYPE);
    HILOGI("AVSenderFilterTest::SendStreamData_Test_001 end");
}

/**
 * @tc.name: SendStreamDataByBytes_Test_001
 * @tc.desc: SendStreamDataByBytes
 * @tc.type: FUNC
 */
HWTEST_F(AVSenderFilterTest, SendStreamDataByBytes_Test_001, TestSize.Level1)
{
    HILOGI("AVSenderFilterTest::SendStreamDataByBytes_Test_001 begin");
    std::string name = "test";
    AVSenderFilter filter(name, FilterType::FILTERTYPE_VIDEODEC);
    std::shared_ptr<AVTransDataBuffer> buffer = std::make_shared<AVTransDataBuffer>(SIZE);
    AVTransStreamDataExt ext;
    std::shared_ptr<AVTransStreamData> streamData = std::make_shared<AVTransStreamData>(buffer, ext);
    EXPECT_NO_FATAL_FAILURE(filter.SendStreamDataByBytes(streamData));
    HILOGI("AVSenderFilterTest::SendStreamDataByBytes_Test_001 end");
}

/**
 * @tc.name: SendPixelMap_Test_001
 * @tc.desc: SendPixelMap
 * @tc.type: FUNC
 */
HWTEST_F(AVSenderFilterTest, SendPixelMap_Test_001, TestSize.Level1)
{
    HILOGI("AVSenderFilterTest::SendPixelMap_Test_001 begin");
    std::string name = "test";
    AVSenderFilter filter(name, FilterType::FILTERTYPE_VIDEODEC);
    auto ret = filter.SendPixelMap(nullptr);
    EXPECT_EQ(ret, NULL_POINTER_ERROR);

    std::shared_ptr<Media::PixelMap> pixelMap = std::make_shared<Media::PixelMap>();
    ret = filter.SendPixelMap(pixelMap);
    EXPECT_NE(ret, NULL_POINTER_ERROR);
    HILOGI("AVSenderFilterTest::SendPixelMap_Test_001 end");
}

/**
 * @tc.name: WriteDataToBuffer_Test_001
 * @tc.desc: WriteDataToBuffer
 * @tc.type: FUNC
 */
HWTEST_F(AVSenderFilterTest, WriteDataToBuffer_Test_001, TestSize.Level1)
{
    HILOGI("AVSenderFilterTest::WriteDataToBuffer_Test_001 begin");
    std::string name = "test";
    AVSenderFilter filter(name, FilterType::FILTERTYPE_VIDEODEC);
    std::shared_ptr<AVTransDataBuffer> buffer = std::make_shared<AVTransDataBuffer>(SIZE);
    cJSON* headerJson = cJSON_CreateObject();
    char* headerStr = new char(1);
    AVTransStreamDataExt ext;
    std::shared_ptr<AVTransStreamData> streamData = std::make_shared<AVTransStreamData>(buffer, ext);
    auto ret = filter.WriteDataToBuffer(buffer, headerJson, headerStr, streamData);
    cJSON_Delete(headerJson);
    EXPECT_EQ(ret, ERR_OK);
    delete headerStr;
    HILOGI("AVSenderFilterTest::WriteDataToBuffer_Test_001 end");
}
}
}
