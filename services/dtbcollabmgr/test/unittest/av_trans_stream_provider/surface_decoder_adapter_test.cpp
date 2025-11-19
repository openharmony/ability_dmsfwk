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
#include "surface_decoder_adapter_test.h"

#include "dtbcollabmgr_log.h"
#include "media_description.h"
#include "test_log.h"

namespace OHOS {
namespace DistributedCollab {
namespace {
    using Status = Media::Status;
    using namespace testing;
    using namespace testing::ext;
    using AVBufferQueue = Media::AVBufferQueue;
    static const std::string TEST_MIME = "testMime";
    static constexpr int32_t NUM_1 = 1;
}

void SurfaceDecoderAdapterTest::SetUpTestCase()
{
    DTEST_LOG << "SurfaceDecoderAdapterTest::SetUpTestCase" << std::endl;
    decodeAdapter_ = std::make_shared<SurfaceDecoderAdapter>();
}

void SurfaceDecoderAdapterTest::TearDownTestCase()
{
    DTEST_LOG << "SurfaceDecoderAdapterTest::TearDownTestCase" << std::endl;
}

void SurfaceDecoderAdapterTest::SetUp()
{
    DTEST_LOG << "SurfaceDecoderAdapterTest::SetUp" << std::endl;
}

void SurfaceDecoderAdapterTest::TearDown()
{
    DTEST_LOG << "SurfaceDecoderAdapterTest::TearDown" << std::endl;
}

/**
 * @tc.name: Init_001
 * @tc.desc: SurfaceDecoderAdapter Init
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceDecoderAdapterTest, Init_001, TestSize.Level3)
{
    DTEST_LOG << "SurfaceDecoderAdapterTest Init_001 begin" << std::endl;
    EXPECT_EQ(decodeAdapter_->Init(TEST_MIME), Status::ERROR_UNKNOWN);
    DTEST_LOG << "SurfaceDecoderAdapterTest Init_001 end" << std::endl;
}

/**
 * @tc.name: Configure_Test
 * @tc.desc: Test Configure
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceDecoderAdapterTest, Configure_Test, TestSize.Level1)
{
    DTEST_LOG << "SurfaceDecoderAdapterTest Configure_Test begin" << std::endl;
    MediaAVCodec::Format format;
    auto ret = decodeAdapter_->Configure(format);
    EXPECT_EQ(ret, Status::ERROR_UNKNOWN);
    DTEST_LOG << "SurfaceDecoderAdapterTest Configure_Test end" << std::endl;
}

/**
 * @tc.name: GetInputBufferQueue_001
 * @tc.desc: SurfaceDecoderAdapter GetInputBufferQueue
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceDecoderAdapterTest, GetInputBufferQueue_001, TestSize.Level3)
{
    DTEST_LOG << "SurfaceDecoderAdapterTest GetInputBufferQueue_001 begin" << std::endl;
    decodeAdapter_->inputBufferQueue_ = AVBufferQueue::Create(NUM_1,
        Media::MemoryType::UNKNOWN_MEMORY, "inputBufferQueue", true);
    EXPECT_EQ(decodeAdapter_->GetInputBufferQueue(), nullptr);
    DTEST_LOG << "SurfaceDecoderAdapterTest GetInputBufferQueue_001 end" << std::endl;
}

/**
 * @tc.name: Start_Test
 * @tc.desc: Test Start
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceDecoderAdapterTest, Start_Test, TestSize.Level1)
{
    DTEST_LOG << "SurfaceDecoderAdapterTest Start_Test begin" << std::endl;
    std::string mime = "test";
    auto ret = decodeAdapter_->Start();
    EXPECT_EQ(ret, Status::ERROR_UNKNOWN);
    DTEST_LOG << "SurfaceDecoderAdapterTest Start_Test end" << std::endl;
}

/**
 * @tc.name: Stop_Test
 * @tc.desc: Test Stop
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceDecoderAdapterTest, Stop_Test, TestSize.Level1)
{
    DTEST_LOG << "SurfaceDecoderAdapterTest Stop_Test begin" << std::endl;
    std::string mime = "test";
    auto ret = decodeAdapter_->Stop();
    EXPECT_EQ(ret, Status::OK);
    DTEST_LOG << "SurfaceDecoderAdapterTest Stop_Test end" << std::endl;
}

/**
 * @tc.name: Flush_Test
 * @tc.desc: Test Flush
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceDecoderAdapterTest, Flush_Test, TestSize.Level1)
{
    DTEST_LOG << "SurfaceDecoderAdapterTest Flush_Test begin" << std::endl;
    std::string mime = "test";
    auto ret = decodeAdapter_->Flush();
    EXPECT_EQ(ret, Status::ERROR_UNKNOWN);
    DTEST_LOG << "SurfaceDecoderAdapterTest Flush_Test end" << std::endl;
}

/**
 * @tc.name: Release_Test
 * @tc.desc: Test Stop
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceDecoderAdapterTest, Release_Test, TestSize.Level1)
{
    DTEST_LOG << "SurfaceDecoderAdapterTest Release_Test begin" << std::endl;
    std::string mime = "test";
    decodeAdapter_->inputBufferQueue_ = nullptr;
    decodeAdapter_->GetInputBufferQueue();
    decodeAdapter_->DetachAllInputBuffer();
    auto testBuffer = std::make_shared<Media::AVBuffer>();
    decodeAdapter_->inputDataBufferQueue_.push(testBuffer);
    decodeAdapter_->DetachAllInputBuffer();
    auto ret = decodeAdapter_->Release();
    EXPECT_EQ(ret, Status::OK);
    DTEST_LOG << "SurfaceDecoderAdapterTest Release_Test end" << std::endl;
}

/**
 * @tc.name: SetParameter_Test
 * @tc.desc: Test SetParameter
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceDecoderAdapterTest, SetParameter_Test, TestSize.Level1)
{
    DTEST_LOG << "SurfaceDecoderAdapterTest SetParameter_Test begin" << std::endl;
    std::string mime = "test";
    MediaAVCodec::Format format;
    auto ret = decodeAdapter_->SetParameter(format);
    EXPECT_EQ(ret, Status::ERROR_UNKNOWN);
    DTEST_LOG << "SurfaceDecoderAdapterTest SetParameter_Test end" << std::endl;
}

/**
 * @tc.name: SetOutputSurface_Test
 * @tc.desc: Test SetOutputSurface
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceDecoderAdapterTest, SetOutputSurface_Test, TestSize.Level1)
{
    DTEST_LOG << "SurfaceDecoderAdapterTest SetOutputSurface_Test begin" << std::endl;
    MediaAVCodec::Format format;
    auto ret = decodeAdapter_->SetParameter(format);
    EXPECT_EQ(ret, Status::ERROR_UNKNOWN);

    ret = decodeAdapter_->SetDecoderAdapterCallback(nullptr);
    EXPECT_EQ(ret, Status::ERROR_UNKNOWN);
    DTEST_LOG << "SurfaceDecoderAdapterTest SetOutputSurface_Test end" << std::endl;
}

/**
 * @tc.name: OnOutputBufferAvailable_001
 * @tc.desc: Test OnOutputBufferAvailable with flag 1 (drop buffer)
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceDecoderAdapterTest, OnOutputBufferAvailable_001, TestSize.Level1)
{
    DTEST_LOG << "SurfaceDecoderAdapterTest OnOutputBufferAvailable_001 begin" << std::endl;
    uint32_t index = 1;
    auto buffer = std::make_shared<Media::AVBuffer>();
    buffer->flag_ = 1;
    buffer->pts_ = 1000;
    
    decodeAdapter_->OnOutputBufferAvailable(index, buffer);
    
    EXPECT_EQ(decodeAdapter_->dropIndexs_.size(), 1);
    EXPECT_EQ(decodeAdapter_->dropIndexs_[0], index);
    EXPECT_EQ(decodeAdapter_->indexs_.size(), 0);
    DTEST_LOG << "SurfaceDecoderAdapterTest OnOutputBufferAvailable_001 end" << std::endl;
}

/**
 * @tc.name: OnOutputBufferAvailable_002
 * @tc.desc: Test OnOutputBufferAvailable with valid PTS (greater than lastBufferPts)
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceDecoderAdapterTest, OnOutputBufferAvailable_002, TestSize.Level1)
{
    DTEST_LOG << "SurfaceDecoderAdapterTest OnOutputBufferAvailable_002 begin" << std::endl;
    uint32_t index = 2;
    auto buffer = std::make_shared<Media::AVBuffer>();
    buffer->flag_ = 0;
    buffer->pts_ = 2000;
    
    decodeAdapter_->lastBufferPts_ = 1000;
    decodeAdapter_->frameNum_ = 5;

    decodeAdapter_->indexs_.clear();
    decodeAdapter_->dropIndexs_.clear();

    decodeAdapter_->OnOutputBufferAvailable(index, buffer);
    
    EXPECT_EQ(decodeAdapter_->lastBufferPts_, 2000);
    EXPECT_EQ(decodeAdapter_->frameNum_, 6);
    EXPECT_EQ(decodeAdapter_->indexs_.size(), 1);
    EXPECT_EQ(decodeAdapter_->indexs_[0], index);
    EXPECT_EQ(decodeAdapter_->dropIndexs_.size(), 0);
    DTEST_LOG << "SurfaceDecoderAdapterTest OnOutputBufferAvailable_002 end" << std::endl;
}

/**
 * @tc.name: OnOutputBufferAvailable_003
 * @tc.desc: Test OnOutputBufferAvailable with invalid PTS (less than or equal to lastBufferPts)
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceDecoderAdapterTest, OnOutputBufferAvailable_003, TestSize.Level1)
{
    DTEST_LOG << "SurfaceDecoderAdapterTest OnOutputBufferAvailable_003 begin" << std::endl;
    uint32_t index = 3;
    auto buffer = std::make_shared<Media::AVBuffer>();
    buffer->flag_ = 0;
    buffer->pts_ = 1000;
    
    decodeAdapter_->lastBufferPts_ = 1500;
    decodeAdapter_->frameNum_ = 3;

    decodeAdapter_->indexs_.clear();
    decodeAdapter_->dropIndexs_.clear();

    decodeAdapter_->OnOutputBufferAvailable(index, buffer);
    
    EXPECT_EQ(decodeAdapter_->lastBufferPts_, 1500);
    EXPECT_EQ(decodeAdapter_->frameNum_, 3);
    EXPECT_EQ(decodeAdapter_->dropIndexs_.size(), 1);
    EXPECT_EQ(decodeAdapter_->dropIndexs_[0], index);
    EXPECT_EQ(decodeAdapter_->indexs_.size(), 0);
    DTEST_LOG << "SurfaceDecoderAdapterTest OnOutputBufferAvailable_003 end" << std::endl;
}

/**
 * @tc.name: OnOutputBufferAvailable_004
 * @tc.desc: Test OnOutputBufferAvailable with zero PTS (initial state)
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceDecoderAdapterTest, OnOutputBufferAvailable_004, TestSize.Level1)
{
    DTEST_LOG << "SurfaceDecoderAdapterTest OnOutputBufferAvailable_004 begin" << std::endl;
    uint32_t index = 4;
    auto buffer = std::make_shared<Media::AVBuffer>();
    buffer->flag_ = 0;
    buffer->pts_ = 0;
    
    decodeAdapter_->lastBufferPts_ = -1;
    decodeAdapter_->frameNum_ = 0;
    
    decodeAdapter_->indexs_.clear();
    decodeAdapter_->dropIndexs_.clear();

    decodeAdapter_->OnOutputBufferAvailable(index, buffer);
    
    EXPECT_EQ(decodeAdapter_->lastBufferPts_, 0);
    EXPECT_EQ(decodeAdapter_->frameNum_, 1);
    EXPECT_EQ(decodeAdapter_->indexs_.size(), 1);
    EXPECT_EQ(decodeAdapter_->indexs_[0], index);
    EXPECT_EQ(decodeAdapter_->dropIndexs_.size(), 0);
    DTEST_LOG << "SurfaceDecoderAdapterTest OnOutputBufferAvailable_005 end" << std::endl;
}
}  // namespace DistributedCollab
}  // namespace OHOS
