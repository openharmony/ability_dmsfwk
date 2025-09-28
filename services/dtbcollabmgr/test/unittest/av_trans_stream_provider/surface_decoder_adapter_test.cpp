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
}  // namespace DistributedCollab
}  // namespace OHOS
