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
}  // namespace DistributedCollab
}  // namespace OHOS
