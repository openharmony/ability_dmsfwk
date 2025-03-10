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

#include "surface_encoder_filter_test.h"
#include "test_log.h"
#include "dtbcollabmgr_log.h"
#include "media_description.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedCollab {
namespace {
    using Status = Media::Status;
    using EventReceiver = Media::Pipeline::EventReceiver;
    using FilterCallback = Media::Pipeline::FilterCallback;
    using Filter = Media::Pipeline::Filter;
    using FilterType = Media::Pipeline::FilterType;
    using AVBuffer = Media::AVBuffer;
    using Meta = Media::Meta;
    using Tag = Media::Tag;
    static constexpr int32_t TEST_APPPID = 1234;
    static constexpr int32_t TEST_APPUID = 5678;
    static constexpr int32_t TEST_INSTANCEID = 12345678;
}

void SurfaceEncoderFilterTest::SetUpTestCase()
{
    DTEST_LOG << "SurfaceEncoderFilterTest::SetUpTestCase" << std::endl;
}

void SurfaceEncoderFilterTest::TearDownTestCase()
{
    DTEST_LOG << "SurfaceEncoderFilterTest::TearDownTestCase" << std::endl;
}

void SurfaceEncoderFilterTest::TearDown()
{
    DTEST_LOG << "SurfaceEncoderFilterTest::TearDown" << std::endl;
}

void SurfaceEncoderFilterTest::SetUp()
{
    DTEST_LOG << "SurfaceEncoderFilterTest::SetUp" << std::endl;
}

/**
 * @tc.name: SetCodecFormat_001
 * @tc.desc: SurfaceEncoderFilter SetCodecFormat return OK
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceEncoderFilterTest, SetCodecFormat_001, TestSize.Level3)
{
    DTEST_LOG << "SurfaceEncoderFilterTest SetCodecFormat_001 begin" << std::endl;
    std::shared_ptr<Meta> format = std::make_shared<Meta>();
    format->Set<Tag::MIME_TYPE>("video/mp4");
    std::string name = "EncoderFilter";
    FilterType type  = FilterType::FILTERTYPE_VENC;
    std::shared_ptr<SurfaceEncoderFilter> videoEncoderFilter_ = std::make_shared<SurfaceEncoderFilter>(name, type);
    EXPECT_EQ(videoEncoderFilter_->SetCodecFormat(format), Status::OK);
    DTEST_LOG << "SurfaceEncoderFilterTest SetCodecFormat_001 end" << std::endl;
}

/**
 * @tc.name: SetCodecFormat_002
 * @tc.desc: SurfaceEncoderFilter SetCodecFormat return ERROR_INVALID_PARAMETER
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceEncoderFilterTest, SetCodecFormat_002, TestSize.Level3)
{
    DTEST_LOG << "SurfaceEncoderFilterTest SetCodecFormat_002 begin" << std::endl;
    std::shared_ptr<Meta> format = std::make_shared<Meta>();
    std::string name = "EncoderFilter";
    FilterType type  = FilterType::FILTERTYPE_VENC;
    std::shared_ptr<SurfaceEncoderFilter> videoEncoderFilter_ = std::make_shared<SurfaceEncoderFilter>(name, type);
    EXPECT_EQ(videoEncoderFilter_->SetCodecFormat(format), Status::ERROR_INVALID_PARAMETER);
    DTEST_LOG << "SurfaceEncoderFilterTest SetCodecFormat_002 end" << std::endl;
}

/**
 * @tc.name: Configure_001
 * @tc.desc: SurfaceEncoderFilter Configure Status::ERROR_UNKNOWN
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceEncoderFilterTest, Configure_001, TestSize.Level3)
{
    DTEST_LOG << "SurfaceEncoderFilterTest Configure_001 begin" << std::endl;
    std::string name = "EncoderFilter";
    FilterType type  = FilterType::FILTERTYPE_VENC;
    std::shared_ptr<SurfaceEncoderFilter> videoEncoderFilter_ = std::make_shared<SurfaceEncoderFilter>(name, type);
    std::shared_ptr<Meta> parameter = std::make_shared<Meta>();
    videoEncoderFilter_->codecAdapter_ = nullptr;
    EXPECT_EQ(videoEncoderFilter_->Configure(parameter), Status::ERROR_UNKNOWN);
    DTEST_LOG << "SurfaceEncoderFilterTest Configure_001 end" << std::endl;
}

/**
 * @tc.name: GetInputSurface_001
 * @tc.desc: SurfaceEncoderFilter GetInputSurface return the surface
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceEncoderFilterTest, GetInputSurface_001, TestSize.Level3)
{
    DTEST_LOG << "SurfaceEncoderFilterTest GetInputSurface_001 begin" << std::endl;
    std::string name = "EncoderFilter";
    FilterType type  = FilterType::FILTERTYPE_VENC;
    std::shared_ptr<SurfaceEncoderFilter> videoEncoderFilter_ = std::make_shared<SurfaceEncoderFilter>(name, type);
    sptr<Surface> surface = nullptr;
    EXPECT_EQ(videoEncoderFilter_->GetInputSurface(), surface);
    DTEST_LOG << "SurfaceEncoderFilterTest GetInputSurface_001 end" << std::endl;
}

/**
 * @tc.name: GetInputSurface_002
 * @tc.desc: SurfaceEncoderFilter GetInputSurface return the surface from codecAdapter
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceEncoderFilterTest, GetInputSurface_002, TestSize.Level3)
{
    DTEST_LOG << "SurfaceEncoderFilterTest GetInputSurface_002 begin" << std::endl;
    std::string name = "EncoderFilter";
    FilterType type  = FilterType::FILTERTYPE_VENC;
    std::shared_ptr<SurfaceEncoderFilter> videoEncoderFilter_ = std::make_shared<SurfaceEncoderFilter>(name, type);
    sptr<Surface> surface = nullptr;
    EXPECT_EQ(videoEncoderFilter_->GetInputSurface(), surface);
    DTEST_LOG << "SurfaceEncoderFilterTest GetInputSurface_002 end" << std::endl;
}

/**
 * @tc.name: GetInputSurface_003
 * @tc.desc: SurfaceEncoderFilter GetInputSurface return null
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceEncoderFilterTest, GetInputSurface_003, TestSize.Level3)
{
    DTEST_LOG << "SurfaceEncoderFilterTest GetInputSurface_003 begin" << std::endl;
    std::string name = "EncoderFilter";
    FilterType type  = FilterType::FILTERTYPE_VENC;
    std::shared_ptr<SurfaceEncoderFilter> videoEncoderFilter_ = std::make_shared<SurfaceEncoderFilter>(name, type);
    EXPECT_EQ(videoEncoderFilter_->GetInputSurface(), nullptr);
    DTEST_LOG << "SurfaceEncoderFilterTest GetInputSurface_003 end" << std::endl;
}

/**
 * @tc.name: DoStart_001
 * @tc.desc: SurfaceEncoderFilter DoStart return the ERROR_UNKNOWN
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceEncoderFilterTest, DoStart_001, TestSize.Level3)
{
    DTEST_LOG << "SurfaceEncoderFilterTest DoStart_001 begin" << std::endl;
    std::string name = "EncoderFilter";
    FilterType type  = FilterType::FILTERTYPE_VENC;
    std::shared_ptr<SurfaceEncoderFilter> videoEncoderFilter_ = std::make_shared<SurfaceEncoderFilter>(name, type);
    videoEncoderFilter_->codecAdapter_ = nullptr;
    EXPECT_EQ(videoEncoderFilter_->DoStart(), Status::ERROR_UNKNOWN);
    DTEST_LOG << "SurfaceEncoderFilterTest DoStart_001 end" << std::endl;
}

/**
 * @tc.name: DoPause_001
 * @tc.desc: SurfaceEncoderFilter DoPause return the ERROR_UNKNOWN
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceEncoderFilterTest, DoPause_001, TestSize.Level3)
{
    DTEST_LOG << "SurfaceEncoderFilterTest DoPause_001 begin" << std::endl;
    std::string name = "EncoderFilter";
    FilterType type  = FilterType::FILTERTYPE_VENC;
    std::shared_ptr<SurfaceEncoderFilter> videoEncoderFilter_ = std::make_shared<SurfaceEncoderFilter>(name, type);
    videoEncoderFilter_->codecAdapter_ = nullptr;
    EXPECT_EQ(videoEncoderFilter_->DoPause(), Status::ERROR_UNKNOWN);
    DTEST_LOG << "SurfaceEncoderFilterTest DoPause_001 end" << std::endl;
}

/**
 * @tc.name: DoResume_001
 * @tc.desc: SurfaceEncoderFilter DoResume return the ERROR_UNKNOWN
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceEncoderFilterTest, DoResume_001, TestSize.Level3)
{
    DTEST_LOG << "SurfaceEncoderFilterTest DoResume_001 begin" << std::endl;
    std::string name = "EncoderFilter";
    FilterType type  = FilterType::FILTERTYPE_VENC;
    std::shared_ptr<SurfaceEncoderFilter> videoEncoderFilter_ = std::make_shared<SurfaceEncoderFilter>(name, type);
    videoEncoderFilter_->codecAdapter_ = nullptr;
    EXPECT_EQ(videoEncoderFilter_->DoResume(), Status::ERROR_UNKNOWN);
    DTEST_LOG << "SurfaceEncoderFilterTest DoResume_001 end" << std::endl;
}

/**
 * @tc.name: DoStop_001
 * @tc.desc: SurfaceEncoderFilter DoStop return the OK
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceEncoderFilterTest, DoStop_001, TestSize.Level3)
{
    DTEST_LOG << "SurfaceEncoderFilterTest DoStop_001 begin" << std::endl;
    std::string name = "EncoderFilter";
    FilterType type  = FilterType::FILTERTYPE_VENC;
    std::shared_ptr<SurfaceEncoderFilter> videoEncoderFilter_ = std::make_shared<SurfaceEncoderFilter>(name, type);
    videoEncoderFilter_->codecAdapter_ = nullptr;
    EXPECT_EQ(videoEncoderFilter_->DoStop(), Status::OK);
    DTEST_LOG << "SurfaceEncoderFilterTest DoStop_001 end" << std::endl;
}

/**
 * @tc.name: Reset_001
 * @tc.desc: SurfaceEncoderFilter Reset return the OK
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceEncoderFilterTest, Reset_001, TestSize.Level3)
{
    DTEST_LOG << "SurfaceEncoderFilterTest Reset_001 begin" << std::endl;
    std::string name = "EncoderFilter";
    FilterType type  = FilterType::FILTERTYPE_VENC;
    std::shared_ptr<SurfaceEncoderFilter> videoEncoderFilter_ = std::make_shared<SurfaceEncoderFilter>(name, type);
    videoEncoderFilter_->codecAdapter_ = nullptr;
    EXPECT_EQ(videoEncoderFilter_->Reset(), Status::OK);
    DTEST_LOG << "SurfaceEncoderFilterTest Reset_001 end" << std::endl;
}

/**
 * @tc.name: DoRelease_001
 * @tc.desc: SurfaceEncoderFilter DoRelease return the OK
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceEncoderFilterTest, DoRelease_001, TestSize.Level3)
{
    DTEST_LOG << "SurfaceEncoderFilterTest DoRelease_001 begin" << std::endl;
    std::string name = "EncoderFilter";
    FilterType type  = FilterType::FILTERTYPE_VENC;
    std::shared_ptr<SurfaceEncoderFilter> videoEncoderFilter_ = std::make_shared<SurfaceEncoderFilter>(name, type);
    videoEncoderFilter_->codecAdapter_ = nullptr;
    EXPECT_EQ(videoEncoderFilter_->DoRelease(), Status::OK);
    DTEST_LOG << "SurfaceEncoderFilterTest DoRelease_001 end" << std::endl;
}

/**
 * @tc.name: SetParameter_001
 * @tc.desc: SurfaceEncoderFilter SetParameter return the nullptr
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceEncoderFilterTest, SetParameter_001, TestSize.Level3)
{
    DTEST_LOG << "SurfaceEncoderFilterTest SetParameter_001 begin" << std::endl;
    std::string name = "EncoderFilter";
    FilterType type  = FilterType::FILTERTYPE_VENC;
    std::shared_ptr<SurfaceEncoderFilter> videoEncoderFilter_ = std::make_shared<SurfaceEncoderFilter>(name, type);
    std::shared_ptr<Meta> parameter = std::make_shared<Meta>();
    videoEncoderFilter_->SetParameter(parameter);
    EXPECT_EQ(videoEncoderFilter_->codecAdapter_, nullptr);
    DTEST_LOG << "SurfaceEncoderFilterTest SetParameter_001 end" << std::endl;
}

/**
 * @tc.name: SetCallingInfo_001
 * @tc.desc: SurfaceEncoderFilter SetCallingInfo with valid parameters
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceEncoderFilterTest, SetCallingInfo_001, TestSize.Level3)
{
    DTEST_LOG << "SurfaceEncoderFilterTest SetCallingInfo_001 begin" << std::endl;
    std::string name = "EncoderFilter";
    FilterType type  = FilterType::FILTERTYPE_VENC;
    std::shared_ptr<SurfaceEncoderFilter> videoEncoderFilter_ = std::make_shared<SurfaceEncoderFilter>(name, type);
    int32_t appUid = TEST_APPUID;
    int32_t appPid = TEST_APPPID;
    std::string bundleName = "com.ohos.testBundle";
    uint64_t instanceId = TEST_INSTANCEID;

    videoEncoderFilter_->SetCallingInfo(appUid, appPid, bundleName, instanceId);

    EXPECT_EQ(videoEncoderFilter_->appUid_, appUid);
    EXPECT_EQ(videoEncoderFilter_->appPid_, appPid);
    EXPECT_EQ(videoEncoderFilter_->bundleName_, bundleName);
    EXPECT_EQ(videoEncoderFilter_->instanceId_, instanceId);
    DTEST_LOG << "SurfaceEncoderFilterTest SetCallingInfo_001 end" << std::endl;
}

/**
 * @tc.name: SetCallingInfo_002
 * @tc.desc: SurfaceEncoderFilter SetCallingInfo when codecAdapter_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceEncoderFilterTest, SetCallingInfo_002, TestSize.Level3)
{
    DTEST_LOG << "SurfaceEncoderFilterTest SetCallingInfo_002 begin" << std::endl;
    std::string name = "EncoderFilter";
    FilterType type  = FilterType::FILTERTYPE_VENC;
    std::shared_ptr<SurfaceEncoderFilter> videoEncoderFilter_ = std::make_shared<SurfaceEncoderFilter>(name, type);
    int32_t appUid = TEST_APPUID;
    int32_t appPid = TEST_APPPID;
    std::string bundleName = "com.ohos.testBundle";
    uint64_t instanceId = TEST_INSTANCEID;

    videoEncoderFilter_->codecAdapter_ = nullptr;
    videoEncoderFilter_->SetCallingInfo(appUid, appPid, bundleName, instanceId);

    EXPECT_EQ(videoEncoderFilter_->appUid_, appUid);
    EXPECT_EQ(videoEncoderFilter_->appPid_, appPid);
    EXPECT_EQ(videoEncoderFilter_->bundleName_, bundleName);
    EXPECT_EQ(videoEncoderFilter_->instanceId_, instanceId);
    DTEST_LOG << "SurfaceEncoderFilterTest SetCallingInfo_002 end" << std::endl;
}
}  // namespace DistributedCollab
}  // namespace OHOS