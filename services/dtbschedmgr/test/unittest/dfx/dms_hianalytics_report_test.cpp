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

#include "dms_hianalytics_report_test.h"
#include "dtbschedmgr_log.h"
#include "mission/notification/dms_continue_recommend_info.h"


using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {
namespace {
constexpr int32_t ONE = 1;

}

void DmsHiAnalyticsReportTest::SetUpTestCase()
{
    DTEST_LOG << "DmsHiAnalyticsReportTest::SetUpTestCase" << std::endl;
}

void DmsHiAnalyticsReportTest::TearDownTestCase()
{
    DTEST_LOG << "DmsHiAnalyticsReportTest::TearDownTestCase" << std::endl;
}

void DmsHiAnalyticsReportTest::TearDown()
{
    DTEST_LOG << "DmsHiAnalyticsReportTest::TearDown" << std::endl;
}

void DmsHiAnalyticsReportTest::SetUp()
{
    DTEST_LOG << "DmsHiAnalyticsReportTest::SetUp" << std::endl;
}

/**
 * @tc.name: PublishRecommendInfo_001
 * @tc.desc: check PublishRecommendInfo
 * @tc.type: FUNC
 */
HWTEST_F(DmsHiAnalyticsReportTest, PublishRecommendInfo_001, TestSize.Level3)
{
    DTEST_LOG << "DmsHiAnalyticsReportTest PublishRecommendInfo_001 begin" << std::endl;
    ContinueRecommendInfo info;
    int32_t ret = DmsHiAnalyticsReport::PublishRecommendInfo(info);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DmsHiAnalyticsReportTest PublishRecommendInfo_001 end" << std::endl;
}
}
}
