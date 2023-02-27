/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "dms_hisysevent_report_test.h"

#include "dfx/dms_hisysevent_report.h"
#include "test_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {
namespace {
    const std::string bundleName = "ohos.hisysevent.test";
    const std::string abilityName = "testAbility";
    const std::string TAG = "DmsHiSysEventReportTest";
    const int32_t eventResult = 0;
    const int32_t callingAppUid = 0;
}

void DmsHiSysEventReportTest::SetUpTestCase()
{
}

void DmsHiSysEventReportTest::TearDownTestCase()
{
}

void DmsHiSysEventReportTest::SetUp()
{
}

void DmsHiSysEventReportTest::TearDown()
{
}

/**
 * @tc.name: testReportBehaviorEvent_001
 * @tc.desc: test ReportBehaviorEvent when HiSysEvent::Write success
 * @tc.type: FUNC
 * @tc.require: I621C1
 */
HWTEST_F(DmsHiSysEventReportTest, testReportBehaviorEvent_001, TestSize.Level3)
{
    DTEST_LOG << "DmsHiSysEventReportTest testReportBehaviorEvent_001 begin" << std::endl;
    BehaviorEventParam param;
    /**
     * @tc.steps: step1. test ReportBehaviorEvent with invalid eventName
     */
    int32_t result = DmsHiSysEventReport::ReportBehaviorEvent(param);
    EXPECT_NE(0, result);
    /**
     * @tc.steps: step2. test ReportBehaviorEvent
     */
    param = { EventCallingType::LOCAL, BehaviorEvent::START_REMOTE_ABILITY, eventResult,
        bundleName, abilityName, callingAppUid };
    result = DmsHiSysEventReport::ReportBehaviorEvent(param);
    EXPECT_EQ(0, result);
    DTEST_LOG << "DmsHiSysEventReportTest testReportBehaviorEvent_001 end" << std::endl;
}

/**
 * @tc.name: testReportFaultEvent_001
 * @tc.desc: test ReportFaultEvent when HiSysEvent::Write success
 * @tc.type: FUNC
 * @tc.require: I621C1
 */
HWTEST_F(DmsHiSysEventReportTest, testReportFaultEvent_001, TestSize.Level3)
{
    DTEST_LOG << "DmsHiSysEventReportTest testReportFaultEvent_001 begin" << std::endl;
    std::string eventName;
    std::string errorType;
    /**
     * @tc.steps: step1. test ReportFaultEvent with invalid error type
     */
    int32_t result = DmsHiSysEventReport::ReportFaultEvent("", "");
    EXPECT_NE(0, result);
    /**
     * @tc.steps: step2. test ReportFaultEvent
     */
    result = DmsHiSysEventReport::ReportFaultEvent(FaultEvent::START_REMOTE_ABILITY,
        EventErrorType::GET_ABILITY_MGR_FAILED);
    EXPECT_EQ(0, result);
    DTEST_LOG << "DmsHiSysEventReportTest testReportFaultEvent_001 end" << std::endl;
}
} // DistributedSchedule
} // namespace OHOS