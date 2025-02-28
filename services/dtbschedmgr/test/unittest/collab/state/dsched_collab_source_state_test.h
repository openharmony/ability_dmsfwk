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

#ifndef DSCHED_COLLAB_SOURCE_STATE_TEST_H
#define DSCHED_COLLAB_SOURCE_STATE_TEST_H
#include "dsched_collab_source_get_peer_version_state.h"
#include "dsched_collab_source_start_state.h"
#include "dsched_collab_source_wait_end_state.h"
#include "dsched_collab_source_wait_result_state.h"

#include "gtest/gtest.h"


namespace OHOS {
namespace DistributedSchedule {


class CollabSrcGetPeerVersionStateTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    static inline std::shared_ptr<CollabSrcGetPeerVersionState> srcGetPeerVersionState_;
    static inline std::shared_ptr<DSchedCollab> dCollab_;
};
class CollabSrcStartStateTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    static inline std::shared_ptr<CollabSrcStartState> srcStateState_;
    static inline std::shared_ptr<DSchedCollab> dCollab_;
};

class CollabSrcWaitEndStateTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    static inline std::shared_ptr<CollabSrcWaitEndState> srcWaitEndState_;
    static inline std::shared_ptr<DSchedCollab> dCollab_;
};

class CollabSrcWaitResultStateTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    static inline std::shared_ptr<CollabSrcWaitResultState> srcWaitRltState_;
    static inline std::shared_ptr<DSchedCollab> dCollab_;
};
} // namespace DistributedSchedule
} // namespace OHOS
#endif // DSCHED_COLLAB_SINK_STATE_TEST_H
