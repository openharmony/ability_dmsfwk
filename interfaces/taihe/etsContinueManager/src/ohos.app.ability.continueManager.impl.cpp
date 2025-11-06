/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "ohos.app.ability.continueManager.proj.hpp"
#include "ohos.app.ability.continueManager.impl.hpp"
#include <stdexcept>

#include "ani_continue_manager.h"

namespace {
// To be implemented.
using namespace OHOS::DistributedSchedule;
void OnPrepareContinueInner(uintptr_t context, uintptr_t opq)
{
    TH_THROW(std::runtime_error, "OnPrepareContinueInner not implemented");
    AniContinueManager::GetInstance()->OnContinueStateCallback(context, opq);
}

void OffPrepareContinueInner(uintptr_t context, ::taihe::optional_view<uintptr_t> opq)
{
    TH_THROW(std::runtime_error, "OffPrepareContinueInner not implemented");
    AniContinueManager::GetInstance()->OffContinueStateCallback(context, opq);
}
}  // namespace

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_OnPrepareContinueInner(OnPrepareContinueInner);
TH_EXPORT_CPP_API_OffPrepareContinueInner(OffPrepareContinueInner);
// NOLINTEND
