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

#include "distributed_extension_ets.h"
#include "dtbschedmgr_log.h"
#include "ani_common_configuration.h"
#include "ani_common_util.h"
#include "ani_common_want.h"
#include "ets_runtime.h"
#include "distributed_extension_context_ets.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "DistributedExtensionETS";
constexpr const char *ON_COLLABORATE =
    "C{std.core.Record}:C{@ohos.app.ability.AbilityConstant.AbilityConstant.CollaborateResult}";
}

extern "C" __attribute__((visibility("default"))) DistributedExtension *OHOS_ABILITY_DistributedExtensionETS(
    const std::unique_ptr<Runtime> &runtime)
{
    return new DistributedExtensionETS(static_cast<ETSRuntime &>(*runtime));
}

DistributedExtensionETS *DistributedExtensionETS::Create(const std::unique_ptr<Runtime> &runtime)
{
    HILOG_INFO("call___%{public}d", runtime->GetLanguage());
    return new DistributedExtensionETS(static_cast<ETSRuntime &>(*runtime));
}

DistributedExtensionETS::DistributedExtensionETS(ETSRuntime &etsRuntime) : etsRuntime_(etsRuntime) {}

DistributedExtensionETS::~DistributedExtensionETS()
{
    HILOG_INFO("destructor");
    if (etsAbilityObj_ == nullptr) {
        HILOG_INFO("etsAbilityObj_ null");
        return;
    }
    bool isAttachThread = false;
    ani_env *env = AppExecFwk::AttachAniEnv(etsVm_, isAttachThread);
    if (env == nullptr) {
        HILOG_INFO("env null");
        return;
    }
    if (etsAbilityObj_->aniRef) {
        env->GlobalReference_Delete(etsAbilityObj_->aniRef);
    }
    AppExecFwk::DetachAniEnv(etsVm_, isAttachThread);
}

void DistributedExtensionETS::Init(const std::shared_ptr<AbilityLocalRecord> &record,
    const std::shared_ptr<OHOSApplication> &application, std::shared_ptr<AbilityHandler> &handler,
    const sptr<IRemoteObject> &token)
{
    HILOG_INFO("ldp Init call");
    if (record == nullptr) {
        HILOG_INFO("null localAbilityRecord");
        return;
    }
    auto abilityInfo = record->GetAbilityInfo();
    if (abilityInfo == nullptr) {
        HILOG_INFO("null abilityInfo");
        return;
    }
    DistributedExtension::Init(record, application, handler, token);

    std::string srcPath;
    GetSrcPath(srcPath);
    std::string moduleName(Extension::abilityInfo_->moduleName);
    moduleName.append("::").append(abilityInfo_->name);
    HILOG_DEBUG("moduleName:%{public}s,srcPath:%{public}s, compileMode :%{public}d",
        moduleName.c_str(), srcPath.c_str(), abilityInfo_->compileMode);

    BindContext(abilityInfo, record->GetWant(), moduleName, srcPath);
    HILOG_INFO("Init End");
}

void DistributedExtensionETS::GetSrcPath(std::string &srcPath)
{
    if (!Extension::abilityInfo_->isModuleJson) {
        srcPath.append(Extension::abilityInfo_->package);
        srcPath.append("/assets/js/");
        if (!Extension::abilityInfo_->srcPath.empty()) {
            srcPath.append(Extension::abilityInfo_->srcPath);
        }
        srcPath.append("/").append(Extension::abilityInfo_->name).append(".abc");
        return;
    }

    if (!Extension::abilityInfo_->srcEntrance.empty()) {
        srcPath.append(Extension::abilityInfo_->moduleName + "/");
        srcPath.append(Extension::abilityInfo_->srcEntrance);
        auto pos = srcPath.rfind(".");
        if (pos != std::string::npos) {
            srcPath.erase(pos);
            srcPath.append(".abc");
        }
    }
}

void DistributedExtensionETS::UpdateDistributedExtensionObj(
    std::shared_ptr<AbilityInfo> &abilityInfo, const std::string &moduleName, const std::string &srcPath)
{
    HILOG_INFO("ldp UpdateDistributedExtensionObj call");
    etsAbilityObj_ = etsRuntime_.LoadModule(moduleName, srcPath, abilityInfo->hapPath,
        abilityInfo->compileMode == AppExecFwk::CompileMode::ES_MODULE, false, abilityInfo_->srcEntrance);
    if (etsAbilityObj_ == nullptr) {
        HILOG_INFO("ldp null etsAbilityObj_");
        return;
    }
    HILOG_INFO("ldp UpdateDistributedExtensionObj End");
}

void DistributedExtensionETS::BindContext(std::shared_ptr<AbilityInfo> &abilityInfo, std::shared_ptr<AAFwk::Want> want,
    const std::string &moduleName, const std::string &srcPath)
{
    HILOG_INFO("BindContext call");
    UpdateDistributedExtensionObj(abilityInfo, moduleName, srcPath);
    if (etsAbilityObj_ == nullptr || want == nullptr) {
        HILOG_INFO("etsAbilityObj_ or abilityContext_ or want is null");
        return;
    }
    auto env = etsRuntime_.GetAniEnv();
    if (env == nullptr) {
        HILOG_INFO("env null");
        return;
    }
    ani_vm *aniVM = nullptr;
    if (env->GetVM(&aniVM) != ANI_OK) {
        HILOG_INFO("GetVM error");
        return;
    }
    if (aniVM == nullptr) {
        HILOG_INFO("aniVM nullptr");
        return;
    }
    etsVm_ = aniVM;
    auto context = GetContext();
    if (context == nullptr) {
        HILOG_INFO("get context error");
        return;
    }
    ani_ref contextObj = CreateDistributedExtensionContextETS(env, context);
    if (contextObj == nullptr) {
        HILOG_INFO("Create context obj error");
        return;
    }
    ani_ref contextGlobalRef = nullptr;
    ani_field field = nullptr;
    ani_status status = ANI_ERROR;
    if ((status = env->GlobalReference_Create(contextObj, &contextGlobalRef)) != ANI_OK) {
        HILOG_INFO("GlobalReference_Create failed, status : %{public}d", status);
        return;
    }
    if ((status = env->Class_FindField(etsAbilityObj_->aniCls, "context", &field)) != ANI_OK) {
        HILOG_INFO("Class_FindField failed, status : %{public}d", status);
        return;
    }
    if ((status = env->Object_SetField_Ref(etsAbilityObj_->aniObj, field, contextGlobalRef)) != ANI_OK) {
        HILOG_INFO("Object_SetField_Ref failed, status : %{public}d", status);
        return;
    }
    HILOG_INFO("BindContext End");
}

int32_t DistributedExtensionETS::TriggerOnCreate(AAFwk::Want& want)
{
    HILOG_DEBUG("TriggerOnCreate");
    if (etsAbilityObj_ == nullptr) {
        HILOG_ERROR("etsAbilityObj_ null");
        return EINVAL;
    }
    bool isAttachThread = false;
    ani_env *env = AppExecFwk::AttachAniEnv(etsVm_, isAttachThread);
    if (env == nullptr) {
        HILOG_ERROR("env null");
        return EINVAL;
    }
    ani_status status = ANI_ERROR;
    do {
        ani_ref wantRef = AppExecFwk::WrapWant(env, want);
        ani_method function;
        if ((status = env->Class_FindMethod(etsAbilityObj_->aniCls, "onCreate",
            "C{@ohos.app.ability.Want.Want}:", &function)) != ANI_OK) {
            HILOG_ERROR("Class_FindMethod status : %{public}d", status);
            break;
        }

        status = env->Object_CallMethod_Void(etsAbilityObj_->aniObj, function, wantRef);
        if (status != ANI_OK) {
            HILOG_ERROR("Object_CallMethod_Void status : %{public}d", status);
            break;
        }
    } while (false);
    AppExecFwk::DetachAniEnv(etsVm_, isAttachThread);
    if (status != ANI_OK) {
        return EINVAL;
    }
    HILOG_INFO("OnCreate End");
    return ERR_OK;
}

int32_t DistributedExtensionETS::TriggerOnDestroy()
{
    HILOG_DEBUG("TriggerOnDestroy");
    if (etsAbilityObj_ == nullptr) {
        HILOG_ERROR("etsAbilityObj_ null");
        return EINVAL;
    }
    bool isAttachThread = false;
    ani_env *env = AppExecFwk::AttachAniEnv(etsVm_, isAttachThread);
    if (env == nullptr) {
        HILOG_ERROR("env null");
        return EINVAL;
    }

    ani_status status = ANI_ERROR;
    do {
        ani_method function;
        if ((status = env->Class_FindMethod(etsAbilityObj_->aniCls, "onDestroy", nullptr, &function)) != ANI_OK) {
            HILOG_ERROR("Class_FindMethod status : %{public}d", status);
            break;
        }
        status = env->Object_CallMethod_Void(etsAbilityObj_->aniObj, function);
        if (status != ANI_OK) {
            HILOG_ERROR("Object_CallMethod_Void status : %{public}d", status);
            break;
        }
    } while (false);
    AppExecFwk::DetachAniEnv(etsVm_, isAttachThread);
    if (status != ANI_OK) {
        return EINVAL;
    }
    HILOG_INFO("OnDestroy End");
    return ERR_OK;
}

int32_t DistributedExtensionETS::TriggerOnCollaborate(AAFwk::WantParams &wantParam)
{
    HILOG_DEBUG("TriggerOnCollaborate");
    if (etsAbilityObj_ == nullptr) {
        HILOG_ERROR("etsAbilityObj_ null");
        return EINVAL;
    }
    bool isAttachThread = false;
    ani_env *env = AppExecFwk::AttachAniEnv(etsVm_, isAttachThread);
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return EINVAL;
    }
    ani_status status = ANI_ERROR;
    do {
        ani_method method = nullptr;
        status = env->Class_FindMethod(etsAbilityObj_->aniCls, "onCollaborate", ON_COLLABORATE, &method);
        if (status != ANI_OK) {
            HILOG_ERROR("onCollaborate FindMethod status: %{public}d, or null method", status);
            break;
        }
        ani_ref wantParamsRef = AppExecFwk::WrapWantParams(env, wantParam);
        if (wantParamsRef == nullptr) {
            HILOG_ERROR("null wantParamsRef");
            break;
        }
        ani_value args[] = { { .r = wantParamsRef } };
        ani_ref result = nullptr;
        if ((status = env->Object_CallMethod_Ref_A(etsAbilityObj_->aniObj, method, &result, args)) != ANI_OK ||
            result == nullptr) {
            HILOG_ERROR("CallMethod status: %{public}d, or null result", status);
            break;
        }
    } while (false);
    AppExecFwk::DetachAniEnv(etsVm_, isAttachThread);
    if (status != ANI_OK) {
        return EINVAL;
    }
    HILOG_INFO("OnCollaborate End");
    return ERR_OK;
}
} // namespace DistributedSchedule
} // namespace OHOS
