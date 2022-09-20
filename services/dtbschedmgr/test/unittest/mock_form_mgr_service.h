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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_FORMMGR_INCLUDE_FORM_MGR_SERVICE_H
#define FOUNDATION_APPEXECFWK_SERVICES_FORMMGR_INCLUDE_FORM_MGR_SERVICE_H

#include <codecvt>
#include <memory>
#include <singleton.h>
#include <system_ability.h>
#include <thread_ex.h>
#include <unordered_map>

#include "form_event_handler.h"
#include "form_mgr_stub.h"
#include "form_provider_data.h"
#include "iremote_object.h"

namespace OHOS {
namespace AppExecFwk {
/**
 * @class MockFormMgrService
 */
class MockFormMgrService : public FormMgrStub,
                       public std::enable_shared_from_this<MockFormMgrService> {
public:
    MockFormMgrService() = default;
    virtual~MockFormMgrService() = default;
    int32_t AddForm(const int64_t formId, const Want &want, const sptr<IRemoteObject> &callerToken,
        FormJsInfo &formInfo) override
    {
        return ERR_OK;
    };
    int32_t DeleteForm(const int64_t formId, const sptr<IRemoteObject> &callerToken) override
    {
        return ERR_OK;
    };
    int32_t ReleaseForm(const int64_t formId, const sptr<IRemoteObject> &callerToken, const bool delCache) override
    {
        return ERR_OK;
    };
    int32_t UpdateForm(const int64_t formId, const FormProviderData &FormProviderData) override
    {
        return ERR_OK;
    };
    int32_t SetNextRefreshTime(const int64_t formId, const int64_t nextTime) override
    {
        return ERR_OK;
    };
    int32_t LifecycleUpdate(const std::vector<int64_t> &formIds, const sptr<IRemoteObject> &callerToken,
        const bool updateType) override
    {
        return ERR_OK;
    };
    ErrCode AddFormInfo(FormInfo &formInfo) override
    {
        return ERR_OK;
    };
    ErrCode RemoveFormInfo(const std::string &moduleName, const std::string &formName) override
    {
        return ERR_OK;
    };
    ErrCode RequestPublishForm(Want &want, bool withFormBindingData,
        std::unique_ptr<FormProviderData> &formBindingData, int64_t &formId) override
    {
        return ERR_OK;
    };
    int32_t RequestForm(const int64_t formId, const sptr<IRemoteObject> &callerToken, const Want &want) override
    {
        return ERR_OK;
    };
    int32_t NotifyWhetherVisibleForms(const std::vector<int64_t> &formIds, const sptr<IRemoteObject> &callerToken,
        const int32_t formVisibleType) override
    {
        return ERR_OK;
    };
    int32_t CastTempForm(const int64_t formId, const sptr<IRemoteObject> &callerToken) override
    {
        return ERR_OK;
    };
    int32_t DumpStorageFormInfos(std::string &formInfos) override
    {
        return ERR_OK;
    };
    int32_t DumpFormInfoByBundleName(const std::string &bundleName, std::string &formInfos) override
    {
        return ERR_OK;
    };
    int32_t DumpFormInfoByFormId(const std::int64_t formId, std::string &formInfo) override
    {
        return ERR_OK;
    };
    int32_t DumpFormTimerByFormId(const std::int64_t formId, std::string &isTimingService) override
    {
        return ERR_OK;
    };
    int32_t MessageEvent(const int64_t formId, const Want &want, const sptr<IRemoteObject> &callerToken) override
    {
        return ERR_OK;
    };
    int32_t RouterEvent(const int64_t formId, Want &want) override
    {
        return ERR_OK;
    };
    int32_t BatchAddFormRecords(const Want &want) override
    {
        return ERR_OK;
    };
    int32_t ClearFormRecords() override
    {
        return ERR_OK;
    };
    int32_t DistributedDataAddForm(const Want &want) override
    {
        return ERR_OK;
    };
    int32_t DistributedDataDeleteForm(const std::string &formId) override
    {
        return ERR_OK;
    };
    int32_t DeleteInvalidForms(const std::vector<int64_t> &formIds, const sptr<IRemoteObject> &callerToken,
                                   int32_t &numFormsDeleted) override
    {
        return ERR_OK;
    };
    int32_t AcquireFormState(const Want &want, const sptr<IRemoteObject> &callerToken,
                                 FormStateInfo &stateInfo) override
    {
        return ERR_OK;
    };
    int32_t NotifyFormsVisible(const std::vector<int64_t> &formIds, bool isVisible,
                                   const sptr<IRemoteObject> &callerToken) override
    {
        return ERR_OK;
    };
    int32_t NotifyFormsPrivacyProtected(const std::vector<int64_t> &formIds, bool isProtected,
                                        const sptr<IRemoteObject> &callerToken) override
    {
        return ERR_OK;
    };
    int32_t NotifyFormsEnableUpdate(const std::vector<int64_t> &formIds, bool isEnableUpdate,
                                        const sptr<IRemoteObject> &callerToken) override
    {
        return ERR_OK;
    };
    int32_t GetAllFormsInfo(std::vector<FormInfo> &formInfos) override
    {
        return ERR_OK;
    };
    int32_t GetFormsInfoByApp(std::string &bundleName, std::vector<FormInfo> &formInfos) override
    {
        return ERR_OK;
    };
    int32_t GetFormsInfoByModule(std::string &bundleName, std::string &moduleName,
                             std::vector<FormInfo> &formInfos) override
    {
        return ERR_OK;
    };
    int32_t UpdateRouterAction(const int64_t formId, std::string &action) override
    {
        return ERR_OK;
    };
    int32_t ShareForm(const int64_t formId, const std::string &deviceId,
        const sptr<IRemoteObject> &callerToken, const int64_t requestCode) override
    {
        return ERR_OK;
    };
    int32_t RecvFormShareInfoFromRemote(const FormShareInfo &info) override
    {
        return ERR_OK;
    };
    bool IsRequestPublishFormSupported() override
    {
        return true;
    };
    int32_t StartAbility(const Want &want, const sptr<IRemoteObject> &callerToken) override
    {
        return ERR_OK;
    };
    int32_t GetFormsInfo(const FormInfoFilter &filter, std::vector<FormInfo> &formInfos) override
    {
        return ERR_OK;
    };
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_FORMMGR_INCLUDE_FORM_MGR_SERVICE_H