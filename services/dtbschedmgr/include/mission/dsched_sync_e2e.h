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

#ifndef DSCHED_SYNC_E2E_H
#define DSCHED_SYNC_E2E_H

#include "distributed_sched_utils.h"
#include "dtbschedmgr_device_info_storage.h"
#include "mission/distributed_bm_storage.h"

namespace OHOS {
namespace DistributedSchedule {
using namespace AppExecFwk;
using namespace DistributedKv;

class DmsKvSyncCB : public OHOS::DistributedKv::KvStoreSyncCallback {
public:
    DmsKvSyncCB();
    virtual ~DmsKvSyncCB();
    void SyncCompleted(const std::map<std::string, DistributedKv::Status> &result) override;
};

class DmsKvSyncE2E {
public:
    DmsKvSyncE2E();
    ~DmsKvSyncE2E();
    static std::shared_ptr<DmsKvSyncE2E> GetInstance();
    bool PushAndPullData();
    bool PushAndPullData(const std::string &networkId);
    void SetDeviceCfg();
    bool CheckDeviceCfg();
    void SetSyncRecord(const std::string &networkId);
    void ClearSyncRecord(const std::string &networkId);
    bool IsSynchronized(const std::string &networkId);

private:
    void TryTwice(const std::function<DistributedKv::Status()> &func) const;
    bool CheckKvStore();
    DistributedKv::Status GetKvStore();

    static std::mutex mutex_;
    static std::shared_ptr<DmsKvSyncE2E> instance_;
    const DistributedKv::AppId appId_ {DMS_BM_APP_ID};
    const DistributedKv::StoreId storeId_ {DISTRIBUTE_BM_STORE_ID};
    DistributedKv::DistributedKvDataManager dataManager_;
    std::shared_ptr<DistributedKv::SingleKvStore> kvStorePtr_;
    mutable std::mutex kvStorePtrMutex_;
    std::atomic<bool> isCfgDevices_ = false;
    std::map<std::string, bool> deviceSyncRecord_;
};
}  // namespace DistributedSchedule
}  // namespace OHOS
#endif  // DSCHED_SYNC_E2E_H
