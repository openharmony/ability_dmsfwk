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

#ifndef OHOS_DISTRIBUTED_BUNDLE_INFO_H
#define OHOS_DISTRIBUTED_BUNDLE_INFO_H

#include <string>
#include <unordered_set>

#include "dtbschedmgr_log.h"
#include "parcel.h"

namespace OHOS {
namespace DistributedSchedule {
struct PublicRecordsInfo : public Parcelable {
    uint16_t maxBundleNameId = 0;

    bool ReadFromParcel(Parcel &parcel);
    bool Marshalling(Parcel &parcel) const override;
    static PublicRecordsInfo *Unmarshalling(Parcel &parcel);
    std::string ToString() const;
    bool FromJsonString(const std::string &jsonString);
};

struct DmsAbilityInfo : public Parcelable {
    std::string abilityName;
    std::vector<std::string> continueType;
    std::vector<uint8_t> continueTypeId;
    std::string moduleName;
    std::unordered_set<std::string> continueBundleName;

    bool ReadFromParcel(Parcel &parcel);
    bool Marshalling(Parcel &parcel) const override;
    static DmsAbilityInfo *Unmarshalling(Parcel &parcel);
};

struct DmsBundleInfo : public Parcelable {
    uint32_t version = 1;
    std::string bundleName;
    uint32_t versionCode = 0;
    std::string versionName;
    uint32_t minCompatibleVersion = 0;
    uint32_t targetVersionCode = 0;
    uint32_t compatibleVersionCode = 0;
    std::string appId;
    bool enabled = true;
    // user related fields, assign when calling the get interface
    uint16_t bundleNameId = 0;
    // bundle update time
    int64_t updateTime = 0;
    std::string developerId;
    std::vector<DmsAbilityInfo> dmsAbilityInfos;
    std::vector<uint8_t> userIdArr;

    bool ReadFromParcel(Parcel &parcel);
    bool Marshalling(Parcel &parcel) const override;
    static DmsBundleInfo *Unmarshalling(Parcel &parcel);
    std::string ToString() const;
    bool FromJsonString(const std::string &jsonString);
};
} // namespace DistributedSchedule
} // namespace OHOS
#endif // OHOS_DISTRIBUTED_BUNDLE_INFO_H