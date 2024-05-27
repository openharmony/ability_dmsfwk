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

#include "mission/distributed_bundle_info.h"

#include "mission/json_util.h"
#include "nlohmann/json.hpp"
#include "parcel_helper.h"
#include "parcel_macro.h"
#include "string_ex.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "dmsBundleInfo";
const std::string JSON_KEY_VERSION = "version";
const std::string JSON_KEY_VERSION_CODE = "versionCode";
const std::string JSON_KEY_COMPATIBLE_VERSION_CODE = "compatibleVersionCode";
const std::string JSON_KEY_VERSION_NAME = "versionName";
const std::string JSON_KEY_MIN_COMPATIBLE_VERSION = "minCompatibleVersion";
const std::string JSON_KEY_TARGET_VERSION_CODE = "targetVersionCode";
const std::string JSON_KEY_APP_ID = "appId";
const std::string JSON_KEY_ENABLED = "enabled";
const std::string JSON_KEY_BUNDLE_NAME_ID = "bundleNameId";
const std::string JSON_KEY_UPDATE_TIME = "updateTime";
const std::string JSON_KEY_DMS_ABILITY_INFOS = "dmsAbilityInfos";
const std::string JSON_KEY_DMS_ABILITY_NAME = "abilityName";
const std::string JSON_KEY_DMS_CONTINUETYPE = "continueType";
const std::string JSON_KEY_DMS_CONTINUETYPEID = "continueTypeId";
const std::string JSON_KEY_DMS_USERID = "userIdArr";
const std::string JSON_KEY_DMS_MODULENAME = "moduleName";
}

bool DmsAbilityInfo::ReadFromParcel(Parcel &parcel)
{
    abilityName = Str16ToStr8(parcel.ReadString16());

    int32_t continueTypeSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, continueTypeSize);
    CONTAINER_SECURITY_VERIFY(parcel, continueTypeSize, &continueType);
    for (auto i = 0; i < continueTypeSize; i++) {
        continueType.emplace_back(Str16ToStr8(parcel.ReadString16()));
    }

    int32_t continueTypeIdSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, continueTypeIdSize);
    CONTAINER_SECURITY_VERIFY(parcel, continueTypeIdSize, &continueTypeId);
    for (auto i = 0; i < continueTypeIdSize; i++) {
        continueTypeId.emplace_back(parcel.ReadUint8());
    }
    moduleName = Str16ToStr8(parcel.ReadString16());
    return true;
}

bool DmsAbilityInfo::Marshalling(Parcel &parcel) const
{
    parcel.WriteString16(Str8ToStr16(abilityName));
    for (auto &ele : continueType) {
        parcel.WriteString16(Str8ToStr16(ele));
    }
    for (auto &ele : continueTypeId) {
        parcel.WriteUint8(ele);
    }
    parcel.WriteString16(Str8ToStr16(moduleName));
    return true;
}

DmsAbilityInfo *DmsAbilityInfo::Unmarshalling(Parcel &parcel)
{
    DmsAbilityInfo *info = new (std::nothrow) DmsAbilityInfo();
    if (info && !info->ReadFromParcel(parcel)) {
        APP_LOGW("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}

void to_json(nlohmann::json &jsonObject, const DmsAbilityInfo &dmsAbilityInfo)
{
    jsonObject = nlohmann::json {
        {JSON_KEY_DMS_ABILITY_NAME, dmsAbilityInfo.abilityName},
        {JSON_KEY_DMS_CONTINUETYPE, dmsAbilityInfo.continueType},
         {JSON_KEY_DMS_CONTINUETYPEID, dmsAbilityInfo.continueTypeId},
        {JSON_KEY_DMS_MODULENAME, dmsAbilityInfo.moduleName}
    };
}

void from_json(const nlohmann::json &jsonObject, DmsAbilityInfo &dmsAbilityInfo)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_DMS_ABILITY_NAME,
        dmsAbilityInfo.abilityName,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_DMS_CONTINUETYPE,
        dmsAbilityInfo.continueType,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::STRING);
    GetValueIfFindKey<std::vector<uint8_t>>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_DMS_CONTINUETYPEID,
        dmsAbilityInfo.continueTypeId,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::NUMBER);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_DMS_MODULENAME,
        dmsAbilityInfo.moduleName,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    if (parseResult != ERR_OK) {
        APP_LOGE("read module moduleInfo from jsonObject error, error code : %{public}d", parseResult);
    }
}

bool DmsBundleInfo::ReadFromParcel(Parcel &parcel)
{
    version = parcel.ReadUint32();
    versionCode = parcel.ReadUint32();
    compatibleVersionCode = parcel.ReadUint32();
    minCompatibleVersion = parcel.ReadUint32();
    targetVersionCode = parcel.ReadUint32();
    bundleName = Str16ToStr8(parcel.ReadString16());
    versionName = Str16ToStr8(parcel.ReadString16());
    appId = Str16ToStr8(parcel.ReadString16());
    enabled = parcel.ReadBool();
    bundleNameId = parcel.ReadUint16();
    updateTime = parcel.ReadInt64();
    uint32_t abilityInfosSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, abilityInfosSize);
    CONTAINER_SECURITY_VERIFY(parcel, abilityInfosSize, &dmsAbilityInfos);
    for (uint32_t i = 0; i < abilityInfosSize; i++) {
        std::unique_ptr<DmsAbilityInfo> dmsAbilityInfo(parcel.ReadParcelable<DmsAbilityInfo>());
        if (!dmsAbilityInfo) {
            APP_LOGE("ReadParcelable<DmsAbilityInfo> failed");
            return false;
        }
        dmsAbilityInfos.emplace_back(*dmsAbilityInfo);
    }
    uint32_t userIdArrSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, userIdArrSize);
    CONTAINER_SECURITY_VERIFY(parcel, userIdArrSize, &userIdArr);
    for (uint32_t i = 0; i < userIdArrSize; i++) {
        uint8_t userId = parcel.ReadUint8();
        userIdArr.emplace_back(userId);
    }
    return true;
}

bool DmsBundleInfo::Marshalling(Parcel &parcel) const
{
    parcel.WriteUint32(version);
    parcel.WriteUint32(versionCode);
    parcel.WriteUint32(compatibleVersionCode);
    parcel.WriteUint32(minCompatibleVersion);
    parcel.WriteUint32(targetVersionCode);
    parcel.WriteString16(Str8ToStr16(bundleName));
    parcel.WriteString16(Str8ToStr16(versionName));
    parcel.WriteString16(Str8ToStr16(appId));
    parcel.WriteBool(enabled);
    parcel.WriteUint16(bundleNameId);
    parcel.WriteInt64(updateTime);
    for (auto &dmsAbilityInfo : dmsAbilityInfos) {
        (parcel).WriteParcelable(&dmsAbilityInfo);
    }
    for (auto userId : userIdArr) {
        (parcel).WriteUint8(userId);
    }
    return true;
}

DmsBundleInfo *DmsBundleInfo::Unmarshalling(Parcel &parcel)
{
    DmsBundleInfo *info = new (std::nothrow) DmsBundleInfo();
    if (info && !info->ReadFromParcel(parcel)) {
        delete info;
        info = nullptr;
    }
    return info;
}

std::string DmsBundleInfo::ToString() const
{
    nlohmann::json jsonObject;
    jsonObject[JSON_KEY_VERSION] = version;
    jsonObject[AppExecFwk::Constants::BUNDLE_NAME] = bundleName;
    jsonObject[JSON_KEY_VERSION_CODE] = versionCode;
    jsonObject[JSON_KEY_VERSION_NAME] = versionName;
    jsonObject[JSON_KEY_COMPATIBLE_VERSION_CODE] = compatibleVersionCode;
    jsonObject[JSON_KEY_MIN_COMPATIBLE_VERSION] = minCompatibleVersion;
    jsonObject[JSON_KEY_TARGET_VERSION_CODE] = targetVersionCode;
    jsonObject[JSON_KEY_APP_ID] = appId;
    jsonObject[JSON_KEY_ENABLED] = enabled;
    jsonObject[JSON_KEY_BUNDLE_NAME_ID] = bundleNameId;
    jsonObject[JSON_KEY_UPDATE_TIME] = updateTime;
    jsonObject[JSON_KEY_DMS_ABILITY_INFOS] = dmsAbilityInfos;
    jsonObject[JSON_KEY_DMS_USERID] = userIdArr;
    return jsonObject.dump();
}

bool DmsBundleInfo::FromJsonString(const std::string &jsonString)
{
    nlohmann::json jsonObject = nlohmann::json::parse(jsonString, nullptr, false);
    if (jsonObject.is_discarded()) {
        return false;
    }

    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<uint32_t>(jsonObject, jsonObjectEnd, JSON_KEY_VERSION, version,
        JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject, jsonObjectEnd, AppExecFwk::Constants::BUNDLE_NAME, bundleName,
        JsonType::STRING, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<uint32_t>(jsonObject, jsonObjectEnd, JSON_KEY_VERSION_CODE, versionCode,
        JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<uint32_t>(jsonObject, jsonObjectEnd, JSON_KEY_COMPATIBLE_VERSION_CODE, compatibleVersionCode,
        JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject, jsonObjectEnd, JSON_KEY_VERSION_NAME, versionName,
        JsonType::STRING, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<uint32_t>(jsonObject, jsonObjectEnd, JSON_KEY_MIN_COMPATIBLE_VERSION, minCompatibleVersion,
        JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<uint32_t>(jsonObject, jsonObjectEnd, JSON_KEY_TARGET_VERSION_CODE, targetVersionCode,
        JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject, jsonObjectEnd, JSON_KEY_APP_ID, appId,
        JsonType::STRING, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject, jsonObjectEnd, JSON_KEY_ENABLED, enabled,
        JsonType::BOOLEAN, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<uint16_t>(jsonObject, jsonObjectEnd, JSON_KEY_BUNDLE_NAME_ID, bundleNameId,
        JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int64_t>(jsonObject, jsonObjectEnd, JSON_KEY_UPDATE_TIME, updateTime,
        JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<DmsAbilityInfo>>(jsonObject, jsonObjectEnd, JSON_KEY_DMS_ABILITY_INFOS,
        dmsAbilityInfos, JsonType::ARRAY, false, parseResult, ArrayType::OBJECT);
    GetValueIfFindKey<std::vector<uint8_t>>(jsonObject, jsonObjectEnd, JSON_KEY_DMS_USERID, userIdArr,
        JsonType::ARRAY, false, parseResult, ArrayType::NUMBER);
    return parseResult == ERR_OK;
}
}  // namespace DistributedSchedule
}  // namespace OHOS