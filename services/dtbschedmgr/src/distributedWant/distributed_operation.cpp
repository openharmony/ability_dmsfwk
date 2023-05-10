/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "parcel_macro_base.h"
#include "distributedWant/distributed_operation.h"
#include "distributedWant/distributed_operation_builder.h"

using namespace OHOS::AppExecFwk;
namespace OHOS {
namespace AAFwk {
DistributedOperation::DistributedOperation() : flags_(0), uri_("")
{
}

DistributedOperation::DistributedOperation(const DistributedOperation& other) : flags_(0), uri_(other.uri_.ToString())
{
    flags_ = other.flags_;
    action_ = other.action_;
    deviceId_ = other.deviceId_;
    entities_ = other.entities_;
    bundleName_ = other.bundleName_;
    abilityName_ = other.abilityName_;
    moduleName_ = other.moduleName_;
    entities_.clear();
}

DistributedOperation::~DistributedOperation()
{}

/**
 * @description: Obtains the value of the abilityName attribute included in this DistributedOperation.
 * @return Returns the ability name included in this DistributedOperation.
 */
std::string DistributedOperation::GetAbilityName() const
{
    return abilityName_;
}

/**
 * @description: Obtains the value of the action attribute included in this DistributedOperation.
 * @return Returns the action included in this DistributedOperation.
 */
std::string DistributedOperation::GetAction() const
{
    return action_;
}
/**
 * @description: Sets a bundle name in this Want.
 * If a bundle name is specified in a Want, the Want will match only
 * the abilities in the specified bundle. You cannot use this method and
 * setPicker(ohos.aafwk.content.Want) on the same Want.
 * @param bundleName Indicates the bundle name to set.
 * @return Returns a Want object containing the specified bundle name.
 */
void DistributedOperation::SetBundleName(const std::string& bundleName)
{
    bundleName_ = bundleName;
}
/**
 * @description: Obtains the value of the bundleName attribute included in this DistributedOperation.
 * @return Returns the bundle name included in this DistributedOperation.
 */
std::string DistributedOperation::GetBundleName() const
{
    return bundleName_;
}

/**
 * @description: Obtains the value of the deviceId attribute included in this DistributedOperation.
 * @return Returns the device ID included in this DistributedOperation.
 */
std::string DistributedOperation::GetDeviceId() const
{
    return deviceId_;
}

/**
 * @description: Obtains the value of the entities attribute included in this DistributedOperation.
 * @return Returns the entities included in this DistributedOperation.
 */
const std::vector<std::string>& DistributedOperation::GetEntities() const
{
    return entities_;
}

std::string DistributedOperation::GetModuleName() const
{
    return moduleName_;
}

/**
 * @description: Adds the description of an entity to a Want
 * @param entity Indicates the entity description to add
 * @return Returns this Want object containing the entity.
 */
void DistributedOperation::AddEntity(const std::string& entity)
{
    if (!HasEntity(entity)) {
        entities_.emplace_back(entity);
    }
}

/**
 * @description: Removes the description of an entity from a Want
 * @param entity Indicates the entity description to remove.
 * @return void
 */
void DistributedOperation::RemoveEntity(const std::string& entity)
{
    if (!entities_.empty()) {
        auto it = std::find(entities_.begin(), entities_.end(), entity);
        if (it != entities_.end()) {
            entities_.erase(it);
        }
    }
}

/**
 * @description: Checks whether a Want contains the given entity
 * @param entity Indicates the entity to check
 * @return Returns true if the given entity is contained; returns false otherwise
 */
bool DistributedOperation::HasEntity(const std::string& entity) const
{
    return std::find(entities_.begin(), entities_.end(), entity) != entities_.end();
}

/**
 * @description: Obtains the number of entities in a Want
 * @return Returns the entity quantity
 */
int DistributedOperation::CountEntities() const
{
    return entities_.size();
}
/**
 * @description: Obtains the value of the flags attribute included in this DistributedOperation.
 * @return Returns the flags included in this DistributedOperation.
 */
unsigned int DistributedOperation::GetFlags() const
{
    return flags_;
}

/**
 * @description: Sets a flag in a Want.
 * @param flags Indicates the flag to set.
 * @return Returns this Want object containing the flag.
 */
void DistributedOperation::SetFlags(unsigned int flags)
{
    flags_ = flags;
}
/**
 * @description: Adds a flag to a Want.
 * @param flags Indicates the flag to add.
 * @return Returns the Want object with the added flag.
 */
void DistributedOperation::AddFlags(unsigned int flags)
{
    flags_ |= flags;
}

/**
 * @description: Removes the description of a flag from a Want.
 * @param flags Indicates the flag to remove.
 * @return Removes the description of a flag from a Want.
 */
void DistributedOperation::RemoveFlags(unsigned int flags)
{
    flags_ &= ~flags;
}

/**
 * @description: Obtains the value of the uri attribute included in this DistributedOperation.
 * @return Returns the URI included in this DistributedOperation.
 */
Uri DistributedOperation::GetUri() const
{
    return uri_;
}

bool DistributedOperation::operator==(const DistributedOperation& other) const
{
    if (abilityName_ != other.abilityName_) {
        return false;
    }
    if (action_ != other.action_) {
        return false;
    }
    if (bundleName_ != other.bundleName_) {
        return false;
    }
    if (deviceId_ != other.deviceId_) {
        return false;
    }
    if (moduleName_ != other.moduleName_) {
        return false;
    }

    size_t entitiesCount = entities_.size();
    size_t otherEntitiesCount = other.entities_.size();
    if (entitiesCount != otherEntitiesCount) {
        return false;
    } else {
        for (size_t i = 0; i < entitiesCount; i++) {
            if (entities_[i] != other.entities_[i]) {
                return false;
            }
        }
    }
    if (flags_ != other.flags_) {
        return false;
    }
    if (uri_.ToString() != other.uri_.ToString()) {
        return false;
    }
    return true;
}

DistributedOperation& DistributedOperation::operator=(const DistributedOperation& other)
{
    if (this != &other) {
        uri_ = other.uri_;
        flags_ = other.flags_;
        action_ = other.action_;
        deviceId_ = other.deviceId_;
        entities_ = other.entities_;
        bundleName_ = other.bundleName_;
        abilityName_ = other.abilityName_;
        moduleName_ = other.moduleName_;
    }
    return *this;
}

bool DistributedOperation::Marshalling(Parcel& parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(abilityName_));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(action_));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(bundleName_));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(deviceId_));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(StringVector, parcel, entities_);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, flags_);

    Uri uri("");
    if (uri_ == uri) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, VALUE_NULL);
    } else {
        if (!parcel.WriteInt32(VALUE_OBJECT)) {
            return false;
        }
        if (!parcel.WriteParcelable(&uri_)) {
            return false;
        }
    }
    return true;
}

DistributedOperation* DistributedOperation::Unmarshalling(Parcel& parcel)
{
    DistributedOperation* operation = new (std::nothrow) DistributedOperation();
    if (operation != nullptr && !operation->ReadFromParcel(parcel)) {
        delete operation;
        operation = nullptr;
    }

    return operation;
}

bool DistributedOperation::ReadFromParcel(Parcel& parcel)
{
    std::u16string readString16;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, readString16);
    abilityName_ = Str16ToStr8(readString16);
    readString16.clear();

    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, readString16);
    action_ = Str16ToStr8(readString16);
    readString16.clear();

    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, readString16);
    bundleName_ = Str16ToStr8(readString16);
    readString16.clear();

    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, readString16);
    deviceId_ = Str16ToStr8(readString16);
    readString16.clear();

    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(StringVector, parcel, &entities_);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, flags_);

    // uri_
    int32_t empty = VALUE_NULL;
    if (!parcel.ReadInt32(empty)) {
        return false;
    }

    if (empty == VALUE_OBJECT) {
        auto uri = parcel.ReadParcelable<Uri>();
        if (uri != nullptr) {
            uri_ = *uri;
            delete uri;
            uri = nullptr;
        } else {
            return false;
        }
    }
    return true;
}

/**
 * @description: Sets a uri in this operation.
 * @param uri Indicates uri object to set.
 * @return -
 */
void DistributedOperation::SetUri(const Uri& uri)
{
    uri_ = uri;
}

/**
 * @description: Returns a uri in this operation.
 * @param uri Indicates uri object to set.
 * @return Returns a uri in this operation.
 */
Uri& DistributedOperation::GetUri(const Uri& uri)
{
    return uri_;
}

/**
 * @description: Sets the value of the abilityName attribute included in this DistributedOperation.
 * @param abilityname
 * @return -
 */
void DistributedOperation::SetAbilityName(const std::string& abilityname)
{
    abilityName_ = abilityname;
}
/**
 * @description: Sets the value of the deviceId attribute included in this DistributedOperation.
 * @param  deviceid
 * @return -
 */
void DistributedOperation::SetDeviceId(const std::string& deviceid)
{
    deviceId_ = deviceid;
}

/**
 * @description: Sets the value of the action attribute included in this DistributedOperation.
 * @param deviceid Indicates deviceid object to set.
 * @return -
 */
void DistributedOperation::SetAction(const std::string& action)
{
    action_ = action;
}

/**
 * @description: Sets the entities of this DistributedOperation.
 * @param entities Indicates entities to set.
 * @return -
 */
void DistributedOperation::SetEntities(const std::vector<std::string>& entities)
{
    entities_.clear();
    entities_ = entities;
}

void DistributedOperation::SetModuleName(const std::string& moduleName)
{
    moduleName_ = moduleName;
}

void DistributedOperation::DumpInfo(int level) const
{
    ABILITYBASE_LOGI("===DistributedOperation::abilityName_ %{public}s =============", abilityName_.c_str());
    ABILITYBASE_LOGI("===DistributedOperation::action_ %{public}s =============", action_.c_str());
    ABILITYBASE_LOGI("===DistributedOperation::bundleName_ %{public}s =============", bundleName_.c_str());
    ABILITYBASE_LOGI("===DistributedOperation::moduleName_ %{public}s =============", moduleName_.c_str());
    size_t entities_count = entities_.size();
    ABILITYBASE_LOGI("===DistributedOperation::entities_: count %{public}u =============", (uint32_t)entities_count);
    for (size_t i = 0; i < entities_count; i++) {
        ABILITYBASE_LOGI("=DistributedOperation::entities_[%{public}u]: %{public}s =============", (uint32_t)i,
            entities_[i].c_str());
    }
    ABILITYBASE_LOGI("===DistributedOperation::flags_ %{public}ud =============", flags_);
    ABILITYBASE_LOGI("===DistributedOperation::uri_ %{public}s =============", uri_.ToString().c_str());
}
}  // namespace AAFwk
}  // namespace OHOS