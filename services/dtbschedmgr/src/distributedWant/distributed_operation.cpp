/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "distributed_operation.h"
#include "distributed_operation_builder.h"
#include "parcel_macro_base.h"

namespace OHOS {
namespace DistributedSchedule {
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

std::string DistributedOperation::GetAbilityName() const
{
    return abilityName_;
}

std::string DistributedOperation::GetAction() const
{
    return action_;
}

void DistributedOperation::SetBundleName(const std::string& bundleName)
{
    bundleName_ = bundleName;
}

std::string DistributedOperation::GetBundleName() const
{
    return bundleName_;
}

std::string DistributedOperation::GetDeviceId() const
{
    return deviceId_;
}

const std::vector<std::string>& DistributedOperation::GetEntities() const
{
    return entities_;
}

std::string DistributedOperation::GetModuleName() const
{
    return moduleName_;
}

void DistributedOperation::AddEntity(const std::string& entity)
{
    if (!HasEntity(entity)) {
        entities_.emplace_back(entity);
    }
}

void DistributedOperation::RemoveEntity(const std::string& entity)
{
    if (!entities_.empty()) {
        auto it = std::find(entities_.begin(), entities_.end(), entity);
        if (it != entities_.end()) {
            entities_.erase(it);
        }
    }
}

bool DistributedOperation::HasEntity(const std::string& entity) const
{
    return std::find(entities_.begin(), entities_.end(), entity) != entities_.end();
}

int DistributedOperation::CountEntities() const
{
    return entities_.size();
}

unsigned int DistributedOperation::GetFlags() const
{
    return flags_;
}

void DistributedOperation::SetFlags(unsigned int flags)
{
    flags_ = flags;
}

void DistributedOperation::AddFlags(unsigned int flags)
{
    flags_ |= flags;
}

void DistributedOperation::RemoveFlags(unsigned int flags)
{
    flags_ &= ~flags;
}

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

void DistributedOperation::SetUri(const Uri& uri)
{
    uri_ = uri;
}

Uri& DistributedOperation::GetUri(const Uri& uri)
{
    return uri_;
}

void DistributedOperation::SetAbilityName(const std::string& abilityname)
{
    abilityName_ = abilityname;
}

void DistributedOperation::SetDeviceId(const std::string& deviceid)
{
    deviceId_ = deviceid;
}

void DistributedOperation::SetAction(const std::string& action)
{
    action_ = action;
}

void DistributedOperation::SetEntities(const std::vector<std::string>& entities)
{
    entities_.clear();
    entities_ = entities;
}

void DistributedOperation::SetModuleName(const std::string& moduleName)
{
    moduleName_ = moduleName;
}
} // namespace DistributedSchedule
} // namespace OHOS