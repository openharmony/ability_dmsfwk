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

#ifndef OHOS_DISTRIBUTEDWANT_OPERATION_H
#define OHOS_DISTRIBUTEDWANT_OPERATION_H

#include <string>
#include "parcel.h"
#include "string_ex.h"
#include "uri.h"

namespace OHOS {
namespace DistributedSchedule {
class DistributedOperationBuilder;
class DistributedOperation : public Parcelable {
    friend class DistributedOperationBuilder;
    friend class DistributedWant;

public:
    DistributedOperation();
    ~DistributedOperation();
    DistributedOperation(const DistributedOperation& other);
    /**
     * @description: Obtains the value of the abilityName attribute included in this DistributedOperation.
     * @return Returns the ability name included in this DistributedOperation.
     */
    std::string GetAbilityName() const;

    /**
     * @description: Obtains the value of the action attribute included in this DistributedOperation.
     * @return Returns the action included in this DistributedOperation.
     */
    std::string GetAction() const;

    /**
     * @description: Obtains the value of the bundleName attribute included in this DistributedOperation.
     * @return Returns the bundle name included in this DistributedOperation.
     */
    std::string GetBundleName() const;

    /**
     * @description: Obtains the value of the deviceId attribute included in this DistributedOperation.
     * @return Returns the device ID included in this DistributedOperation.
     */
    std::string GetDeviceId() const;

    /**
     * @description: Obtains the value of the entities attribute included in this DistributedOperation.
     * @return Returns the entities included in this DistributedOperation.
     */
    const std::vector<std::string>& GetEntities() const;

    /**
     * @description: Obtains the value of the flags attribute included in this DistributedOperation.
     * @return Returns the flags included in this DistributedOperation.
     */
    unsigned int GetFlags() const;

    /**
     * @description: Obtains the value of the uri attribute included in this DistributedOperation.
     * @return Returns the URI included in this DistributedOperation.
     */
    OHOS::Uri GetUri() const;

    /**
     * @description: Obtains the description of the ModuleName object in the DistributedOperation.
     * @return Returns the ModuleName description in the DistributedOperation.
     */
    std::string GetModuleName() const;

    bool operator==(const DistributedOperation& other) const;
    DistributedOperation& operator=(const DistributedOperation& other);

    bool Marshalling(Parcel& parcel) const;
    static DistributedOperation* Unmarshalling(Parcel& parcel);

private:
    /**
     * @description: Sets a flag in a DistributedWant.
     * @param flags Indicates the flag to set.
     * @return Returns this DistributedWant object containing the flag.
     */
    void SetFlags(unsigned int flags);
    /**
     * @description: Adds a flag to a DistributedWant.
     * @param flags Indicates the flag to add.
     * @return Returns the DistributedWant object with the added flag.
     */
    void AddFlags(unsigned int flags);
    /**
     * @description: Removes the description of a flag from a DistributedWant.
     * @param flags Indicates the flag to remove.
     * @return Removes the description of a flag from a DistributedWant.
     */
    void RemoveFlags(unsigned int flags);

    /**
     * @description: Adds the description of an entity to a DistributedWant
     * @param entity Indicates the entity description to add
     * @return Returns this DistributedWant object containing the entity.
     */
    void AddEntity(const std::string& entity);

    /**
     * @description: Removes the description of an entity from a DistributedWant
     * @param entity Indicates the entity description to remove.
     * @return void
     */
    void RemoveEntity(const std::string& entity);

    /**
     * @description: Checks whether a DistributedWant contains the given entity
     * @param entity Indicates the entity to check
     * @return Returns true if the given entity is contained; returns false otherwise
     */
    bool HasEntity(const std::string& entity) const;

    /**
     * @description: Obtains the number of entities in a DistributedWant
     * @return Returns the entity quantity
     */
    int CountEntities() const;

    /**
     * @description: Sets a bundle name in this DistributedWant.
     * If a bundle name is specified in a DistributedWant, the DistributedWant will match only
     * the abilities in the specified bundle. You cannot use this method and
     * setPicker(ohos.aafwk.content.DistributedWant) on the same DistributedWant.
     * @param bundleName Indicates the bundle name to set.
     * @return Returns a DistributedWant object containing the specified bundle name.
     */
    void SetBundleName(const std::string& bundleName);

    /**
     * @description: Sets a uri in this DistributedOperation.
     * @param uri Indicates uri object to set.
     * @return -
     */
    void SetUri(const OHOS::Uri& uri);

    /**
     * @description: Gets a uri in this DistributedOperation.
     * @param uri Indicates uri object to set.
     * @return Returns a uri in this DistributedOperation.
     */
    OHOS::Uri& GetUri(const OHOS::Uri& uri);

    /**
     * @description: Sets the value of the abilityName attribute included in this DistributedOperation.
     * @return Returns the ability name included in this DistributedOperation.
     */
    void SetAbilityName(const std::string& abilityname);

    /**
     * @description: Sets the value of the deviceId attribute included in this DistributedOperation.
     * @param deviceid Indicates deviceid object to set.
     * @return -
     */
    void SetDeviceId(const std::string& deviceid);

    /**
     * @description: Sets the value of the action attribute included in this DistributedOperation.
     * @param deviceid Indicates deviceid object to set.
     * @return -
     */
    void SetAction(const std::string& action);

    /**
     * @description: Sets the entities of this DistributedOperation.
     * @param entities Indicates entities to set.
     * @return -
     */
    void SetEntities(const std::vector<std::string>& entities);

    /**
     * @description: Sets an ModuleName object in the DistributedOperation.
     * @param moduleName Indicates the ModuleName description.
     * @return Returns this DistributedOperation object containing the ModuleName.
     */
    void SetModuleName(const std::string& moduleName);

private:
    std::string abilityName_;
    std::string action_;
    std::string bundleName_;
    std::string deviceId_;
    std::string moduleName_;
    std::vector<std::string> entities_;
    unsigned int flags_;
    OHOS::Uri uri_;

    // no object in parcel
    static constexpr int VALUE_NULL = -1;
    // object exist in parcel
    static constexpr int VALUE_OBJECT = 1;

    bool ReadFromParcel(Parcel& parcel);
};
} // namespace DistributedSchedule
} // namespace OHOS
#endif // OHOS_DISTRIBUTEDWANT_OPERATION_H