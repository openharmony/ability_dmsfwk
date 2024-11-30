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

#ifndef OHOS_DISTRIBUTEDWANT_WANT_V2_H
#define OHOS_DISTRIBUTEDWANT_WANT_V2_H

#include <algorithm>
#include <string>
#include <vector>
#include "distributedWant/distributed_operation.h"
#include "want_params.h"
#include "element_name.h"
#include "nlohmann/json.hpp"
#include "parcel.h"
#include "uri.h"
#include "want.h"

using DistributedOperation = OHOS::DistributedSchedule::DistributedOperation;

namespace OHOS {
namespace DistributedSchedule {
class DistributedWantV2 final : public Parcelable {
public:
    /**
     * Indicates the grant to perform read operations on the URI.
     */
    static constexpr unsigned int FLAG_AUTH_READ_URI_PERMISSION = 0x00000001;
    /**
     * Indicates the grant to perform write operations on the URI.
     */
    static constexpr unsigned int FLAG_AUTH_WRITE_URI_PERMISSION = 0x00000002;
    /**
     * Returns the result to the source ability.
     */
    static constexpr unsigned int FLAG_ABILITY_FORWARD_RESULT = 0x00000004;
    /**
     * Determines whether an ability on the local device can be migrated to a remote device.
     */
    static constexpr unsigned int FLAG_ABILITY_CONTINUATION = 0x00000008;
    /**
     * Specifies whether a component does not belong to OHOS.
     */
    static constexpr unsigned int FLAG_NOT_OHOS_COMPONENT = 0x00000010;
    /**
     * Specifies whether an ability is started.
     */
    static constexpr unsigned int FLAG_ABILITY_FORM_ENABLED = 0x00000020;
    /**
     * Indicates the grant for possible persisting on the URI.
     */
    static constexpr unsigned int FLAG_AUTH_PERSISTABLE_URI_PERMISSION = 0x00000040;
    /**
     * Returns the result to the source ability slice.
     */
    static constexpr unsigned int FLAG_AUTH_PREFIX_URI_PERMISSION = 0x00000080;
    /**
     * Supports multi-device startup in the distributed scheduling system.
     */
    static constexpr unsigned int FLAG_ABILITYSLICE_MULTI_DEVICE = 0x00000100;
    /**
     * Indicates that an ability using the Service template is started regardless of whether the host application has
     * been started.
     */
    static constexpr unsigned int FLAG_START_FOREGROUND_ABILITY = 0x00000200;

    /**
     * Indicates the continuation is reversible.
     */
    static constexpr unsigned int FLAG_ABILITY_CONTINUATION_REVERSIBLE = 0x00000400;

    /**
     * Install the specified ability if it's not installed.
     */
    static constexpr unsigned int FLAG_INSTALL_ON_DEMAND = 0x00000800;
    /**
     * Returns the result to the source ability slice.
     */
    static constexpr unsigned int FLAG_ABILITYSLICE_FORWARD_RESULT = 0x04000000;
    /**
     * Install the specifiedi ability with background mode if it's not installed.
     */
    static constexpr unsigned int FLAG_INSTALL_WITH_BACKGROUND_MODE = 0x80000000;

    /**
     * @description:  Default construcotr of DistributedWantV2 class, which is used to initialzie flags and URI.
     * @param None
     * @return None
     */
    DistributedWantV2();

    /**
     * @description: Default deconstructor of DistributedWantV2 class
     * @param None
     * @return None
     */
    ~DistributedWantV2();

    /**
     * @description: Copy construcotr of DistributedWantV2 class, which is used to initialzie flags, URI, etc.
     * @param want the source instance of DistributedWantV2.
     * @return None
     */
    DistributedWantV2(const DistributedWantV2& want);
    DistributedWantV2& operator=(const DistributedWantV2&);
    DistributedWantV2(const AAFwk::Want& want);

    /**
     * @description: Sets a flag in a DistributedWantV2.
     * @param flags Indicates the flag to set.
     * @return Returns this DistributedWantV2 object containing the flag.
     */
    DistributedWantV2& SetFlags(unsigned int flags);

    /**
     * @description: Obtains the description of flags in a DistributedWantV2.
     * @return Returns the flag description in the DistributedWantV2.
     */
    unsigned int GetFlags() const;

    /**
     * @description: Adds a flag to a DistributedWantV2.
     * @param flags Indicates the flag to add.
     * @return Returns the DistributedWantV2 object with the added flag.
     */
    DistributedWantV2& AddFlags(unsigned int flags);

    /**
     * @description: Removes the description of a flag from a DistributedWantV2.
     * @param flags Indicates the flag to remove.
     * @return Removes the description of a flag from a DistributedWantV2.
     */
    void RemoveFlags(unsigned int flag);

    /**
     * @description: Sets the bundleName and abilityName attributes for this DistributedWantV2 object.
     * @param bundleName Indicates the bundleName to set for the operation attribute in the DistributedWantV2.
     * @param abilityName Indicates the abilityName to set for the operation attribute in the DistributedWantV2.
     * @return Returns this DistributedWantV2 object that contains the specified bundleName and abilityName attributes.
     */
    DistributedWantV2& SetElementName(const std::string& bundleName, const std::string& abilityName);

    /**
     * @description: Sets the bundleName and abilityName attributes for this DistributedWantV2 object.
     * @param deviceId Indicates the deviceId to set for the operation attribute in the DistributedWantV2.
     * @param bundleName Indicates the bundleName to set for the operation attribute in the DistributedWantV2.
     * @param abilityName Indicates the abilityName to set for the operation attribute in the DistributedWantV2.
     * @return Returns this DistributedWantV2 object that contains the specified bundleName and abilityName attributes.
     */
    DistributedWantV2& SetElementName(
        const std::string& deviceId, const std::string& bundleName, const std::string& abilityName);

    /**
     * @description: Sets an ElementName object in a DistributedWantV2.
     * @param element Indicates the ElementName description.
     * @return Returns this DistributedWantV2 object containing the ElementName
     */
    DistributedWantV2& SetElement(const OHOS::AppExecFwk::ElementName& element);

    /**
     * @description: Obtains the description of the ElementName object in a DistributedWantV2.
     * @return Returns the ElementName description in the DistributedWantV2.
     */
    OHOS::AppExecFwk::ElementName GetElement() const;

    /**
     * @description: Obtains the description of a URI in a DistributedWantV2.
     * @return Returns the URI description in the DistributedWantV2.
     */
    OHOS::Uri GetUri() const;

    /**
     * @description: Obtains the string representation of the URI in this DistributedWantV2.
     * @return Returns the string of the URI.
     */
    std::string GetUriString() const;

    /**
     * @description: Sets the description of a URI in a DistributedWantV2.
     * @param uri Indicates the URI description.
     * @return Returns this DistributedWantV2 object containing the URI.
     */
    DistributedWantV2& SetUri(const std::string& uri);

    /**
     * @description: Sets the description of a URI in a DistributedWantV2.
     * @param uri Indicates the URI description.
     * @return Returns this DistributedWantV2 object containing the URI.
     */
    DistributedWantV2& SetUri(const OHOS::Uri& uri);

    /**
     * @description: Sets the description of a URI and a type in this DistributedWantV2.
     * @param uri Indicates the URI description.
     * @param type Indicates the type description.
     * @return Returns the DistributedWantV2 object containing the URI and the type by setting.
     */
    DistributedWantV2& SetUriAndType(const OHOS::Uri& uri, const std::string& type);

    /**
     * @description: Formats a specified URI.
     * This method uses the Uri.getLowerCaseScheme() method to format a URI and then saves
     * the formatted URI to this DistributedWantV2 object.
     * @param uri Indicates the string of URI to format.
     * @return Returns this DistributedWantV2 object that contains the formatted uri attribute.
     */
    DistributedWantV2& FormatUri(const std::string& uri);

    /**
     * @description: Formats a specified URI.
     * This method uses the Uri.getLowerCaseScheme() method to format a URI and then saves
     * the formatted URI to this DistributedWantV2 object.
     * @param uri Indicates the URI to format.
     * @return Returns this DistributedWantV2 object that contains the formatted URI attribute.
     */
    DistributedWantV2& FormatUri(const OHOS::Uri& uri);

    /**
     * @description: Obtains the description of an action in a DistributedWantV2.
     * @return Returns a DistributedWantV2 object that contains the action description.
     */
    std::string GetAction() const;

    /**
     * @description: Sets the description of an action in a DistributedWantV2.
     * @param action Indicates the action description to set.
     * @return Returns a DistributedWantV2 object that contains the action description.
     */
    DistributedWantV2& SetAction(const std::string& action);

    /**
     * @description: Obtains the name of the specified bundle in a DistributedWantV2.
     * @return Returns the specified bundle name in the DistributedWantV2.
     */
    std::string GetBundle() const;

    /**
     * @description: Sets a bundle name in this DistributedWantV2.
     * If a bundle name is specified in a DistributedWantV2, the DistributedWantV2 will match only
     * the abilities in the specified bundle. You cannot use this method and
     * setPicker(ohos.aafwk.content.DistributedWantV2) on the same DistributedWantV2.
     * @param bundleName Indicates the bundle name to set.
     * @return Returns a DistributedWantV2 object containing the specified bundle name.
     */
    DistributedWantV2& SetBundle(const std::string& bundleName);

    /**
     * @description: Obtains the description of all entities in a DistributedWantV2
     * @return Returns a set of entities
     */
    const std::vector<std::string>& GetEntities() const;

    /**
     * @description: Adds the description of an entity to a DistributedWantV2
     * @param entity Indicates the entity description to add
     * @return {DistributedWantV2} Returns this DistributedWantV2 object containing the entity.
     */
    DistributedWantV2& AddEntity(const std::string& entity);

    /**
     * @description: Removes the description of an entity from a DistributedWantV2
     * @param entity Indicates the entity description to remove.
     * @return void
     */
    void RemoveEntity(const std::string& entity);

    /**
     * @description: Checks whether a DistributedWantV2 contains the given entity
     * @param entity Indicates the entity to check
     * @return Returns true if the given entity is contained; returns false otherwise
     */
    bool HasEntity(const std::string& key) const;

    /**
     * @description: Obtains the number of entities in a DistributedWantV2
     * @return Returns the entity quantity
     */
    int CountEntities();

    /**
     * @description: Obtains the description of the URI scheme in this DistributedWantV2.
     * @return Returns the URI scheme description in this DistributedWantV2.
     */
    const std::string GetScheme() const;

    /**
     * @description: Obtains the description of the type in this DistributedWantV2
     * @return Returns the type description in this DistributedWantV2
     */
    std::string GetType() const;

    /**
     * @description: Sets the description of a type in this DistributedWantV2
     * @param type Indicates the type description
     * @return Returns this DistributedWantV2 object containing the type
     */
    DistributedWantV2& SetType(const std::string& type);

    /**
     * @description: clear the specific DistributedWantV2 object.
     * @param want Indicates the DistributedWantV2 to clear
     */
    static void ClearWant(DistributedWantV2* want);

    /**
     * @description: Obtains the description of the WantParams object in a DistributedWantV2
     * @return Returns the WantParams description in the DistributedWantV2
     */
    const AAFwk::WantParams& GetParams() const;

    /**
     * @description: Sets a WantParams object in a want.
     * @param wantParams  Indicates the WantParams description.
     * @return Returns this want object containing the WantParams.
     */
    DistributedWantV2& SetParams(const AAFwk::WantParams& wantParams);

    /**
     * @description: Obtains a bool-type value matching the given key.
     * @param key   Indicates the key of WantParams.
     * @param defaultValue  Indicates the default bool-type value.
     * @return Returns the bool-type value of the parameter matching the given key;
     * returns the default value if the key does not exist.
     */
    bool GetBoolParam(const std::string& key, bool defaultValue) const;

    /**
     * @description: Obtains a bool-type array matching the given key.
     * @param key   Indicates the key of WantParams.
     * @return Returns the bool-type array of the parameter matching the given key;
     * returns null if the key does not exist.
     */
    std::vector<bool> GetBoolArrayParam(const std::string& key) const;

    /**
     * @description: Sets a parameter value of the IRemoteObject type.
     * @param key   Indicates the key matching the parameter.
     * @param value Indicates the IRemoteObject value of the parameter.
     * @return Returns this want object containing the parameter value.
     */
    DistributedWantV2& SetParam(const std::string& key, const sptr<IRemoteObject>& remoteObject);

    /**
     * @description: Sets a parameter value of the boolean type.
     * @param key   Indicates the key matching the parameter.
     * @param value Indicates the boolean value of the parameter.
     * @return Returns this DistributedWantV2 object containing the parameter value.
     */
    DistributedWantV2& SetParam(const std::string& key, bool value);

    /**
     * @description: Sets a parameter value of the boolean array type.
     * @param key   Indicates the key matching the parameter.
     * @param value Indicates the boolean array of the parameter.
     * @return Returns this DistributedWantV2 object containing the parameter value.
     */
    DistributedWantV2& SetParam(const std::string& key, const std::vector<bool>& value);

    /**
     * @description: Obtains a byte-type value matching the given key.
     * @param key   Indicates the key of WantParams.
     * @param defaultValue  Indicates the default byte-type value.
     * @return Returns the byte-type value of the parameter matching the given key;
     * returns the default value if the key does not exist.
     */
    AAFwk::byte GetByteParam(const std::string& key, AAFwk::byte defaultValue) const;

    /**
     * @description: Obtains a byte-type array matching the given key.
     * @param key   Indicates the key of WantParams.
     * @return Returns the byte-type array of the parameter matching the given key;
     * returns null if the key does not exist.
     */
    std::vector<AAFwk::byte> GetByteArrayParam(const std::string& key) const;

    /**
     * @description: Sets a parameter value of the byte type.
     * @param key   Indicates the key matching the parameter.
     * @param value Indicates the byte-type value of the parameter.
     * @return Returns this DistributedWantV2 object containing the parameter value.
     */
    DistributedWantV2& SetParam(const std::string& key, AAFwk::byte value);

    /**
     * @description: Sets a parameter value of the byte array type.
     * @param key   Indicates the key matching the parameter.
     * @param value Indicates the byte array of the parameter.
     * @return Returns this DistributedWantV2 object containing the parameter value.
     */
    DistributedWantV2& SetParam(const std::string& key, const std::vector<AAFwk::byte>& value);

    /**
     * @description: Obtains a char value matching the given key.
     * @param key   Indicates the key of wnatParams.
     * @param value Indicates the default char value.
     * @return Returns the char value of the parameter matching the given key;
     * returns the default value if the key does not exist.
     */
    AAFwk::zchar GetCharParam(const std::string& key, AAFwk::zchar defaultValue) const;

    /**
     * @description: Obtains a char array matching the given key.
     * @param key   Indicates the key of WantParams.
     * @return Returns the char array of the parameter matching the given key;
     * returns null if the key does not exist.
     */
    std::vector<AAFwk::zchar> GetCharArrayParam(const std::string& key) const;

    /**
     * @description: Sets a parameter value of the char type.
     * @param key   Indicates the key of WantParams.
     * @param value Indicates the char value of the parameter.
     * @return Returns this DistributedWantV2 object containing the parameter value.
     */
    DistributedWantV2& SetParam(const std::string& key, AAFwk::zchar value);

    /**
     * @description: Sets a parameter value of the char array type.
     * @param key   Indicates the key of WantParams.
     * @param value Indicates the char array of the parameter.
     * @return Returns this DistributedWantV2 object containing the parameter value.
     */
    DistributedWantV2& SetParam(const std::string& key, const std::vector<AAFwk::zchar>& value);

    /**
     * @description: Obtains an int value matching the given key.
     * @param key   Indicates the key of WantParams.
     * @param value Indicates the default int value.
     * @return Returns the int value of the parameter matching the given key;
     * returns the default value if the key does not exist.
     */
    int GetIntParam(const std::string& key, int defaultValue) const;

    /**
     * @description: Obtains an int array matching the given key.
     * @param key   Indicates the key of WantParams.
     * @return Returns the int array of the parameter matching the given key;
     * returns null if the key does not exist.
     */
    std::vector<int> GetIntArrayParam(const std::string& key) const;

    /**
     * @description: Sets a parameter value of the int type.
     * @param key   Indicates the key matching the parameter.
     * @param value Indicates the int value of the parameter.
     * @return Returns this DistributedWantV2 object containing the parameter value.
     */
    DistributedWantV2& SetParam(const std::string& key, int value);

    /**
     * @description: Sets a parameter value of the int array type.
     * @param key   Indicates the key matching the parameter.
     * @param value Indicates the int array of the parameter.
     * @return Returns this DistributedWantV2 object containing the parameter value.
     */
    DistributedWantV2& SetParam(const std::string& key, const std::vector<int>& value);

    /**
     * @description: Obtains a double value matching the given key.
     * @param key   Indicates the key of WantParams.
     * @param defaultValue  Indicates the default double value.
     * @return Returns the double value of the parameter matching the given key;
     * returns the default value if the key does not exist.
     */
    double GetDoubleParam(const std::string& key, double defaultValue) const;

    /**
     * @description: Obtains a double array matching the given key.
     * @param key   Indicates the key of WantParams.
     * @return Returns the double array of the parameter matching the given key;
     * returns null if the key does not exist.
     */
    std::vector<double> GetDoubleArrayParam(const std::string& key) const;

    /**
     * @description: Sets a parameter value of the double type.
     * @param key   Indicates the key matching the parameter.
     * @param value Indicates the int value of the parameter.
     * @return Returns this DistributedWantV2 object containing the parameter value.
     */
    DistributedWantV2& SetParam(const std::string& key, double value);

    /**
     * @description: Sets a parameter value of the double array type.
     * @param key   Indicates the key matching the parameter.
     * @param value Indicates the double array of the parameter.
     * @return Returns this DistributedWantV2 object containing the parameter value.
     */
    DistributedWantV2& SetParam(const std::string& key, const std::vector<double>& value);

    /**
     * @description: Obtains a float value matching the given key.
     * @param key   Indicates the key of wnatParams.
     * @param value Indicates the default float value.
     * @return Returns the float value of the parameter matching the given key;
     * returns the default value if the key does not exist.
     */
    float GetFloatParam(const std::string& key, float defaultValue) const;

    /**
     * @description: Obtains a float array matching the given key.
     * @param key Indicates the key of WantParams.
     * @return Obtains a float array matching the given key.
     */
    std::vector<float> GetFloatArrayParam(const std::string& key) const;

    /**
     * @description: Sets a parameter value of the float type.
     * @param key Indicates the key matching the parameter.
     * @param value Indicates the byte-type value of the parameter.
     * @return Returns this DistributedWantV2 object containing the parameter value.
     */
    DistributedWantV2& SetParam(const std::string& key, float value);

    /**
     * @description: Sets a parameter value of the float array type.
     * @param key Indicates the key matching the parameter.
     * @param value Indicates the byte-type value of the parameter.
     * @return Returns this DistributedWantV2 object containing the parameter value.
     */
    DistributedWantV2& SetParam(const std::string& key, const std::vector<float>& value);

    /**
     * @description: Obtains a long value matching the given key.
     * @param key Indicates the key of WantParams.
     * @param value Indicates the default long value.
     * @return Returns the long value of the parameter matching the given key;
     * returns the default value if the key does not exist.
     */
    long GetLongParam(const std::string& key, long defaultValue) const;

    /**
     * @description: Obtains a long array matching the given key.
     * @param key Indicates the key of WantParams.
     * @return Returns the long array of the parameter matching the given key;
     * returns null if the key does not exist.
     */
    std::vector<long> GetLongArrayParam(const std::string& key) const;

    DistributedWantV2& SetParam(const std::string& key, long long value);

    /**
     * @description: Sets a parameter value of the long type.
     * @param key Indicates the key matching the parameter.
     * @param value Indicates the byte-type value of the parameter.
     * @return Returns this DistributedWantV2 object containing the parameter value.
     */
    DistributedWantV2& SetParam(const std::string& key, long value);

    /**
     * @description: Sets a parameter value of the long array type.
     * @param key Indicates the key matching the parameter.
     * @param value Indicates the byte-type value of the parameter.
     * @return Returns this DistributedWantV2 object containing the parameter value.
     */
    DistributedWantV2& SetParam(const std::string& key, const std::vector<long>& value);

    /**
     * @description: a short value matching the given key.
     * @param key Indicates the key of WantParams.
     * @param defaultValue Indicates the default short value.
     * @return Returns the short value of the parameter matching the given key;
     * returns the default value if the key does not exist.
     */
    short GetShortParam(const std::string& key, short defaultValue) const;

    /**
     * @description: Obtains a short array matching the given key.
     * @param key Indicates the key of WantParams.
     * @return Returns the short array of the parameter matching the given key;
     * returns null if the key does not exist.
     */
    std::vector<short> GetShortArrayParam(const std::string& key) const;

    /**
     * @description: Sets a parameter value of the short type.
     * @param key Indicates the key matching the parameter.
     * @param value Indicates the byte-type value of the parameter.
     * @return Returns this DistributedWantV2 object containing the parameter value.
     */
    DistributedWantV2& SetParam(const std::string& key, short value);

    /**
     * @description: Sets a parameter value of the short array type.
     * @param key Indicates the key matching the parameter.
     * @param value Indicates the byte-type value of the parameter.
     * @return Returns this DistributedWantV2 object containing the parameter value.
     */
    DistributedWantV2& SetParam(const std::string& key, const std::vector<short>& value);

    /**
     * @description: Obtains a string value matching the given key.
     * @param key Indicates the key of WantParams.
     * @return Returns the string value of the parameter matching the given key;
     * returns null if the key does not exist.
     */
    std::string GetStringParam(const std::string& key) const;

    /**
     * @description: Obtains a string array matching the given key.
     * @param key Indicates the key of WantParams.
     * @return Returns the string array of the parameter matching the given key;
     * returns null if the key does not exist.
     */
    std::vector<std::string> GetStringArrayParam(const std::string& key) const;

    /**
     * @description: Sets a parameter value of the string type.
     * @param key Indicates the key matching the parameter.
     * @param value Indicates the byte-type value of the parameter.
     * @return Returns this DistributedWantV2 object containing the parameter value.
     */
    DistributedWantV2& SetParam(const std::string& key, const std::string& value);

    /**
     * @description: Sets a parameter value of the string array type.
     * @param key Indicates the key matching the parameter.
     * @param value Indicates the byte-type value of the parameter.
     * @return Returns this DistributedWantV2 object containing the parameter value.
     */
    DistributedWantV2& SetParam(const std::string& key, const std::vector<std::string>& value);

    /**
     * @description: Checks whether a DistributedWantV2 contains the parameter matching a given key.
     * @param key Indicates the key.
     * @return Returns true if the DistributedWantV2 contains the parameter; returns false otherwise.
     */
    bool HasParameter(const std::string& key) const;

    /**
     * @description: Replaces parameters in this Want object with those in the given WantParams object.
     * @param wantParams Indicates the WantParams object containing the new parameters.
     * @return Returns this Want object containing the new parameters.
     */
    DistributedWantV2* ReplaceParams(AAFwk::WantParams& wantParams);

    /**
     * @description: Replaces parameters in this DistributedWantV2 object with those in the given Want object.
     * @param want Indicates the DistributedWantV2 object containing the new parameters.
     * @return Returns this DistributedWantV2 object containing the new parameters.
     */
    DistributedWantV2* ReplaceParams(DistributedWantV2& want);

    /**
     * @description: Removes the parameter matching the given key.
     * @param key Indicates the key matching the parameter to be removed.
     */
    void RemoveParam(const std::string& key);

    /**
     * @description: Gets the description of an operation in a DistributedWantV2.
     * @return Returns the operation included in this DistributedWantV2.
     */
    DistributedOperation GetOperation() const;

    /**
     * @description: Sets the description of an operation in a DistributedWantV2.
     * @param operation Indicates the operation description.
     */
    void SetOperation(const DistributedOperation& operation);

    /**
     * @description: Sets the description of an operation in a DistributedWantV2.
     * @param want Indicates the DistributedWantV2 object to compare.
     * @return Returns true if the operation components of the two objects are equal; returns false otherwise.
     */
    bool OperationEquals(const DistributedWantV2& want);

    /**
     * @description: Marshals a DistributedWantV2 into a Parcel.
     * Fields in the DistributedWantV2 are marshalled separately.
     * @param parcel Indicates the Parcel object for marshalling.
     * @return Returns true if the marshalling is successful; returns false otherwise.
     */
    virtual bool Marshalling(Parcel& parcel) const;

    /**
     * @description: Unmarshals a DistributedWantV2 from a Parcel.
     * Fields in the DistributedWantV2 are unmarshalled separately.
     * If any field fails to be unmarshalled, false is returned.
     * @param parcel Indicates the Parcel object for unmarshalling.
     * @return Returns true if the unmarshalling is successful; returns false otherwise.
     */
    static DistributedWantV2* Unmarshalling(Parcel& parcel);

    std::string ToString() const;

    static DistributedWantV2* FromString(std::string& string);

    std::shared_ptr<AAFwk::Want> ToWant();

    DistributedWantV2& SetDeviceId(const std::string& deviceId);
public:
    static const std::string ACTION_PLAY;
    static const std::string ACTION_HOME;
    static const std::string ENTITY_HOME;
    static const std::string ENTITY_VIDEO;
    static const std::string FLAG_HOME_INTENT_FROM_SYSTEM;
    static const std::string ENTITY_MUSIC;
    static const std::string ENTITY_EMAIL;
    static const std::string ENTITY_CONTACTS;
    static const std::string ENTITY_MAPS;
    static const std::string ENTITY_BROWSER;
    static const std::string ENTITY_CALENDAR;
    static const std::string ENTITY_MESSAGING;
    static const std::string ENTITY_FILES;
    static const std::string ENTITY_GALLERY;
    static unsigned int FLAG_ABILITY_NEW_MISSION;
    static unsigned int FLAG_ABILITY_CLEAR_MISSION;
    static constexpr int HEX_STRING_BUF_LEN = 36;
    static constexpr int HEX_STRING_LEN = 10;
    static const std::string PARAM_RESV_WINDOW_MODE;
    static const std::string PARAM_RESV_DISPLAY_ID;
    static const std::string PARAM_RESV_CALLER_TOKEN;
    static const std::string PARAM_RESV_CALLER_UID;
    static const std::string PARAM_RESV_CALLER_PID;

private:
    AAFwk::WantParams parameters_;
    DistributedOperation operation_;

    static const std::string OCT_EQUALSTO;
    static const std::string OCT_SEMICOLON;
    static const std::string MIME_TYPE;
    static const std::string WANT_HEADER;
    static constexpr int VALUE_NULL = -1;
    static constexpr int VALUE_OBJECT = 1;

private:
    bool ReadFromParcel(Parcel& parcel);
    OHOS::Uri GetLowerCaseScheme(const OHOS::Uri& uri);
    nlohmann::json ToJson() const;
    bool ReadFromJson(nlohmann::json& wantJson);
    bool CanReadFromJson(nlohmann::json& wantJson);
    bool MarshallingWriteEntities(Parcel& parcel) const;
    bool MarshallingWriteElement(Parcel& parcel) const;
    bool MarshallingWriteParameters(Parcel& parcel) const;
    bool MarshallingWriteUri(Parcel& parcel) const;
    bool ReadUriFromParcel(Parcel& parcel);
    bool ReadEntitiesFromParcel(Parcel& parcel);
    bool ReadElementFromParcel(Parcel& parcel);
    bool ReadParametersFromParcel(Parcel& parcel);
};
} // namespace DistributedSchedule
} // namespace OHOS
#endif // OHOS_DISTRIBUTEDWANT_WANT_V2_H
