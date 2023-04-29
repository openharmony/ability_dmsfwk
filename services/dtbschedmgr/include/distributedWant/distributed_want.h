/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_AAFWK_DISTRIBUTED_WANT_H
#define OHOS_AAFWK_DISTRIBUTED_WANT_H

#include <string>
#include <vector>
#include <algorithm>

#include "distributedWant/distributed_want_params.h"
#include "distributedWant/distributed_operation.h"
#include "want.h"
#include "uri.h"
#include "element_name.h"
#include "parcel.h"
#include "nlohmann/json.hpp"

using DistributedOperation = OHOS::AAFwk::DistributedOperation;

namespace OHOS {
namespace AAFwk {
class DistributedWant final : public Parcelable {
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
     * @description:  Default construcotr of DistributedWant class, which is used to initialzie flags and URI.
     * @param None
     * @return None
     */
    DistributedWant();

    /**
     * @description: Default deconstructor of DistributedWant class
     * @param None
     * @return None
     */
    ~DistributedWant();

    /**
     * @description: Copy construcotr of DistributedWant class, which is used to initialzie flags, URI, etc.
     * @param want the source instance of DistributedWant.
     * @return None
     */
    DistributedWant(const DistributedWant& want);
    DistributedWant& operator=(const DistributedWant&);
    DistributedWant(const Want& want);

    /**
     * @description: Sets a flag in a DistributedWant.
     * @param flags Indicates the flag to set.
     * @return Returns this DistributedWant object containing the flag.
     */
    DistributedWant& SetFlags(unsigned int flags);

    /**
     * @description: Obtains the description of flags in a DistributedWant.
     * @return Returns the flag description in the DistributedWant.
     */
    unsigned int GetFlags() const;

    /**
     * @description: Adds a flag to a DistributedWant.
     * @param flags Indicates the flag to add.
     * @return Returns the DistributedWant object with the added flag.
     */
    DistributedWant& AddFlags(unsigned int flags);

    /**
     * @description: Removes the description of a flag from a DistributedWant.
     * @param flags Indicates the flag to remove.
     * @return Removes the description of a flag from a DistributedWant.
     */
    void RemoveFlags(unsigned int flag);

    /**
     * @description: Sets the bundleName and abilityName attributes for this DistributedWant object.
     * @param bundleName Indicates the bundleName to set for the operation attribute in the DistributedWant.
     * @param abilityName Indicates the abilityName to set for the operation attribute in the DistributedWant.
     * @return Returns this DistributedWant object that contains the specified bundleName and abilityName attributes.
     */
    DistributedWant& SetElementName(const std::string& bundleName, const std::string& abilityName);

    /**
     * @description: Sets the bundleName and abilityName attributes for this DistributedWant object.
     * @param deviceId Indicates the deviceId to set for the operation attribute in the DistributedWant.
     * @param bundleName Indicates the bundleName to set for the operation attribute in the DistributedWant.
     * @param abilityName Indicates the abilityName to set for the operation attribute in the DistributedWant.
     * @return Returns this DistributedWant object that contains the specified bundleName and abilityName attributes.
     */
    DistributedWant& SetElementName(const std::string& deviceId, const std::string& bundleName, const std::string& abilityName);

    /**
     * @description: Sets an ElementName object in a DistributedWant.
     * @param element Indicates the ElementName description.
     * @return Returns this DistributedWant object containing the ElementName
     */
    DistributedWant& SetElement(const OHOS::AppExecFwk::ElementName& element);

    /**
     * @description: Obtains the description of the ElementName object in a DistributedWant.
     * @return Returns the ElementName description in the DistributedWant.
     */
    OHOS::AppExecFwk::ElementName GetElement() const;

    /**
     * @description: Creates a DistributedWant with its corresponding attributes specified for starting the main ability of an
     * application.
     * @param ElementName  Indicates the ElementName object defining the deviceId, bundleName,
     * and abilityName sub-attributes of the operation attribute in a DistributedWant.
     * @return Returns the DistributedWant object used to start the main ability of an application.
     */
    static DistributedWant* MakeMainAbility(const OHOS::AppExecFwk::ElementName& elementName);

    /**
     * @description: Creates a DistributedWant instance by using a given Uniform Resource Identifier (URI).
     * This method parses the input URI and saves it in a DistributedWant object.
     * @param uri Indicates the URI to parse.
     * @return Returns a DistributedWant object containing the URI.
     */
    static DistributedWant* WantParseUri(const char* uri);

    /**
     * @description: Creates a DistributedWant instance by using a given Uniform Resource Identifier (URI).
     * This method parses the input URI and saves it in a DistributedWant object.
     * @param uri Indicates the URI to parse.
     * @return Returns a DistributedWant object containing the URI.
     */
    static DistributedWant* ParseUri(const std::string& uri);

    /**
     * @description: Obtains the description of a URI in a DistributedWant.
     * @return Returns the URI description in the DistributedWant.
     */
    Uri GetUri() const;

    /**
     * @description: Obtains the string representation of the URI in this DistributedWant.
     * @return Returns the string of the URI.
     */
    std::string GetUriString() const;

    /**
     * @description: Sets the description of a URI in a DistributedWant.
     * @param uri Indicates the URI description.
     * @return Returns this DistributedWant object containing the URI.
     */
    DistributedWant& SetUri(const std::string& uri);

    /**
     * @description: Sets the description of a URI in a DistributedWant.
     * @param uri Indicates the URI description.
     * @return Returns this DistributedWant object containing the URI.
     */
    DistributedWant& SetUri(const Uri& uri);

    /**
     * @description: Sets the description of a URI and a type in this DistributedWant.
     * @param uri Indicates the URI description.
     * @param type Indicates the type description.
     * @return Returns the DistributedWant object containing the URI and the type by setting.
     */
    DistributedWant& SetUriAndType(const Uri& uri, const std::string& type);

    /**
     * @description: Converts a DistributedWant into a URI string containing a representation of it.
     * @param want Indicates the DistributedWant description.--DistributedWant.
     * @return   Returns an encoding URI string describing the DistributedWant object.
     */
    std::string WantToUri(DistributedWant& want);

    /**
     * @description: Converts parameter information in a DistributedWant into a URI string.
     * @return Returns the URI string.
     */
    std::string ToUri() const;

    /**
     * @description: Formats a specified URI.
     * This method uses the Uri.getLowerCaseScheme() method to format a URI and then saves
     * the formatted URI to this DistributedWant object.
     * @param uri Indicates the string of URI to format.
     * @return Returns this DistributedWant object that contains the formatted uri attribute.
     */
    DistributedWant& FormatUri(const std::string& uri);

    /**
     * @description: Formats a specified URI.
     * This method uses the Uri.getLowerCaseScheme() method to format a URI and then saves
     * the formatted URI to this DistributedWant object.
     * @param uri Indicates the URI to format.
     * @return Returns this DistributedWant object that contains the formatted URI attribute.
     */
    DistributedWant& FormatUri(const Uri& uri);

    /**
     * @description: Obtains the description of an action in a DistributedWant.
     * @return Returns a DistributedWant object that contains the action description.
     */
    std::string GetAction() const;

    /**
     * @description: Sets the description of an action in a DistributedWant.
     * @param action Indicates the action description to set.
     * @return Returns a DistributedWant object that contains the action description.
     */
    DistributedWant& SetAction(const std::string& action);

    /**
     * @description: Obtains the name of the specified bundle in a DistributedWant.
     * @return Returns the specified bundle name in the DistributedWant.
     */
    std::string GetBundle() const;

    /**
     * @description: Sets a bundle name in this DistributedWant.
     * If a bundle name is specified in a DistributedWant, the DistributedWant will match only
     * the abilities in the specified bundle. You cannot use this method and
     * setPicker(ohos.aafwk.content.DistributedWant) on the same DistributedWant.
     * @param bundleName Indicates the bundle name to set.
     * @return Returns a DistributedWant object containing the specified bundle name.
     */
    DistributedWant& SetBundle(const std::string& bundleName);

    /**
     * @description: Obtains the description of all entities in a DistributedWant
     * @return Returns a set of entities
     */
    const std::vector<std::string>& GetEntities() const;

    /**
     * @description: Adds the description of an entity to a DistributedWant
     * @param entity Indicates the entity description to add
     * @return {DistributedWant} Returns this DistributedWant object containing the entity.
     */
    DistributedWant& AddEntity(const std::string& entity);

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
    bool HasEntity(const std::string& key) const;

    /**
     * @description: Obtains the number of entities in a DistributedWant
     * @return Returns the entity quantity
     */
    int CountEntities();

    /**
     * @description: Obtains the description of the URI scheme in this DistributedWant.
     * @return Returns the URI scheme description in this DistributedWant.
     */
    const std::string GetScheme() const;

    /**
     * @description: Obtains the description of the type in this DistributedWant
     * @return Returns the type description in this DistributedWant
     */
    std::string GetType() const;

    /**
     * @description: Sets the description of a type in this DistributedWant
     * @param type Indicates the type description
     * @return Returns this DistributedWant object containing the type
     */
    DistributedWant& SetType(const std::string& type);

    /**
     * @description: Formats a specified MIME type. This method uses
     * the formatMimeType(java.lang.String) method to format a MIME type
     * and then saves the formatted type to this DistributedWant object.
     * @param type Indicates the MIME type to format
     * @return Returns this DistributedWant object that contains the formatted type attribute
     */
    DistributedWant& FormatType(const std::string& type);

    /**
     * @description: Formats a specified URI and MIME type.
     * This method works in the same way as formatUri(ohos.utils.net.URI)
     * and formatType(java.lang.String).
     * @param uri Indicates the URI to format.
     * @param type Indicates the MIME type to format.
     * @return Returns this DistributedWant object that contains the formatted URI and type attributes.
     */
    DistributedWant& FormatUriAndType(const Uri& uri, const std::string& type);

    /**
     * @description: This method formats data of a specified MIME type
     * by removing spaces from the data and converting the data into
     * lowercase letters. You can use this method to normalize
     * the external data used to create DistributedWant information.
     * @param type Indicates the MIME type to format
     * @return Returns this DistributedWant object that contains the formatted type attribute
     */
    static std::string FormatMimeType(const std::string& mimeType);

    /**
     * @description: clear the specific DistributedWant object.
     * @param want Indicates the DistributedWant to clear
     */
    static void ClearWant(DistributedWant* want);

    /**
     * @description: Obtains the description of the DistributedWantParams object in a DistributedWant
     * @return Returns the DistributedWantParams description in the DistributedWant
     */
    const DistributedWantParams& GetParams() const;

    /**
     * @description: Sets a DistributedWantParams object in a want.
     * @param wantParams  Indicates the DistributedWantParams description.
     * @return Returns this want object containing the DistributedWantParams.
     */
    DistributedWant& SetParams(const DistributedWantParams& wantParams);

    /**
     * @description: Obtains a bool-type value matching the given key.
     * @param key   Indicates the key of DistributedWantParams.
     * @param defaultValue  Indicates the default bool-type value.
     * @return Returns the bool-type value of the parameter matching the given key;
     * returns the default value if the key does not exist.
     */
    bool GetBoolParam(const std::string& key, bool defaultValue) const;

    /**
     * @description: Obtains a bool-type array matching the given key.
     * @param key   Indicates the key of DistributedWantParams.
     * @return Returns the bool-type array of the parameter matching the given key;
     * returns null if the key does not exist.
     */
    std::vector<bool> GetBoolArrayParam(const std::string& key) const;

    /**
     * @description: Sets a parameter value of the boolean type.
     * @param key   Indicates the key matching the parameter.
     * @param value Indicates the boolean value of the parameter.
     * @return Returns this DistributedWant object containing the parameter value.
     */
    DistributedWant& SetParam(const std::string& key, bool value);

    /**
     * @description: Sets a parameter value of the boolean array type.
     * @param key   Indicates the key matching the parameter.
     * @param value Indicates the boolean array of the parameter.
     * @return Returns this DistributedWant object containing the parameter value.
     */
    DistributedWant& SetParam(const std::string& key, const std::vector<bool>& value);

    /**
     * @description: Obtains a byte-type value matching the given key.
     * @param key   Indicates the key of DistributedWantParams.
     * @param defaultValue  Indicates the default byte-type value.
     * @return Returns the byte-type value of the parameter matching the given key;
     * returns the default value if the key does not exist.
     */
    byte GetByteParam(const std::string& key, byte defaultValue) const;

    /**
     * @description: Obtains a byte-type array matching the given key.
     * @param key   Indicates the key of DistributedWantParams.
     * @return Returns the byte-type array of the parameter matching the given key;
     * returns null if the key does not exist.
     */
    std::vector<byte> GetByteArrayParam(const std::string& key) const;

    /**
     * @description: Sets a parameter value of the byte type.
     * @param key   Indicates the key matching the parameter.
     * @param value Indicates the byte-type value of the parameter.
     * @return Returns this DistributedWant object containing the parameter value.
     */
    DistributedWant& SetParam(const std::string& key, byte value);

    /**
     * @description: Sets a parameter value of the byte array type.
     * @param key   Indicates the key matching the parameter.
     * @param value Indicates the byte array of the parameter.
     * @return Returns this DistributedWant object containing the parameter value.
     */
    DistributedWant& SetParam(const std::string& key, const std::vector<byte>& value);

    /**
     * @description: Obtains a char value matching the given key.
     * @param key   Indicates the key of wnatParams.
     * @param value Indicates the default char value.
     * @return Returns the char value of the parameter matching the given key;
     * returns the default value if the key does not exist.
     */
    zchar GetCharParam(const std::string& key, zchar defaultValue) const;

    /**
     * @description: Obtains a char array matching the given key.
     * @param key   Indicates the key of DistributedWantParams.
     * @return Returns the char array of the parameter matching the given key;
     * returns null if the key does not exist.
     */
    std::vector<zchar> GetCharArrayParam(const std::string& key) const;

    /**
     * @description: Sets a parameter value of the char type.
     * @param key   Indicates the key of DistributedWantParams.
     * @param value Indicates the char value of the parameter.
     * @return Returns this DistributedWant object containing the parameter value.
     */
    DistributedWant& SetParam(const std::string& key, zchar value);

    /**
     * @description: Sets a parameter value of the char array type.
     * @param key   Indicates the key of DistributedWantParams.
     * @param value Indicates the char array of the parameter.
     * @return Returns this DistributedWant object containing the parameter value.
     */
    DistributedWant& SetParam(const std::string& key, const std::vector<zchar>& value);

    /**
     * @description: Obtains an int value matching the given key.
     * @param key   Indicates the key of DistributedWantParams.
     * @param value Indicates the default int value.
     * @return Returns the int value of the parameter matching the given key;
     * returns the default value if the key does not exist.
     */
    int GetIntParam(const std::string& key, int defaultValue) const;

    /**
     * @description: Obtains an int array matching the given key.
     * @param key   Indicates the key of DistributedWantParams.
     * @return Returns the int array of the parameter matching the given key;
     * returns null if the key does not exist.
     */
    std::vector<int> GetIntArrayParam(const std::string& key) const;

    /**
     * @description: Sets a parameter value of the int type.
     * @param key   Indicates the key matching the parameter.
     * @param value Indicates the int value of the parameter.
     * @return Returns this DistributedWant object containing the parameter value.
     */
    DistributedWant& SetParam(const std::string& key, int value);

    /**
     * @description: Sets a parameter value of the int array type.
     * @param key   Indicates the key matching the parameter.
     * @param value Indicates the int array of the parameter.
     * @return Returns this DistributedWant object containing the parameter value.
     */
    DistributedWant& SetParam(const std::string& key, const std::vector<int>& value);

    /**
     * @description: Obtains a double value matching the given key.
     * @param key   Indicates the key of DistributedWantParams.
     * @param defaultValue  Indicates the default double value.
     * @return Returns the double value of the parameter matching the given key;
     * returns the default value if the key does not exist.
     */
    double GetDoubleParam(const std::string& key, double defaultValue) const;

    /**
     * @description: Obtains a double array matching the given key.
     * @param key   Indicates the key of DistributedWantParams.
     * @return Returns the double array of the parameter matching the given key;
     * returns null if the key does not exist.
     */
    std::vector<double> GetDoubleArrayParam(const std::string& key) const;

    /**
     * @description: Sets a parameter value of the double type.
     * @param key   Indicates the key matching the parameter.
     * @param value Indicates the int value of the parameter.
     * @return Returns this DistributedWant object containing the parameter value.
     */
    DistributedWant& SetParam(const std::string& key, double value);

    /**
     * @description: Sets a parameter value of the double array type.
     * @param key   Indicates the key matching the parameter.
     * @param value Indicates the double array of the parameter.
     * @return Returns this DistributedWant object containing the parameter value.
     */
    DistributedWant& SetParam(const std::string& key, const std::vector<double>& value);

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
     * @param key Indicates the key of DistributedWantParams.
     * @return Obtains a float array matching the given key.
     */
    std::vector<float> GetFloatArrayParam(const std::string& key) const;

    /**
     * @description: Sets a parameter value of the float type.
     * @param key Indicates the key matching the parameter.
     * @param value Indicates the byte-type value of the parameter.
     * @return Returns this DistributedWant object containing the parameter value.
     */
    DistributedWant& SetParam(const std::string& key, float value);

    /**
     * @description: Sets a parameter value of the float array type.
     * @param key Indicates the key matching the parameter.
     * @param value Indicates the byte-type value of the parameter.
     * @return Returns this DistributedWant object containing the parameter value.
     */
    DistributedWant& SetParam(const std::string& key, const std::vector<float>& value);

    /**
     * @description: Obtains a long value matching the given key.
     * @param key Indicates the key of DistributedWantParams.
     * @param value Indicates the default long value.
     * @return Returns the long value of the parameter matching the given key;
     * returns the default value if the key does not exist.
     */
    long GetLongParam(const std::string& key, long defaultValue) const;

    /**
     * @description: Obtains a long array matching the given key.
     * @param key Indicates the key of DistributedWantParams.
     * @return Returns the long array of the parameter matching the given key;
     * returns null if the key does not exist.
     */
    std::vector<long> GetLongArrayParam(const std::string& key) const;

    DistributedWant& SetParam(const std::string& key, long long value);

    /**
     * @description: Sets a parameter value of the long type.
     * @param key Indicates the key matching the parameter.
     * @param value Indicates the byte-type value of the parameter.
     * @return Returns this DistributedWant object containing the parameter value.
     */
    DistributedWant& SetParam(const std::string& key, long value);

    /**
     * @description: Sets a parameter value of the long array type.
     * @param key Indicates the key matching the parameter.
     * @param value Indicates the byte-type value of the parameter.
     * @return Returns this DistributedWant object containing the parameter value.
     */
    DistributedWant& SetParam(const std::string& key, const std::vector<long>& value);

    /**
     * @description: a short value matching the given key.
     * @param key Indicates the key of DistributedWantParams.
     * @param defaultValue Indicates the default short value.
     * @return Returns the short value of the parameter matching the given key;
     * returns the default value if the key does not exist.
     */
    short GetShortParam(const std::string& key, short defaultValue) const;

    /**
     * @description: Obtains a short array matching the given key.
     * @param key Indicates the key of DistributedWantParams.
     * @return Returns the short array of the parameter matching the given key;
     * returns null if the key does not exist.
     */
    std::vector<short> GetShortArrayParam(const std::string& key) const;

    /**
     * @description: Sets a parameter value of the short type.
     * @param key Indicates the key matching the parameter.
     * @param value Indicates the byte-type value of the parameter.
     * @return Returns this DistributedWant object containing the parameter value.
     */
    DistributedWant& SetParam(const std::string& key, short value);

    /**
     * @description: Sets a parameter value of the short array type.
     * @param key Indicates the key matching the parameter.
     * @param value Indicates the byte-type value of the parameter.
     * @return Returns this DistributedWant object containing the parameter value.
     */
    DistributedWant& SetParam(const std::string& key, const std::vector<short>& value);

    /**
     * @description: Obtains a string value matching the given key.
     * @param key Indicates the key of DistributedWantParams.
     * @return Returns the string value of the parameter matching the given key;
     * returns null if the key does not exist.
     */
    std::string GetStringParam(const std::string& key) const;

    /**
     * @description: Obtains a string array matching the given key.
     * @param key Indicates the key of DistributedWantParams.
     * @return Returns the string array of the parameter matching the given key;
     * returns null if the key does not exist.
     */
    std::vector<std::string> GetStringArrayParam(const std::string& key) const;

    /**
     * @description: Sets a parameter value of the string type.
     * @param key Indicates the key matching the parameter.
     * @param value Indicates the byte-type value of the parameter.
     * @return Returns this DistributedWant object containing the parameter value.
     */
    DistributedWant& SetParam(const std::string& key, const std::string& value);

    /**
     * @description: Sets a parameter value of the string array type.
     * @param key Indicates the key matching the parameter.
     * @param value Indicates the byte-type value of the parameter.
     * @return Returns this DistributedWant object containing the parameter value.
     */
    DistributedWant& SetParam(const std::string& key, const std::vector<std::string>& value);

    /**
     * @description: Checks whether a DistributedWant contains the parameter matching a given key.
     * @param key Indicates the key.
     * @return Returns true if the DistributedWant contains the parameter; returns false otherwise.
     */
    bool HasParameter(const std::string& key) const;

    /**
     * @description: Replaces parameters in this Want object with those in the given DistributedWantParams object.
     * @param wantParams Indicates the DistributedWantParams object containing the new parameters.
     * @return Returns this Want object containing the new parameters.
     */
    DistributedWant* ReplaceParams(DistributedWantParams& wantParams);

    /**
     * @description: Replaces parameters in this DistributedWant object with those in the given Want object.
     * @param want Indicates the DistributedWant object containing the new parameters.
     * @return Returns this DistributedWant object containing the new parameters.
     */
    DistributedWant* ReplaceParams(DistributedWant& want);

    /**
     * @description: Removes the parameter matching the given key.
     * @param key Indicates the key matching the parameter to be removed.
     */
    void RemoveParam(const std::string& key);

    /**
     * @description: Gets the description of an operation in a DistributedWant.
     * @return Returns the operation included in this DistributedWant.
     */
    DistributedOperation GetOperation() const;

    /**
     * @description: Sets the description of an operation in a DistributedWant.
     * @param operation Indicates the operation description.
     */
    void SetOperation(const OHOS::AAFwk::DistributedOperation& operation);

    /**
     * @description: Sets the description of an operation in a DistributedWant.
     * @param want Indicates the DistributedWant object to compare.
     * @return Returns true if the operation components of the two objects are equal; returns false otherwise.
     */
    bool OperationEquals(const DistributedWant& want);

    /**
     * @description: Creates a DistributedWant object that contains only the operation component of this DistributedWant.
     * @return Returns the created DistributedWant object.
     */
    DistributedWant* CloneOperation();

    /**
     * @description: Marshals a DistributedWant into a Parcel.
     * Fields in the DistributedWant are marshalled separately. If any field fails to be marshalled, false is returned.
     * @param parcel Indicates the Parcel object for marshalling.
     * @return Returns true if the marshalling is successful; returns false otherwise.
     */
    virtual bool Marshalling(Parcel& parcel) const;

    /**
     * @description: Unmarshals a DistributedWant from a Parcel.
     * Fields in the DistributedWant are unmarshalled separately. If any field fails to be unmarshalled, false is returned.
     * @param parcel Indicates the Parcel object for unmarshalling.
     * @return Returns true if the unmarshalling is successful; returns false otherwise.
     */
    static DistributedWant* Unmarshalling(Parcel& parcel);

    void DumpInfo(int level) const;

    std::string ToString() const;

    static DistributedWant* FromString(std::string& string);

    std::shared_ptr<Want> ToWant();

    /**
    * @description: Sets a device id in a DistributedWant.
    * @param deviceId Indicates the device id to set.
    * @return Returns this DistributedWant object containing the flag.
    */
    DistributedWant& SetDeviceId(const std::string& deviceId);
public:
    // action definition
    static const std::string ACTION_PLAY;
    static const std::string ACTION_HOME;

    // entity definition
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

    // flag definition
    static unsigned int FLAG_ABILITY_NEW_MISSION;
    static unsigned int FLAG_ABILITY_CLEAR_MISSION;

    static constexpr int HEX_STRING_BUF_LEN = 36;
    static constexpr int HEX_STRING_LEN = 10;

    // reserved param definition
    static const std::string PARAM_RESV_WINDOW_MODE;
    static const std::string PARAM_RESV_DISPLAY_ID;
    static const std::string PARAM_RESV_CALLER_TOKEN;
    static const std::string PARAM_RESV_CALLER_UID;
    static const std::string PARAM_RESV_CALLER_PID;

private:
    DistributedWantParams parameters_;
    DistributedOperation operation_;

    static const std::string OCT_EQUALSTO;
    static const std::string OCT_SEMICOLON;
    static const std::string MIME_TYPE;
    static const std::string WANT_HEADER;

    // no object in parcel
    static constexpr int VALUE_NULL = -1;
    // object exist in parcel
    static constexpr int VALUE_OBJECT = 1;

private:
    static bool ParseFlag(const std::string& content, DistributedWant& want);
    static std::string Decode(const std::string& str);
    static std::string Encode(const std::string& str);
    static bool ParseContent(const std::string& content, std::string& prop, std::string& value);
    static bool ParseUriInternal(const std::string& content, OHOS::AppExecFwk::ElementName& element, DistributedWant& want);
    bool ReadFromParcel(Parcel& parcel);
    static bool CheckAndSetParameters(DistributedWant& want, const std::string& key, std::string& prop, const std::string& value);
    Uri GetLowerCaseScheme(const Uri& uri);
    void ToUriStringInner(std::string& uriString) const;
    nlohmann::json ToJson() const;
    bool ReadFromJson(nlohmann::json& wantJson);

};
}  // namespace AAFwk
}  // namespace OHOS

#endif  // OHOS_AAFWK_DISTRIBUTED_WANT_H
