/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "mission/param/param_common_event.h"

#include <common_event_data.h>
#include <common_event_manager.h>
#include <common_event_support.h>
#include <memory>
#include <unistd.h>
#include <iosfwd>
#include <sstream>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>

#include "dtbschedmgr_log.h"
#include "common_event_subscriber.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "ParamManager";
const int32_t RETRY_SUBSCRIBER = 3;
const int32_t TEN_BIT_SIZE = 10;
const std::string EVENT_INFO_TYPE = "type";
const std::string EVENT_INFO_TYPE_VALUE = "ContinuationService";
const std::string EVENT_INFO_SUBTYPE = "subtype";
const std::string EVENT_INFO_SUBTYPE_VALUE = "generic";
const std::string CONTINUATION_SERVICE_DATA_PATH =
    "/data/service/el1/public/update/param_service/install/system/etc/ContinuationService/generic/";
//const std::string PUBKEY_FILE = "/system/profile/hwkey_param_upgrade_v1.pem";
const std::string CONTINUATION_SERVICE_DATA_FILE_NAME = "disable_continuation_service_applist.json";
const std::string VERSION_FILE_NAME = "version.txt";
constexpr char VERSION_CODE_KEY[] = "versionCode";
constexpr int64_t FILE_MAX_SIZE = 10 * 1024; // 限制文件大小为10KB 防止不可信文件导致内存过大
}

ParamCommonEvent::ParamCommonEvent()
{
    HILOGI("ParamCommonEvent ParamCommonEvent");
    handleEventFunc_["usual.event.DUE_SA_CFG_UPDATED"] = &ParamCommonEvent::HandleParamUpdate;
    eventHandles_["usual.event.DUE_SA_CFG_UPDATED"] =
        [this](const OHOS::AAFwk::Want &want) { this->HandleParamUpdate(want); };
}

ParamCommonEvent::~ParamCommonEvent()
{
    UnSubscriberEvent();
}

void ParamCommonEvent::SubscriberEvent()
{
    HILOGI("SubscriberEvent start.");
    if (subscriber_) {
        HILOGI("Common Event is already subscribered!");
        return;
    }
    EventFwk::MatchingSkills matchingSkills;
    for (auto &event : handleEventFunc_) {
        HILOGI("Add event: %{public}s", event.first.c_str());
        matchingSkills.AddEvent(event.first);
    }
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    subscribeInfo.SetPermission("ohos.permission.RECEIVE_UPDATE_MESSAGE");
    subscriber_ = std::make_shared<ParamCommonEventSubscriber>(subscribeInfo, *this);

    int32_t retry = RETRY_SUBSCRIBER;
    do {
        bool subscribeResult = EventFwk::CommonEventManager::SubscribeCommonEvent(subscriber_);
        if (subscribeResult) {
            HILOGI("SubscriberEvent success.");
            return;
        } else {
            HILOGI("SubscriberEvent failed, retry %{public}d", retry);
            retry--;
            sleep(1);
        }
    } while (retry);

    HILOGI("SubscriberEvent failed.");
}

void ParamCommonEvent::UnSubscriberEvent()
{
    HILOGI("UnSubscriberEvent start.");
    eventHandles_.clear();
    handleEventFunc_.clear();
    if (subscriber_) {
        bool subscribeResult = EventFwk::CommonEventManager::UnSubscribeCommonEvent(subscriber_);
        HILOGI("subscribeResult = %{public}d", subscribeResult);
        subscriber_ = nullptr;
    }
    HILOGI("UnSubscriberEvent end.");
}

void ParamCommonEvent::OnReceiveEvent(const AAFwk::Want &want)
{
    std::string action = want.GetAction();
    auto it = eventHandles_.find(action);
    if (it == eventHandles_.end()) {
        HILOGI("Ignore event: %{public}s", action.c_str());
        return;
    }
    HILOGI("Handle event: %{public}s", action.c_str());
    it->second(want);
}

void ParamCommonEvent::HandleParamUpdate(const AAFwk::Want &want) const
{
    std::string action = want.GetAction();
    std::string type = want.GetStringParam(EVENT_INFO_TYPE);
    std::string subtype = want.GetStringParam(EVENT_INFO_SUBTYPE);
    HILOGI("recive param update event: %{public}s ,%{public}s ,%{public}s ", action.c_str(), type.c_str(),
        subtype.c_str());
    if (type != EVENT_INFO_TYPE_VALUE || subtype != EVENT_INFO_SUBTYPE_VALUE) {
        HILOGW("Invalid type or subtype !!");
        return;
    }
    UpdateBlacklist();
}

static std::string Trim(const std::string &value)
{
    size_t left = 0;
    while (left < value.size() && isspace(static_cast<unsigned char>(value[left])) != 0) {
        ++left;
    }
    size_t right = value.size();
    while (right > left && isspace(static_cast<unsigned char>(value[right - 1])) != 0) {
        --right;
    }
    return value.substr(left, right - left);
}

static bool ParseUint32(const std::string &value, uint32_t &result)
{
    std::string trimValue = Trim(value);
    if (trimValue.empty()) {
        return false;
    }
    uint64_t acc = 0;
    for (const char ch : trimValue) {
        if (isdigit(static_cast<unsigned char>(ch)) == 0) {
            return false;
        }
        uint32_t digit = static_cast<uint32_t>(ch - '0');
        if (acc > (std::numeric_limits<uint32_t>::max() - digit) / TEN_BIT_SIZE) {
            return false;
        }
        acc = acc * TEN_BIT_SIZE + digit;
    }
    result = static_cast<uint32_t>(acc);
    return true;
}

static bool ParseVersionRange(const std::string &rule, std::pair<uint32_t, uint32_t> &range)
{
    std::string trimRule = Trim(rule);
    if (trimRule.empty()) {
        return false;
    }
    size_t splitPos = trimRule.find('-');
    if (splitPos == std::string::npos) {
        uint32_t versionCode = 0;
        if (!ParseUint32(trimRule, versionCode)) {
            return false;
        }
        range = {versionCode, versionCode};
        return true;
    }

    uint32_t startCode = 0;
    uint32_t endCode = 0;
    if (!ParseUint32(trimRule.substr(0, splitPos), startCode) ||
        !ParseUint32(trimRule.substr(splitPos + 1), endCode)) {
        return false;
    }
    if (startCode <= endCode) {
        range = {startCode, endCode};
    } else {
        range = {endCode, startCode};
    }
    return true;
}

bool ParamCommonEvent::UpdateBlacklist() const
{
    HILOGI("UpdateBlacklist");
    if (!VerifyCertSfFile()) {
        HILOGE("VerifyCertSfFile failed !");
        return false;
    }
    if (!VerifyParamFile(CONTINUATION_SERVICE_DATA_PATH, VERSION_FILE_NAME)) {
        HILOGE("Verify Version File failed !");
        return false;
    }
    if (!VerifyParamFile(CONTINUATION_SERVICE_DATA_PATH, CONTINUATION_SERVICE_DATA_FILE_NAME)) {
        HILOGE("Verify Config File failed !");
        return false;
    }
    std::string filePath = CONTINUATION_SERVICE_DATA_PATH + CONTINUATION_SERVICE_DATA_FILE_NAME;
    std::ifstream file(filePath);
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string jsonText = buffer.str();
    HILOGI("UpdateBlacklist, file context:%{public}s", jsonText.c_str());
    if (jsonText.empty()) {
        HILOGE("file is empty.");
        return false;
    }

    cJSON *root = cJSON_Parse(jsonText.c_str());
    if (root == nullptr || !cJSON_IsObject(root)) {
        HILOGE("Parse controllist json failed.");
        if (root != nullptr) {
            cJSON_Delete(root);
        }
        return false;
    }

    bool ret =  UpdateBlacklistInner(root);
    cJSON_Delete(root);
    return ret;
}

// 校验下载的参数文件是否合法
/*
    // 获取签名文件
    std::string certFile = CONTINUATION_SERVICE_DATA_PATH + "CERT.ENC";
    // 验证CERT.SF文件是否合法
    if (!VerifyFileSign(PUBKEY_FILE, certFile, verifyFile)) {
        HILOGE("signToolManager verify failed %{public}s,%{public}s, %{public}s", PUBKEY_FILE.c_str(),
                  certFile.c_str(), verifyFile.c_str());
        return false;
    }
 * */
bool ParamCommonEvent::VerifyCertSfFile() const
{
    // 获取待验证的文件
    std::string verifyFile = CONTINUATION_SERVICE_DATA_PATH + "CERT.SF";

    // 验证MANIFEST.MF 是否合法
    std::string manifestFile = CONTINUATION_SERVICE_DATA_PATH + "MANIFEST.MF";
    std::ifstream file(verifyFile);
    if (!file.good()) {
        HILOGE("Verify is not good,verifyFile:%{public}s", verifyFile.c_str());
        return false;
    }
    std::string line;
    std::string sha256Digest;
    std::getline(file, line);
    file.close();
    sha256Digest = Split(line, ':')[1];
    Trim(sha256Digest);
    HILOGI("Verify manifestFile ,sha256Digest:%{public}s", sha256Digest.c_str());

    std::tuple<int, std::string> ret = CalcFileSha256Digest(manifestFile);
    std::string manifestDigest = std::get<1>(ret);
    HILOGI("CalcFileSha256Digest manifestFile ,manifestDigest:%{public}s", manifestDigest.c_str());
    if (sha256Digest == manifestDigest) {
        return true;
    }
    return false;
}

// 校验下载的参数文件的完整性
bool ParamCommonEvent::VerifyParamFile(const std::string& cfgDirPath, const std::string &filePathStr) const
{
    HILOGI("VerifyParamFile ,filePathStr:%{public}s", filePathStr.c_str());
    std::string absFilePath = cfgDirPath + filePathStr;
    std::string manifestFile = cfgDirPath + "MANIFEST.MF";
    std::ifstream file(manifestFile);
    std::string line;
    std::string sha256Digest;

    if (!file.good()) {
        HILOGI("manifestFile is not good,manifestFile:%{public}s", manifestFile.c_str());
        return false;
    }
    std::ifstream paramFile(absFilePath);
    if (!paramFile.good()) {
        HILOGI("paramFile is not good,paramFile:%{public}s", absFilePath.c_str());
        return false;
    }

    while (std::getline(file, line)) {
        std::string nextline;
        if (line.find("Name: " + filePathStr) != std::string::npos) {
            std::getline(file, nextline);
            sha256Digest = Split(nextline, ':')[1];
            Trim(sha256Digest);
            break;
        }
    }
    HILOGI("VerifyParamFile, Read manifestFile, sha256Digest:%{public}s", sha256Digest.c_str());
    if (sha256Digest.empty()) {
        HILOGI("VerifyParamFile failed ,sha256Digest is empty");
        return false;
    }

    std::tuple<int, std::string> ret = CalcFileSha256Digest(absFilePath);
    if (std::get<0>(ret) != 0) {
        HILOGI("CalcFileSha256Digest failed,error : %{public}d ", std::get<0>(ret));
        return false;
    }
    HILOGI("VerifyParamFile, CalcFileSha256Digest, sha256Digest:%{public}s", std::get<1>(ret).c_str());
    if (sha256Digest == std::get<1>(ret)) {
        return true;
    } else {
        HILOGI("VerifyParamFile failed ,sha256Digest: %{public}s, fileShaDigest:%{public}s ", sha256Digest.c_str(),
            std::get<1>(ret).c_str());
        return false;
    }
}

std::vector<std::string> ParamCommonEvent::Split(const std::string &str, char delim) const
{
    std::vector<std::string> tokens;
    size_t start;
    size_t end = 0;
    while ((start = str.find_first_not_of(delim, end)) != std::string::npos) {
        end = str.find(delim, start);
        tokens.push_back(str.substr(start, end - start));
    }
    return tokens;
}

void ParamCommonEvent::Trim(std::string &inputStr) const
{
    inputStr.erase(inputStr.begin(),
        std::find_if(inputStr.begin(), inputStr.end(), [](unsigned char ch) { return !std::isspace(ch); }));
    inputStr.erase(
        std::find_if(inputStr.rbegin(), inputStr.rend(), [](unsigned char ch) { return !std::isspace(ch); }).base(),
        inputStr.end());
}

std::tuple<int, std::string> ParamCommonEvent::CalcFileSha256Digest(const std::string &fpath) const
{
    auto res = std::make_unique<unsigned char[]>(SHA256_DIGEST_LENGTH);
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    auto sha256Update = [ctx = &ctx](char *buf, size_t len) { SHA256_Update(ctx, buf, len); };
    int err = ForEachFileSegment(fpath, sha256Update);
    SHA256_Final(res.get(), &ctx);
    if (err) {
        return { err, "" };
    }
    std::string dist;
    CalcBase64(res.get(), SHA256_DIGEST_LENGTH, dist);
    return { err, dist };
}

void ParamCommonEvent::CalcBase64(uint8_t *input, uint32_t inputLen, std::string &encodedStr) const
{
    size_t expectedLength = 4 * ((inputLen + 2) / 3);
    encodedStr.resize(expectedLength);
    size_t actualLength = EVP_EncodeBlock(reinterpret_cast<uint8_t *>(&encodedStr[0]), input, inputLen);
    encodedStr.resize(actualLength);
    HILOGI("expectedLength = %{public}zu, actualLength = %{public}zu", expectedLength, actualLength);
}

int ParamCommonEvent::ForEachFileSegment(const std::string &fpath, std::function<void(char *, size_t)> executor) const
{
    std::unique_ptr<FILE, decltype(&fclose)> filp = { fopen(fpath.c_str(), "r"), fclose };
    if (!filp) {
        return errno;
    }
    const size_t pageSize { getpagesize() };
    auto buf = std::make_unique<char[]>(pageSize);
    size_t actLen;
    do {
        actLen = fread(buf.get(), 1, pageSize, filp.get());
        if (actLen > 0) {
            executor(buf.get(), actLen);
        }
    } while (actLen == pageSize);

    return ferror(filp.get()) ? errno : 0;
}

bool ParamCommonEvent::VerifyFileSign(const std::string &pubKeyPath, const std::string &signPath,
    const std::string &digestPath) const
{
    if (!(IsFileExists(pubKeyPath) && IsFileExists(signPath) && IsFileExists(digestPath))) {
        HILOGE("file not exist");
        return false;
    }

    if (GetFileSize(signPath) > FILE_MAX_SIZE || GetFileSize(digestPath) > FILE_MAX_SIZE) {
        HILOGE("VerifyFileSign error, file size is invalid");
        return false;
    }

    const std::string signStr = GetfileStream(signPath);
    const std::string digestStr = GetfileStream(digestPath);
    if (signStr.empty() || digestStr.empty()) {
        HILOGE("VerifyFileSign error, signStr or digestStr is empty");
        return false;
    }

    BIO *bio = BIO_new_file(pubKeyPath.c_str(), "r");
    RSA *pubKey = RSA_new();
    if (PEM_read_bio_RSA_PUBKEY(bio, &pubKey, nullptr, nullptr) == nullptr) {
        HILOGI("get pubKey is failed");
        return false;
    }

    bool verify = false;
    if (!(pubKey == nullptr || signStr.empty() || digestStr.empty())) {
        verify = VerifyRsa(pubKey, digestStr, signStr);
    } else {
        HILOGE("pubKey == NULL || signStr.empty() || digeststr.empty()");
    }
    BIO_free(bio);
    RSA_free(pubKey);
    return verify;
}

bool ParamCommonEvent::IsFileExists(const std::string &fileName) const
{
    std::ifstream file(fileName);
    bool ret = file.good();
    if (!ret) {
        if (access(fileName.c_str(), F_OK) == 0) {
            HILOGI("file is exist but not accessible, no read permission or selinux control");
        } else {
            HILOGI("file is not exist errno is %{public}d", errno);
        }
    }
    return ret;
}

int64_t ParamCommonEvent::GetFileSize(const std::string &fileName) const
{
    std::error_code errorCode;
    int64_t fileSize = static_cast<int64_t>(std::filesystem::file_size(fileName, errorCode));
    if (errorCode.operator bool()) {
        HILOGE("get file size error, file = %{public}s", fileName.c_str());
        return 0;
    }
    return fileSize;
}

std::string ParamCommonEvent::GetfileStream(const std::string &filepath) const
{
    std::ifstream file(filepath, std::ios::in | std::ios::binary);
    // 文件流的异常处理，不能用try catch的形式
    if (!file) {
        HILOGI("Failed to open the file!");
        return NULL;
    }
    std::stringstream infile;
    infile << file.rdbuf();
    const std::string fileString = infile.str();
    if (fileString.empty()) {
        return NULL;
    }
    return fileString;
}

bool ParamCommonEvent::VerifyRsa(RSA *pubKey, const std::string &digest, const std::string &sign) const
{
    EVP_PKEY *evpKey = nullptr;
    EVP_MD_CTX *ctx = nullptr;
    evpKey = EVP_PKEY_new();
    if (evpKey == nullptr) {
        HILOGW("evpKey == nullptr");
        return false;
    }
    if (EVP_PKEY_set1_RSA(evpKey, pubKey) != 1) {
        HILOGW("EVP_PKEY_set1_RSA(evpKey, pubKey) != 1");
        return false;
    }
    ctx = EVP_MD_CTX_new();
    EVP_MD_CTX_init(ctx);
    if (ctx == nullptr) {
        HILOGW("ctx == nullptr");
        EVP_PKEY_free(evpKey);
        return false;
    }
    // warnning：需要与签名的hash算法一致，当前使用的是 sha256withrsa ，需要选择 EVP_sha256()
    if (EVP_VerifyInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
        HILOGW("EVP_VerifyInit_ex(ctx, EVP_sha256(), NULL) != 1");
        EVP_PKEY_free(evpKey);
        EVP_MD_CTX_free(ctx);
        return false;
    }
    if (EVP_VerifyUpdate(ctx, digest.c_str(), digest.size()) != 1) {
        HILOGW("EVP_VerifyUpdate(ctx, digest.c_str(), digest.size()) != 1");
        EVP_PKEY_free(evpKey);
        EVP_MD_CTX_free(ctx);
        return false;
    }
    if (EVP_VerifyFinal(ctx, (unsigned char *)sign.c_str(), sign.size(), evpKey) != 1) {
        HILOGW("EVP_VerifyFinal(ctx, (unsigned char *)sign.c_str(), sign.size(), evpKey) != 1)");
        EVP_PKEY_free(evpKey);
        EVP_MD_CTX_free(ctx);
        return false;
    }

    EVP_PKEY_free(evpKey);
    EVP_MD_CTX_free(ctx);
    return true;
}

bool ParamCommonEvent::UpdateBlacklistInner(cJSON *root) const
{
    if (root == nullptr || !cJSON_IsObject(root)) {
        HILOGE("UpdateBlacklistInner invalid root.");
        return false;
    }
    std::unordered_map<std::string, std::vector<std::pair<uint32_t, uint32_t>>> tempBlackList;
    for (cJSON *bundleItem = root->child; bundleItem != nullptr; bundleItem = bundleItem->next) {
        if (bundleItem->string == nullptr || !cJSON_IsObject(bundleItem)) {
            continue;
        }
        cJSON *versionCodeArray = cJSON_GetObjectItemCaseSensitive(bundleItem, VERSION_CODE_KEY);
        if (versionCodeArray == nullptr || !cJSON_IsArray(versionCodeArray)) {
            continue;
        }

        std::vector<std::pair<uint32_t, uint32_t>> versionRanges;
        cJSON *versionRuleItem = nullptr;
        cJSON_ArrayForEach(versionRuleItem, versionCodeArray) {
            if (!cJSON_IsString(versionRuleItem) || versionRuleItem->valuestring == nullptr) {
                continue;
            }
            std::pair<uint32_t, uint32_t> range;
            if (ParseVersionRange(versionRuleItem->valuestring, range)) {
                versionRanges.push_back(range);
            }
        }
        if (!versionRanges.empty()) {
            tempBlackList[std::string(bundleItem->string)] = std::move(versionRanges);
        }
    }

    std::lock_guard<std::mutex> lock(blackListMutex_);
    blackListMap_ = std::move(tempBlackList);
    HILOGI("Update controllist success, bundle size: %{public}zu.", blackListMap_.size());
    return true;
}

bool ParamCommonEvent::CheckBlacklist(std::string bundleName, uint32_t versionCode)
{
    HILOGI("CheckBlacklist, versionCode: %{public}d", versionCode);
    std::lock_guard<std::mutex> lock(blackListMutex_);
    auto bundleIter = blackListMap_.find(bundleName);
    if (bundleIter == blackListMap_.end()) {
        HILOGI("CheckBlacklist, bundleIter == blackListMap_.end()");
        return false;
    }

    for (const auto &range : bundleIter->second) {
        if (versionCode >= range.first && versionCode <= range.second) {
            HILOGI("Hit controllist, bundleName: %{public}s, versionCode: %{public}u.",
                bundleName.c_str(), versionCode);
            return true;
        }
    }
    HILOGI("CheckBlacklist end");
    return false;
}
} // namespace DistributedSchedule
} // namespace OHOS
