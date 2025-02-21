/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "softbus_file_adapter.h"
#include "dtbcollabmgr_log.h"
#include "inner_transport.h"
#include "trans_type_enhanced.h"
#include "softbus_error_code.h"
#include <fcntl.h>
#include <unistd.h>
#include <cstdio>
#include <sys/stat.h>
#include <cstdlib>
#include <string>
#include <climits>

namespace OHOS {
namespace DistributedCollab {

IMPLEMENT_SINGLE_INSTANCE(SoftbusFileAdpater);

namespace {
    static const std::string TAG = "SoftbusFileAdpaterInner";
    static constexpr int32_t SUCCESS_CODE = 0;
    static constexpr int32_t TEMP_DIR_PERMISSION = 0700;
}

static int OpenFile(const char* filename, int32_t flag, int32_t mode)
{
    return SoftbusFileAdpater::GetInstance().Open(filename, flag, mode);
}

static int CloseFile(int32_t fd)
{
    return SoftbusFileAdpater::GetInstance().Close(fd);
}

static int RemoveFile(const char* filename)
{
    return SoftbusFileAdpater::GetInstance().Remove(filename);
}

int32_t SoftbusFileAdpater::SetFileSchema(int32_t socketId)
{
    HILOGI("start to set file schema");
    SocketFileSchema schema;
    schema.OpenFd = OpenFile;
    schema.CloseFd = CloseFile;
    schema.RemoveFd = RemoveFile;

    int32_t ret = RegisterFileSchema(socketId, &schema);
    if (ret != SOFTBUS_OK) {
        return -REGISTER_FILE_SCHEMA_FAILED;
    }
    return ERR_OK;
}

int32_t SoftbusFileAdpater::Open(const char* filename, int32_t flag, int32_t mode)
{
    HILOGI("dfile open file callback enter");
    if (filename == nullptr) {
        HILOGE("null file name");
        return -INVALID_FILE_NAME;
    }
    int32_t ret = CreateParentDirs(filename);
    if (ret != ERR_OK) {
        return ret;
    }
    // stack, no need delete
    char realPath[PATH_MAX] = {0};
    if (realpath(filename, realPath) == nullptr) {
        if (errno != ENOENT) {
            HILOGE("get real path failed, %{public}s, err=%{public}d", filename, errno);
            return -INVALID_FILE_NAME;
        }
        return open(filename, flag, mode);
    }
    return open(realPath, flag, mode);
}

int32_t SoftbusFileAdpater::CreateParentDirs(const char* filename)
{
    HILOGI("create all parent dirs");
    std::string path(filename);
    size_t pos = 0;
    int32_t ret = ERR_OK;
    while ((pos = path.find_first_of('/', pos + 1)) != std::string::npos) {
        std::string dir = path.substr(0, pos);
        ret = CreateDir(dir);
        if (ret != ERR_OK) {
            return ret;
        }
    }
    return ERR_OK;
}

int32_t SoftbusFileAdpater::CreateDir(const std::string& path)
{
    HILOGI("create dir");
    int32_t ret = mkdir(path.c_str(), TEMP_DIR_PERMISSION);
    if (ret != SUCCESS_CODE) {
        HILOGE("create %{public}s failed, error=%{public}d", path.c_str(), ret);
        return -CREATE_DIR_FAILED;
    }
    return ERR_OK;
}

int32_t SoftbusFileAdpater::Close(int32_t fd)
{
    HILOGI("dfile close file callback enter");
    if (fd < 0) {
        HILOGE("Invalid file descriptor");
        return -INVALID_PARAMETERS_ERR;
    }
    return close(fd);
}

int32_t SoftbusFileAdpater::Remove(const char* filename)
{
    HILOGI("dfile remove file callback enter");
    if (filename == nullptr) {
        HILOGE("null file name");
        return -INVALID_FILE_NAME;
    }
    char realPath[PATH_MAX] = {0};
    if (realpath(filename, realPath) == nullptr && errno != ENOENT) {
        HILOGE("get real path failed, %{public}s, err=%{public}d", filename, errno);
        return -INVALID_FILE_NAME;
    }
    return remove(filename);
}
}
}