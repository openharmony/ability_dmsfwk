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
#ifndef DLOPEN_MOCK_H
#define DLOPEN_MOCK_H

#include <dlfcn.h>
#include <gmock/gmock.h>

namespace OHOS {
namespace DistributedCollab {
class MockDlfcn {
public:
    MockDlfcn() {};
    virtual ~MockDlfcn() {};

    virtual void *dlopen (const char *file, int mode) = 0;
};

class DlfcnMock : public MockDlfcn {
public:
    DlfcnMock();
    ~DlfcnMock() override;

    static DlfcnMock& GetMock();

    MOCK_METHOD(void *, dlopen, (const char *file, int mode), (override));
private:
    static DlfcnMock *gMock;
};
}  // namespace DistributedCollab
}  // namespace OHOS
#endif
