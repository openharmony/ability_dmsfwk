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

#include "dms_sdk_demo.h"

#include <iostream>
#include <string>
#include <vector>
 
using namespace OHOS;
using namespace DistributedSchedule;
using namespace std;
 
Business g_business;
namespace {
DmsHandler &dmsSourceHandlerdemo = DmsHandler::GetInstance();
std::string g_type = "IDSchedEventListener";
sptr<IDSchedEventListener> listener = sptr<IDSchedEventListener>(new Business());
ContinueInfo g_continueInfo;
}
 
void Business::Register()
{
    int32_t result = 0;
    result = dmsSourceHandlerdemo.RegisterDSchedEventListener(g_type, listener);
    if (result < 0) {
        cout << "RegisterDSchedEventListener failed.CODE = " << result << endl;
    } else {
        cout << "RegisterDSchedEventListener succeed.CODE = " << result << endl;
    }
}
 
void Business::UnRegister()
{
    int32_t result = 0;
    result = dmsSourceHandlerdemo.UnRegisterDSchedEventListener(g_type, listener);
    if (result < 0) {
        cout << "UnRegisterDSchedEventListener failed.CODE = " << result << endl;
    } else {
        cout << "UnRegisterDSchedEventListener succeed.CODE = " << result << endl;
    }
}

void Business::GetContinueInfo()
{
    int32_t result = 0;
    result = dmsSourceHandlerdemo.GetContinueInfo(g_continueInfo);
    if (result < 0) {
        cout << "GetContinueInfo failed.CODE = " << result << endl;
    } else {
        cout << "continueInfo.dstNetworkId_ : " << g_continueInfo.dstNetworkId_ << endl;
        cout << "continueInfo.srcNetworkId_ : " << g_continueInfo.srcNetworkId_ << endl;
    }
}

void Business::DSchedEventNotify(EventNotify& notify)
{
    cout << endl << "DSchedEventNotify Start." << endl;
    cout << "eventResult: " << notify.eventResult_ << endl;
    cout << "srcNetworkId: " << notify.srcNetworkId_ << endl;
    cout << "dstNetworkId: " << notify.dstNetworkId_ << endl;
    cout << "bundleName: " << notify.bundleName_ << endl;
    cout << "moduleName: " << notify.moduleName_ << endl;
    cout << "abilityName: " << notify.abilityName_ << endl;
    cout << "DSchedEventNotify Success." << endl;
}

int main()
{
    cout << "Please select an option to test the interface:" << endl;
    cout << "A.RegisterDSchedEventListener  B.UnRegisterDSchedEventListener C.GetContinueInfo X.exit" << endl;
    cout << "\n" << endl;
 
    char cmd;
    while (cin >> cmd) {
        if (cmd <= 'z' && cmd >= 'a') {
            cmd = cmd + 'A' - 'a';
        }
        switch (cmd) {
            case 'A' : g_business.Register();
                break;
            case 'B' : g_business.UnRegister();
                break;
            case 'C' : g_business.GetContinueInfo();
                break;
            case 'X' :
                return 0;
            default:
                cout << "unknown cmd, please input again" << endl;
        }
    }
 
    return 0;
}