/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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
sptr<IDSchedEventListener> listener = sptr<IDSchedEventListener>(new Business());
ContinueInfo g_continueInfo;
}

void Business::Register(DSchedEventType type)
{
    int32_t result = 0;
    result = dmsSourceHandlerdemo.RegisterDSchedEventListener(type, listener);
    if (result < 0) {
        cout << "RegisterDSchedEventListener failed.CODE = " << result << endl;
    } else {
        cout << "RegisterDSchedEventListener succeed.CODE = " << result << endl;
    }
}

void Business::UnRegister(DSchedEventType type)
{
    int32_t result = 0;
    result = dmsSourceHandlerdemo.UnRegisterDSchedEventListener(type, listener);
    if (result < 0) {
        cout << "UnRegisterDSchedEventListener failed.CODE = " << result << endl;
    } else {
        cout << "UnRegisterDSchedEventListener succeed.CODE = " << result << endl;
    }
}

void Business::GetContinueDeviceInfo()
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

void Business::GetDSchedEventInfo(DSchedEventType type)
{
    vector<EventNotify> notifys;
    int32_t result = dmsSourceHandlerdemo.GetDSchedEventInfo(type, notifys);
    if (result < 0) {
        cout << "GetContinueInfo failed.CODE = " << result << endl;
    } else {
        for (auto notify : notifys) {
            cout << endl << "DSchedEventInfo:" << endl;
            cout << "eventResult: " << notify.eventResult_ << endl;
            cout << "srcNetworkId: " << notify.srcNetworkId_ << endl;
            cout << "dstNetworkId: " << notify.dstNetworkId_ << endl;
            cout << "srcBundleName: " << notify.srcBundleName_ << endl;
            cout << "srcModuleName: " << notify.srcModuleName_ << endl;
            cout << "srcAbilityName: " << notify.srcAbilityName_ << endl;
            cout << "destBundleName: " << notify.destBundleName_ << endl;
            cout << "destModuleName: " << notify.destModuleName_ << endl;
            cout << "destAbilityName: " << notify.destAbilityName_ << endl;
            cout << "developerId: " << notify.developerId_ << endl;
            cout << "dSchedEventType: " << notify.dSchedEventType_ << endl;
            cout << "state: " << notify.state_ << endl << endl;
        }
    }
    notifys.clear();
}

void Business::DSchedEventNotify(EventNotify& notify)
{
    cout << endl << "DSchedEventNotify Start." << endl;
    cout << "eventResult: " << notify.eventResult_ << endl;
    cout << "srcNetworkId: " << notify.srcNetworkId_ << endl;
    cout << "dstNetworkId: " << notify.dstNetworkId_ << endl;
    cout << "srcBundleName: " << notify.srcBundleName_ << endl;
    cout << "srcModuleName: " << notify.srcModuleName_ << endl;
    cout << "srcAbilityName: " << notify.srcAbilityName_ << endl;
    cout << "destBundleName: " << notify.destBundleName_ << endl;
    cout << "destModuleName: " << notify.destModuleName_ << endl;
    cout << "destAbilityName: " << notify.destAbilityName_ << endl;
    cout << "developerId: " << notify.developerId_ << endl;
    cout << "dSchedEventType: " << notify.dSchedEventType_ << endl;
    cout << "state: " << notify.state_ << endl;
    cout << "DSchedEventNotify Success." << endl;
}
int main()
{
    cout << "Please select an option to test the interface:" << endl;
    cout << "A.RegisterContinueListener       B.UnRegisterContinueListener       C.GetContinueInfo" << endl;
    cout << "D.RegisterCollaborationListener  E.UnRegisterCollaborationListener  F.GetCollaborationInfo" << endl;
    cout << "G.RegisterAllListener            H.UnRegisterAllListener            I.GetAllInfo" << endl;
    cout << "J.GetContinueDeviceInfo          X.exit" << endl;
    cout << "\n" << endl;
 
    char cmd;
    while (cin >> cmd) {
        if (cmd <= 'z' && cmd >= 'a') {
            cmd = cmd + 'A' - 'a';
        }
        switch (cmd) {
            case 'A' : g_business.Register(DMS_CONTINUE);
                break;
            case 'B' : g_business.UnRegister(DMS_CONTINUE);
                break;
            case 'C' : g_business.GetDSchedEventInfo(DMS_CONTINUE);
                break;
            case 'D' : g_business.Register(DMS_COLLABORATION);
                break;
            case 'E' : g_business.UnRegister(DMS_COLLABORATION);
                break;
            case 'F' : g_business.GetDSchedEventInfo(DMS_COLLABORATION);
                break;
            case 'G' : g_business.Register(DMS_ALL);
                break;
            case 'H' : g_business.UnRegister(DMS_ALL);
                break;
            case 'I' : g_business.GetDSchedEventInfo(DMS_ALL);
                break;
            case 'J' : g_business.GetContinueDeviceInfo();
                break;
            case 'X' :
                return 0;
            default:
                cout << "unknown cmd, please input again" << endl;
        }
    }
 
    return 0;
}