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


import AbilityConstant from '@ohos.app.ability.AbilityConstant';
import hilog from '@ohos.hilog';
import UIAbility from '@ohos.app.ability.UIAbility';
import Want from '@ohos.app.ability.Want';
import window from '@ohos.window';
import RemoteDeviceModel from '../Model/RemoteDeviceModel';
import rpc from '@ohos.rpc';
import bundleManager from '@ohos.bundle.bundleManager';
import abilityAccessCtrl, { Permissions } from '@ohos.abilityAccessCtrl';

const printLog = '[MainAbility]';
const remoteDeviceModel = new RemoteDeviceModel;
let messageProxy: null| rpc.IRemoteObject = null;
let connectedAbility;
const BUNDLE_NAME = 'com.dms.stage_manual_test_suite';

function ConnectRemoteAbility() {
  showLog(printLog + "connect service extension ability begin")
  showLog(printLog + "connect remote device id is " + globalThis.selectDevice)
  let want = {
    bundleName: BUNDLE_NAME,
    abilityName: "MyServiceExtensionAbility",
    deviceId: globalThis.selectDevice
  }
  connectedAbility = globalThis.context.connectAbility(want, {
    onConnect: async function (elementName, proxy) {
      showLog(printLog + "service extension ability connect success")
      if (proxy === null) {
        showLog("can not get proxy")
        return
      }
      messageProxy = proxy
      showLog(printLog + "get proxy, elementName: " + elementName)
    },
    onDisconnect: function () {
      showLog(printLog + "service extension ability disconnect success")
    },
    onFailed: function () {
      showLog(printLog + "service extension ability connect fail")
    }
  })
  showLog(printLog + "connect service extension ability, connectId = " + connectedAbility)
}

async function DisconnectRemoteAbility() {
  showLog(printLog + "disconnect service extension ability begin")
  showLog(printLog + "disconnect remote device id is " + globalThis.selectDevice)
  await globalThis.context.disconnectAbility(connectedAbility)
  showLog(printLog + "disconnect service extension ability, connectId = " + connectedAbility)
  connectedAbility = null
}

async function SendMessage(): Promise<void> {
  if (messageProxy === null) {
    showLog(printLog + "can not get proxy");
  } else {
    showLog(printLog + "send message : " + AppStorage.get<string>("message"));
    let option = new rpc.MessageOption();
    let data = new rpc.MessageSequence();
    let reply = new rpc.MessageSequence();
    data.writeString(AppStorage.get<string>("message"));

    await messageProxy.sendMessageRequest(1, data, reply, option);
    showLog(printLog + "send message success");

    globalThis.receiveMessage = reply.readString();
    showLog(printLog + "receive reply message : " + globalThis.receiveMessage);
  }
}

function showLog(logMessage: string): void {
  console.log(logMessage)
  AppStorage.set<string>("receiveMessage", AppStorage.get<string>("receiveMessage") + logMessage + "\n");
}

export default class EntryAbility extends UIAbility {
  //获取当前应用的权限的授予状态：grantStatus（授予返回：0，未授予：-1）
  async getGrantStatus(permission: Permissions): Promise<abilityAccessCtrl.GrantStatus>{
    let atManager = abilityAccessCtrl.createAtManager();
    let grantStatus : abilityAccessCtrl.GrantStatus = -1;

    //获取tokenId:
    let tokenId :number = 0;
    try {
      let bundleInfo: bundleManager.BundleInfo = await bundleManager.getBundleInfoForSelf(bundleManager.BundleFlag.GET_BUNDLE_INFO_WITH_APPLICATION);
      let appInfo: bundleManager.ApplicationInfo = bundleInfo.appInfo;
      tokenId = appInfo.accessTokenId;
    }catch (err){
      hilog.error(0x0000, printLog,'Failed to get bundle info for self,cause ${public}s' ,JSON.stringify(err)??'')
    }

    // 检验应用是否被授予此权限，授予返回：PERMISSION_GRANTED = 0，未授予：PERMISSION_DENIED = -1
    try {
      grantStatus = await atManager.checkAccessToken(tokenId,permission);
    }catch (err){
      hilog.error(0x0000, printLog,'Failed to check Access Token ,cause %{public}s',JSON.stringify(err)??'')
    }

    return grantStatus;
  }

  //检验权限授予情况&动态申请权限
  async checkPermissions():Promise<void>{
    const permissions:Array<Permissions> = ['ohos.permission.DISTRIBUTED_DATASYNC'];

    let grantStatus:abilityAccessCtrl.GrantStatus = await this.getGrantStatus(permissions[0]);
    // 检验权限授予情况
    if(grantStatus === abilityAccessCtrl.GrantStatus.PERMISSION_GRANTED){
      //已授予
      hilog.info(0x0000, printLog,'%{public}s','Permission already granted.');
    }else{
      //未授予,向用户弹框动态申请授权
      let atManager = abilityAccessCtrl.createAtManager();
      try {
        atManager.requestPermissionsFromUser(this.context, ['ohos.permission.DISTRIBUTED_DATASYNC'], (err, data) => {
          hilog.info(0x0000, printLog, 'data:%{public}s',JSON.stringify(data));
          hilog.info(0x0000, printLog, 'data: data.permissions %{public}s',data.permissions);
          hilog.info(0x0000, printLog, 'data: data.authResults %{public}s',data.authResults);
        });
      } catch(err) {
        hilog.error(0x0000, printLog, 'catch err , %{public}s', JSON.stringify(err)??'');
        return;
      }
    }
  }
  onCreate(want: Want, launchParam: AbilityConstant.LaunchParam): void {
    console.log("[ServiceExtensionDemo] MainAbility onCreate")
    this.checkPermissions();
    // this.context.startAbility
    globalThis.abilityWant = want;
    globalThis.context = this.context;
    globalThis.DeviceIdList = [];
    globalThis.selectDevice;
    globalThis.receiveMessage = "";
  }

  onDestroy(): void {
    AppStorage.set<string>("receiveMessage", "")
    console.log("[ServiceExtensionDemo] MainAbility onDestroy")
  }

  onWindowStageCreate(windowStage: window.WindowStage): void {
    // Main window is created, set main page for this ability
    console.log("[ServiceExtension] MainAbility onWindowStageCreate")
    globalThis.ConnectRemoteAbility = ConnectRemoteAbility();
    globalThis.DisconnectRemoteAbility = DisconnectRemoteAbility();
    globalThis.SendMessage = SendMessage();
    windowStage.loadContent("pages/MainPage", (err, data) => {
      if (err.code) {
        console.error('Failed to load the content. Cause:' + JSON.stringify(err));
        return;
      }
      console.info('Succeeded in loading the content. Data: ' + JSON.stringify(data))
    });
  }

  onWindowStageDestroy(): void {
    // Main window is destroyed, release UI related resources
    hilog.info(0x0000, printLog, '%{public}s', 'Ability onWindowStageDestroy');
  }

  onForeground(): void {
    // Ability has brought to foreground
    hilog.info(0x0000, printLog, '%{public}s', 'Ability onForeground');
  }

  onBackground(): void {
    // Ability has back to background
    hilog.info(0x0000, printLog, '%{public}s', 'Ability onBackground');
  }
}
