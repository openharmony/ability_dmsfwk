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

import UIAbility from '@ohos.app.ability.UIAbility'
import AbilityConstant from '@ohos.app.ability.AbilityConstant'
import accessControl, { Permissions } from "@ohos.abilityAccessCtrl";
import bundle from '@ohos.bundle';
import distributedObject from '@ohos.data.distributedDataObject';
import Logger from './Logger';
import abilityAccessCtrl from '@ohos.abilityAccessCtrl';
import bundleManager from '@ohos.bundle.bundleManager';
import window from '@ohos.window';

const BUNDLE_NAME = "com.ohos.continuationManualTestSuite.hmservice"
const PERMISSION_REJECT = -1

class ContentStorage {
}


export default class MainAbility extends UIAbility {

    contentStorage : LocalStorage
    sessionId : string
    g_object: distributedObject.DataObject|null = null;

    async handleParam(want) {
        this.g_object = distributedObject.create(this.context, {data:undefined});
        if (this.g_object) {
            this.g_object = undefined;
        }
        if (!this.g_object) {
            this.g_object = distributedObject.create(this.context, {name: undefined});
        }
        this.sessionId = want.parameters.session
        Logger.info(`continuation sessionId:  ${this.sessionId}`)


        await this.g_object.setSessionId(this.sessionId); // set session id, so it will sync data from remote device
        Logger.info(`this.g_object_name = ${this.g_object['name']}`);

        AppStorage.setOrCreate<string>('ContinueStudy', this.g_object['name'])
        let workInput = want.parameters.work // get user data from want params
        Logger.info(`work input ${workInput}`)
        AppStorage.setOrCreate<string>('ContinueWork', workInput)
        this.contentStorage = new LocalStorage();
        Logger.info('ready to restore');
        this.context.restoreWindowStage(this.contentStorage);
    }

    onCreate(want, launchParam: AbilityConstant.LaunchParam) {
        Logger.info("[Demo] MainAbility onCreate")
        if (launchParam.launchReason == AbilityConstant.LaunchReason.CONTINUATION) {
            this.handleParam(want);
        }
    }

    onContinue(wantParam : {[key: string]: any}) {
        Logger.info(`onContinue version = ${wantParam.version}, targetDevice: ${wantParam.targetDevice}`)
        let workInput = AppStorage.get<string>('ContinueWork');
        Logger.info(`onContinue work input = ${workInput}`);
        if (this.g_object) {
            this.g_object = undefined;
        }
        this.g_object = distributedObject.create(this.context, {name: undefined});

        this.sessionId = distributedObject.genSessionId();
        wantParam['session'] = this.sessionId;
        if (this.g_object != null) {
            // 分布式对象设置 sessionId
            this.g_object.setSessionId(this.sessionId, () => {
                Logger.info("join session");
            })
        }
        this.g_object['name'] = AppStorage.get<string>('ContinueStudy');
        Logger.info(`onContinue sessionId = ${this.sessionId}, name = ${this.g_object['name']}`)
        this.g_object.save(wantParam.targetDevice, (err, result)=>{
            if (err) {
                Logger.info(" save callback err: ", JSON.stringify(err));
                return;
            }
            Logger.info('save callback,result = ', JSON.stringify(result));
        });
        wantParam["work"] = workInput // set user input data into want params
        return 0;
    }

    onNewWant(want, launchParam) {
        Logger.info("MainAbility onNewWant")
        if (launchParam.launchReason == AbilityConstant.LaunchReason.CONTINUATION) {
            this.handleParam(want);
        }
    }

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
            Logger.info('Failed to get bundle info for self,cause ${public}s' ,JSON.stringify(err)??'');
        }

        // 检验应用是否被授予此权限，授予返回：PERMISSION_GRANTED = 0，未授予：PERMISSION_DENIED = -1
        try {
            grantStatus = await atManager.checkAccessToken(tokenId,permission);
        }catch (err){
            Logger.info('Failed to check Access Token ,cause %{public}s' ,JSON.stringify(err)??'');
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
            Logger.info('Permission already granted.');
        }else{
            //未授予,向用户弹框动态申请授权
            let atManager = abilityAccessCtrl.createAtManager();
            try {
                atManager.requestPermissionsFromUser(this.context, ['ohos.permission.DISTRIBUTED_DATASYNC'], (err, data) => {
                    Logger.info('data: ' + JSON.stringify(data));
                });
            }catch (err){
                Logger.info('catch err ,' + JSON.stringify(err)??'');
                return;
            }
        }
    }

    onDestroy() {
        Logger.info("MainAbility onDestroy")
    }

    onWindowStageCreate(windowStage: window.WindowStage) {
        // Main window is created, set main page for this ability
        Logger.info("MainAbility onWindowStageCreate");
        this.checkPermissions()
        windowStage.loadContent('pages/Index', (err, data) => {
            if (err.code) {
                Logger.error(0x0000, 'testTag', 'Failed to load the content. Cause: %{public}s', JSON.stringify(err) ?? '');
                return;
            }
            Logger.info(0x0000, 'testTag', 'Succeeded in loading the content. Data: %{public}s', JSON.stringify(data) ?? '');
        });
    }

    onWindowStageRestore(windowStage: window.WindowStage) {
        Logger.info("MainAbility onWindowStageRestore");
        this.checkPermissions();
    }

    onWindowStageDestroy() {
        // Main window is destroyed, release UI related resources
        Logger.info("MainAbility onWindowStageDestroy")
    }

    onForeground() {
        // Ability has brought to foreground
        Logger.info("MainAbility onForeground")
    }

    onBackground() {
        // Ability has back to background
        Logger.info("MainAbility onBackground")
    }
};
