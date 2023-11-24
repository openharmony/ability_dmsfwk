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
import UIAbility from '@ohos.app.ability.UIAbility';
import Want from '@ohos.app.ability.Want';
import hilog from '@ohos.hilog';
import window from '@ohos.window';
import bundleManager from '@ohos.bundle.bundleManager';
import abilityAccessCtrl, { Permissions } from '@ohos.abilityAccessCtrl';

export default class EntryAbility extends UIAbility {
    async checkAccessToken(permission: Permissions): Promise<abilityAccessCtrl.GrantStatus> {
        let atManager = abilityAccessCtrl.createAtManager();
        let grantStatus: abilityAccessCtrl.GrantStatus = abilityAccessCtrl.GrantStatus.PERMISSION_DENIED;
        let tokenId: number = -1;
        try {
            let bundleInfo: bundleManager.BundleInfo =
                await bundleManager.getBundleInfoForSelf(bundleManager.BundleFlag.GET_BUNDLE_INFO_WITH_APPLICATION);
            let appInfo: bundleManager.ApplicationInfo = bundleInfo.appInfo;
            tokenId = appInfo.accessTokenId;
        } catch (err) {
            hilog.error(0x0000, 'testTag', 'Failed to get bundle info for self, cause %{public}s',
                JSON.stringify(err) ?? '');
        }
        try {
            grantStatus = await atManager.checkAccessToken(tokenId, permission);
        } catch (err) {
            hilog.error(0x0000, 'testTag', 'Failed to check access token, cause %{public}s',
                JSON.stringify(err) ?? '');
        }
        return grantStatus;
    }
    async checkPermissions(): Promise<void> {
        const permissions: Array<Permissions> = ['ohos.permission.DISTRIBUTED_DATASYNC'];
        let grantStatus: abilityAccessCtrl.GrantStatus = await this.checkAccessToken(permissions[0]);
        if (grantStatus === abilityAccessCtrl.GrantStatus.PERMISSION_GRANTED) {
        hilog.info(0x0000, 'testTag', '%{public}s', 'Permission already granted.');
        } else {
            let atManager = abilityAccessCtrl.createAtManager();
            try {
                atManager.requestPermissionsFromUser(this.context, ['ohos.permission.DISTRIBUTED_DATASYNC'], (err, data)=>{
                    hilog.info(0x0000, 'testTag', 'data: %{public}s', JSON.stringify(data));
                    hilog.info(0x0000, 'testTag', 'data permissions: %{public}s', data.permissions);
                    hilog.info(0x0000, 'testTag', 'data authResults: %{public}s', data.authResults);
                });
            } catch (err) {
                hilog.error(0x0000, 'testTag', 'catch err-> %{public}s', JSON.stringify(err) ?? '');
                return;
            }
        }
    }
    onCreate(want: Want, param: AbilityConstant.LaunchParam): void {
        hilog.info(0x0000, 'testTag', '%{public}s', 'Ability onCreate');
        this.checkPermissions();
    }
    onDestroy(): void {
        hilog.info(0x0000, 'testTag', '%{public}s', 'Ability onDestroy');
    }
    onWindowStageCreate(windowStage: window.WindowStage) {
        hilog.info(0x0000, 'testTag', '%{public}s', 'Ability onWindowStageCreate');
        windowStage.loadContent('pages/Index', (err, data) => {
            if (err.code) {
                hilog.error(0x0000, 'testTag', 'Failed to load the content. Cause: %{public}s',
                    JSON.stringify(err) ?? '');
                return;
            }
            hilog.info(0x0000, 'testTag', 'Succeeded in loading the content. Data: %{public}s',
                JSON.stringify(data) ?? '');
        });
    }
    onWindowStageDestroy(): void {
        /* Main window is destroyed, release UI related resources */
        hilog.info(0x0000, 'testTag', '%{public}s', 'Ability onWindowStageDestroy');
    }
    onForeground(): void {
        /* Ability has brought to foreground */
        hilog.info(0x0000, 'testTag', '%{public}s', 'Ability onForeground');
    }
    onBackground(): void {
        /* Ability has back to background */
        hilog.info(0x0000, 'testTag', '%{public}s', 'Ability onBackground');
    }
}
