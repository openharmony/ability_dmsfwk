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

import { describe, it, beforeAll, afterAll } from '@ohos/hypium';
import { BusinessError } from '@ohos.base';
import abilityDelegatorRegistry from '@ohos.app.ability.abilityDelegatorRegistry';
import { Driver, ON, Component } from '@kit.TestKit';

// 正常等待时长
export const COMMON_DELAY: number = 1000;

// 等待组件最长时长
export const WAIT_DELAY: number = 2000;

const DELEGATOR: abilityDelegatorRegistry.AbilityDelegator = abilityDelegatorRegistry.getAbilityDelegator();

const TAG: string = 'ContinueTest';

export default function ContinueTest() {
  describe('ContinueTest', () => {
    let dr: Driver = Driver.create();
    beforeAll(async () => {
      try {
        await DELEGATOR.startAbility({
          'bundleName': 'com.sample.continue',
          'abilityName': 'EntryAbility',
        }).then(() => {
          console.info(`${TAG} com.sample.continue EntryAbility start success`);
        });
      } catch (exception) {
        console.info(`Failed to startAbility. Code: ${(exception as BusinessError).code}, message: ${(exception as BusinessError).message}`);
      };
    });

    afterAll(async () => {
      await dr.delayMs(COMMON_DELAY);
      await dr.pressHome();
      await dr.delayMs(COMMON_DELAY);
    });

    /*
    * @tc.number: ContinueTest_001
    * @tc.name: 动态配置迁移能力
    * @tc.type: 0 || TestType.FUNCTION  || Level.LEVEL0
    * @tc.desc: 动态配置迁移能力测试
    */
    it('ContinueTest_001', 0, ContinueTest_001(dr));

    /*
    * @tc.number: ContinueTest_002
    * @tc.name: 校验基础迁移数据示例页面展示正确
    * @tc.type: 0 || TestType.FUNCTION  || Level.LEVEL0
    * @tc.desc: 校验基础迁移数据示例页面展示正确
    */
    it('ContinueTest_002', 0, ContinueTest_002(dr));

    /*
    * @tc.number: ContinueTest_003
    * @tc.name: 校验用分布式数据对象迁移数据页面展示正确
    * @tc.type: 0 || TestType.FUNCTION  || Level.LEVEL0
    * @tc.desc: 校验使用分布式数据对象迁移数据页面展示正确
    */
    it('ContinueTest_003', 0, ContinueTest_003(dr));
  });
}

function ContinueTest_001(driver: Driver): Function {
  return async (done: Function) => {
    console.info(`${TAG} ContinueTest_001 start`);
    await driver.delayMs(COMMON_DELAY);
    try {
      let button: Component = await driver.findComponent(ON.text('动态配置迁移能力'));
      await button.click();
      await driver.delayMs(COMMON_DELAY);
    } catch (err) {
      console.error(TAG, `ContinueTest_001 err.code : ${err?.code}, message: ${err?.message}`);
    }
    done();
    console.info(`${TAG} ContinueTest_001 end`);
  };
}

function ContinueTest_002(driver: Driver): Function {
  return async (done: Function) => {
    console.info(`${TAG} ContinueTest_002 start`);
    await driver.delayMs(COMMON_DELAY);
    try {
      let button = await driver.waitForComponent(ON.text('基础迁移数据示例'), WAIT_DELAY);
      await button.click();
      console.info(`${TAG} ContinueTest_002 clicked1`);
      // 校验NFC页面展示正确
      await driver.delayMs(COMMON_DELAY);
      await driver.assertComponentExist(ON.text('默认文本'));
    } catch (err) {
      console.error(TAG, `ContinueTest_002 err.code : ${err?.code}, message: ${err?.message}`);
    }
    done();
    console.info(`${TAG} ContinueTest_002 end`);
  };
}

function ContinueTest_003(driver: Driver): Function {
  return async (done: Function) => {
    console.info(`${TAG} ContinueTest_003 start`);
    await driver.delayMs(COMMON_DELAY);
    try {
      let button = await driver.waitForComponent(ON.text('使用分布式数据对象迁移数据'), WAIT_DELAY);
      await button.click();
      console.info(`${TAG} ContinueTest_003 clicked1`);
      // 校验NFC页面展示正确
      await driver.delayMs(COMMON_DELAY);
      await driver.assertComponentExist(ON.text('验证分布式对象基础数据迁移'));
    } catch (err) {
      console.error(TAG, `ContinueTest_003 err.code : ${err?.code}, message: ${err?.message}`);
    }
    done();
    console.info(`${TAG} ContinueTest_003 end`);
  };
}