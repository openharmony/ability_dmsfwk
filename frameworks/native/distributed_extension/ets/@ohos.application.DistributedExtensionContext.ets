/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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

import { BusinessError, AsyncCallback } from '@ohos.base';
import AsyncCallbackWrapper from './utils/AbilityUtils';
import { ConnectOptions } from 'ability.connectOptions';
import ExtensionContext from 'application.ExtensionContext';
import Want from '@ohos.app.ability.Want';

export class Cleaner {
  public ptr: long = 0;

  constructor(ptr: long) {
    this.ptr = ptr;
  }

  native clean(): void;
}

export function callback(cleaner: Cleaner): void {
  cleaner.clean();
}

let destroyRegister = new FinalizationRegistry<Cleaner>(callback);
let unregisterToken = new object();

export default class DistributedExtensionContext extends ExtensionContext {
  constructor(context: long) {
    if (this.nativeEtsContext == 0) {
      this.nativeEtsContext = context;
    }
    this.registerCleaner(this.nativeEtsContext);
  }

  registerCleaner(ptr: long): void {
    this.cleaner = new Cleaner(ptr);
    destroyRegister.register(this, this.cleaner!, unregisterToken);
  }

  unregisterCleaner(): void {
    destroyRegister.unregister(unregisterToken);
  }

  nativeEtsContext: long = 0;
  private cleaner: Cleaner | null = null;

  native nativeConnectServiceExtensionAbility(want: Want, options: ConnectOptions): long;

  native nativeDisconnectServiceExtensionAbility(connection: long, callback: AsyncCallbackWrapper<void>): void;

  connectServiceExtensionAbility(want: Want, options: ConnectOptions): long {
    return this.nativeConnectServiceExtensionAbility(want, options);
  }

  disconnectServiceExtensionAbility(connection: long): Promise<void> {
    return new Promise<void>((resolve: (data: undefined) => void, reject: (err: BusinessError) => void): void => {
      let asyncCall = new AsyncCallbackWrapper<void>((err: BusinessError | null) => {
        if (err == null || err.code == 0) {
          resolve(undefined);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        this.nativeDisconnectServiceExtensionAbility(connection, asyncCall);
      });
    });
  }
}
