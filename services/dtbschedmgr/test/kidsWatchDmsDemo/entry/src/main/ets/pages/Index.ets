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
import { abilityConnectionManager } from '@kit.DistributedServiceKit'
import { continueManager } from '@kit.AbilityKit';
import { common } from '@kit.AbilityKit';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { util } from '@kit.ArkTS';

let dialogTitle: string = '';
let dialogMessage: string = '';

@CustomDialog
struct CustomDialog01 {
  controller: CustomDialogController;
  @Prop dialogTitle: string = 'Info';
  @Prop dialogMessage: string = '';

  build() {
    Column() {
      Text(this.dialogTitle)
        .fontSize(18)
        .fontWeight(FontWeight.Bold)
        .margin({ bottom: 8 })

      Text(this.dialogMessage)
        .fontSize(14)
        .maxLines(10)
        .textOverflow({ overflow: TextOverflow.Ellipsis })
    }
    .height('auto')
    .padding(16)
    .justifyContent(FlexAlign.Center)
  }
}

@Entry
@Component
struct Index {
  @State currentSessionId: number = -1;
  @State connectionStatus: string = 'Disconnected';
  @State messageToSend: string = 'Hello from OpenHarmony';
  @State dataToSend: string = 'Test data payload';
  @State eventLog: Array<string> = [];

  private listenersActive: Map<string, boolean> = new Map([
    ['connect', false],
    ['disconnect', false],
    ['receiveMessage', false],
    ['receiveData', false],
    ['prepareContinue', false]
  ]);

  private connectCallback: ((callbackInfo: Object) => void) | null = null;
  private disconnectCallback: ((callbackInfo: Object) => void) | null = null;
  private receiveMessageCallback: ((callbackInfo: Object) => void) | null = null;
  private receiveDataCallback: ((callbackInfo: Object) => void) | null = null;
  private prepareContinueCallback: ((callbackInfo: Object) => void) | null = null;

  dialogController: CustomDialogController = new CustomDialogController({
    builder: CustomDialog01({
      dialogTitle: dialogTitle,
      dialogMessage: dialogMessage
    }),
  })

  private showDialog(title: string, message: string): void {
    dialogTitle = title;
    dialogMessage = message;
    this.dialogController.open();
  }

  private validateSession(): boolean {
    return true;
  }

  private logEvent(eventType: string, data: Object): void {
    const timestamp = new Date().toLocaleTimeString();
    const logEntry = `[${timestamp}] ${eventType}: ${JSON.stringify(data)}`;
    this.eventLog = [...this.eventLog.slice(-49), logEntry];
    hilog.info(1, 'EventLog', logEntry);
  }

  build() {
    Scroll() {
      Column() {
        Row() {
          Text('DMSFWK API Test')
            .fontSize(20)
            .fontWeight(FontWeight.Bold)
            .fontColor('#182431')
        }
        .width('100%')
        .margin({ top: 8, bottom: 8 })

        this.buildSessionManagementSection()
        this.buildConnectionManagementSection()
        this.buildDataTransferSection()
        this.buildEventListeningSection()
        this.buildContinueManagerSection()
        this.buildStatusSection()
      }
      .width('100%')
      .padding({ left: 12, right: 12, bottom: 16 })
    }
  }

  @Builder
  buildSessionManagementSection() {
    Column() {
      Text('会话管理 (abilityConnectionManager)')
        .fontSize(16)
        .fontWeight(FontWeight.Medium)
        .fontColor('#182431')
        .width('100%')
        .margin({ top: 12, bottom: 8 })

      Row() {
        Text('run：CreateAbilityConnectionSession')
          .fontSize(14)
          .fontColor('#66182431')
        Blank()
        Button('run')
          .fontSize(12)
          .height(28)
          .margin({ left: 8 })
          .onClick(() => { this.testCreateAbilityConnectionSession(); })
      }
      .width('100%')
      .padding(12)
      .backgroundColor('#FFFFFF')
      .borderRadius(8)
      .margin({ bottom: 8 })

      Row() {
        Text('run：DestroyAbilityConnectionSession')
          .fontSize(14)
          .fontColor('#66182431')
        Blank()
        Button('run')
          .fontSize(12)
          .height(28)
          .margin({ left: 8 })
          .onClick(() => { this.testDestroyAbilityConnectionSession(); })
      }
      .width('100%')
      .padding(12)
      .backgroundColor('#FFFFFF')
      .borderRadius(8)
      .margin({ bottom: 8 })

      Row() {
        Text('run：GetPeerInfoById')
          .fontSize(14)
          .fontColor('#66182431')
        Blank()
        Button('run')
          .fontSize(12)
          .height(28)
          .margin({ left: 8 })
          .onClick(() => { this.testGetPeerInfoById(); })
      }
      .width('100%')
      .padding(12)
      .backgroundColor('#FFFFFF')
      .borderRadius(8)
      .margin({ bottom: 8 })
    }
  }

  @Builder
  buildConnectionManagementSection() {
    Column() {
      Text('连接管理 (abilityConnectionManager)')
        .fontSize(16)
        .fontWeight(FontWeight.Medium)
        .fontColor('#182431')
        .width('100%')
        .margin({ top: 12, bottom: 8 })

      Row() {
        Text('run：Connect')
          .fontSize(14)
          .fontColor('#66182431')
        Blank()
        Button('run')
          .fontSize(12)
          .height(28)
          .margin({ left: 8 })
          .onClick(() => { this.testConnect(); })
      }
      .width('100%')
      .padding(12)
      .backgroundColor('#FFFFFF')
      .borderRadius(8)
      .margin({ bottom: 8 })

      Row() {
        Text('run：AcceptConnect')
          .fontSize(14)
          .fontColor('#66182431')
        Blank()
        Button('run')
          .fontSize(12)
          .height(28)
          .margin({ left: 8 })
          .onClick(() => { this.testAcceptConnect(); })
      }
      .width('100%')
      .padding(12)
      .backgroundColor('#FFFFFF')
      .borderRadius(8)
      .margin({ bottom: 8 })

      Row() {
        Text('run：Disconnect')
          .fontSize(14)
          .fontColor('#66182431')
        Blank()
        Button('run')
          .fontSize(12)
          .height(28)
          .margin({ left: 8 })
          .onClick(() => { this.testDisconnect(); })
      }
      .width('100%')
      .padding(12)
      .backgroundColor('#FFFFFF')
      .borderRadius(8)
      .margin({ bottom: 8 })

      Row() {
        Text('run：Reject')
          .fontSize(14)
          .fontColor('#66182431')
        Blank()
        Button('run')
          .fontSize(12)
          .height(28)
          .margin({ left: 8 })
          .onClick(() => { this.testReject(); })
      }
      .width('100%')
      .padding(12)
      .backgroundColor('#FFFFFF')
      .borderRadius(8)
      .margin({ bottom: 8 })
    }
  }

  @Builder
  buildDataTransferSection() {
    Column() {
      Text('数据传输 (abilityConnectionManager)')
        .fontSize(16)
        .fontWeight(FontWeight.Medium)
        .fontColor('#182431')
        .width('100%')
        .margin({ top: 12, bottom: 8 })

      TextInput({ placeholder: 'Enter message', text: this.messageToSend })
        .width('100%')
        .height(40)
        .margin({ bottom: 8 })
        .onChange((value: string) => { this.messageToSend = value; })

      Row() {
        Text('run：SendMessage')
          .fontSize(14)
          .fontColor('#66182431')
        Blank()
        Button('run')
          .fontSize(12)
          .height(28)
          .margin({ left: 8 })
          .onClick(() => { this.testSendMessage(); })
      }
      .width('100%')
      .padding(12)
      .backgroundColor('#FFFFFF')
      .borderRadius(8)
      .margin({ bottom: 8 })

      TextInput({ placeholder: 'Enter data', text: this.dataToSend })
        .width('100%')
        .height(40)
        .margin({ bottom: 8 })
        .onChange((value: string) => { this.dataToSend = value; })

      Row() {
        Text('run：SendData')
          .fontSize(14)
          .fontColor('#66182431')
        Blank()
        Button('run')
          .fontSize(12)
          .height(28)
          .margin({ left: 8 })
          .onClick(() => { this.testSendData(); })
      }
      .width('100%')
      .padding(12)
      .backgroundColor('#FFFFFF')
      .borderRadius(8)
      .margin({ bottom: 8 })

      Row() {
        Text('run：SendImage')
          .fontSize(14)
          .fontColor('#66182431')
        Blank()
        Button('run')
          .fontSize(12)
          .height(28)
          .margin({ left: 8 })
          .onClick(() => { this.testSendImage(); })
      }
      .width('100%')
      .padding(12)
      .backgroundColor('#FFFFFF')
      .borderRadius(8)
      .margin({ bottom: 8 })
    }
  }

  @Builder
  buildEventListeningSection() {
    Column() {
      Text('事件监听 (abilityConnectionManager)')
        .fontSize(16)
        .fontWeight(FontWeight.Medium)
        .fontColor('#182431')
        .width('100%')
        .margin({ top: 12, bottom: 8 })

      Row() {
        Button('On')
          .fontSize(12)
          .height(28)
          .onClick(() => { this.testOnConnect(); })
        Button('Off')
          .fontSize(12)
          .height(28)
          .margin({ left: 8 })
          .onClick(() => { this.testOffConnect(); })
        Text('Connect')
          .fontSize(14)
          .fontColor('#66182431')
          .margin({ left: 8 })
        Blank()
      }
      .width('100%')
      .padding(12)
      .backgroundColor('#FFFFFF')
      .borderRadius(8)
      .margin({ bottom: 8 })

      Row() {
        Button('On')
          .fontSize(12)
          .height(28)
          .onClick(() => { this.testOnDisconnect(); })
        Button('Off')
          .fontSize(12)
          .height(28)
          .margin({ left: 8 })
          .onClick(() => { this.testOffDisconnect(); })
        Text('Disconnect')
          .fontSize(14)
          .fontColor('#66182431')
          .margin({ left: 8 })
        Blank()
      }
      .width('100%')
      .padding(12)
      .backgroundColor('#FFFFFF')
      .borderRadius(8)
      .margin({ bottom: 8 })

      Row() {
        Button('On')
          .fontSize(12)
          .height(28)
          .onClick(() => { this.testOnReceiveMessage(); })
        Button('Off')
          .fontSize(12)
          .height(28)
          .margin({ left: 8 })
          .onClick(() => { this.testOffReceiveMessage(); })
        Text('ReceiveMessage')
          .fontSize(14)
          .fontColor('#66182431')
          .margin({ left: 8 })
        Blank()
      }
      .width('100%')
      .padding(12)
      .backgroundColor('#FFFFFF')
      .borderRadius(8)
      .margin({ bottom: 8 })

      Row() {
        Button('On')
          .fontSize(12)
          .height(28)
          .onClick(() => { this.testOnReceiveData(); })
        Button('Off')
          .fontSize(12)
          .height(28)
          .margin({ left: 8 })
          .onClick(() => { this.testOffReceiveData(); })
        Text('ReceiveData')
          .fontSize(14)
          .fontColor('#66182431')
          .margin({ left: 8 })
        Blank()
      }
      .width('100%')
      .padding(12)
      .backgroundColor('#FFFFFF')
      .borderRadius(8)
      .margin({ bottom: 8 })
    }
  }

  @Builder
  buildContinueManagerSection() {
    Column() {
      Text('应用继续 (continueManager)')
        .fontSize(16)
        .fontWeight(FontWeight.Medium)
        .fontColor('#182431')
        .width('100%')
        .margin({ top: 12, bottom: 8 })

      Row() {
        Button('On')
          .fontSize(12)
          .height(28)
          .onClick(() => { this.testOnPrepareContinue(); })
        Button('Off')
          .fontSize(12)
          .height(28)
          .margin({ left: 8 })
          .onClick(() => { this.testOffPrepareContinue(); })
        Text('PrepareContinue')
          .fontSize(14)
          .fontColor('#66182431')
          .margin({ left: 8 })
        Blank()
      }
      .width('100%')
      .padding(12)
      .backgroundColor('#FFFFFF')
      .borderRadius(8)
      .margin({ bottom: 8 })
    }
  }

  @Builder
  buildStatusSection() {
    Column() {
      Text('状态信息')
        .fontSize(16)
        .fontWeight(FontWeight.Medium)
        .fontColor('#182431')
        .width('100%')
        .margin({ top: 12, bottom: 8 })

      Row() {
        Text('Session ID:')
          .fontSize(14)
          .fontColor('#66182431')
        Text(this.currentSessionId === -1 ? 'None' : this.currentSessionId.toString())
          .fontSize(14)
          .fontColor('#182431')
          .margin({ left: 8 })
      }
      .width('100%')
      .padding(12)
      .backgroundColor('#FFFFFF')
      .borderRadius(8)
      .margin({ bottom: 8 })

      Row() {
        Text('Connection:')
          .fontSize(14)
          .fontColor('#66182431')
        Text(this.connectionStatus)
          .fontSize(14)
          .fontColor('#182431')
          .margin({ left: 8 })
      }
      .width('100%')
      .padding(12)
      .backgroundColor('#FFFFFF')
      .borderRadius(8)
      .margin({ bottom: 8 })

      Text('事件日志')
        .fontSize(14)
        .fontColor('#66182431')
        .width('100%')
        .margin({ top: 4, bottom: 4 })

      Scroll() {
        Column() {
          ForEach(this.eventLog, (log: string, index: number) => {
            Text(log)
              .fontSize(12)
              .fontColor('#66182431')
              .width('100%')
              .margin({ bottom: 2 })
          }, (log: string, index: number) => `${index}_${log}`)
        }
        .width('100%')
        .padding(8)
      }
      .width('100%')
      .height(150)
      .backgroundColor('#F1F3F5')
      .borderRadius(8)
      .margin({ bottom: 8 })
    }
  }

  aboutToDisappear(): void {
    if (this.currentSessionId !== -1) {
      if (this.listenersActive.get('connect')) {
        try {
          abilityConnectionManager.off('connect', this.currentSessionId);
        } catch (error) {
          hilog.warn(1, 'cleanup', 'Failed to remove connect listener');
        }
      }
      if (this.listenersActive.get('disconnect')) {
        try {
          abilityConnectionManager.off('disconnect', this.currentSessionId);
        } catch (error) {
          hilog.warn(1, 'cleanup', 'Failed to remove disconnect listener');
        }
      }
      if (this.listenersActive.get('receiveMessage')) {
        try {
          abilityConnectionManager.off('receiveMessage', this.currentSessionId);
        } catch (error) {
          hilog.warn(1, 'cleanup', 'Failed to remove receiveMessage listener');
        }
      }
      if (this.listenersActive.get('receiveData')) {
        try {
          abilityConnectionManager.off('receiveData', this.currentSessionId);
        } catch (error) {
          hilog.warn(1, 'cleanup', 'Failed to remove receiveData listener');
        }
      }
    }
    if (this.listenersActive.get('prepareContinue')) {
      try {
        const context = getContext(this) as common.UIAbilityContext;
        continueManager.off('prepareContinue', context);
      } catch (error) {
        hilog.warn(1, 'cleanup', 'Failed to remove prepareContinue listener');
      }
    }
  }

  private async testCreateAbilityConnectionSession(): Promise<void> {
    const context =
      ......as common.UIAbilityContext;
    let TestPeerInfo: abilityConnectionManager.PeerInfo = {
      deviceId: '',
      bundleName: 'com.example.peer',
      moduleName: 'entry',
      abilityName: 'EntryAbility',
      serviceName: 'com.example.peer.service'
    };

    let TestConnectOptions: abilityConnectionManager.ConnectOptions = {
      needSendData: true
    };

    try {
      const sessionId: number = abilityConnectionManager.createAbilityConnectionSession(
        'com.example.test.service',
        context,
        TestPeerInfo,
        TestConnectOptions
      )
      this.currentSessionId = sessionId;
      hilog.info(1, 'testCreateAbilityConnectionSession', `[返回值] sessionId: ${sessionId}`);
      this.showDialog('Success', `Session created with ID: ${sessionId}`);
    } catch (error) {
      const errorInfo: string = JSON.stringify(error);
      hilog.warn(1, 'testCreateAbilityConnectionSession', `[返回值] errorInfo: ${errorInfo}`);
      this.showDialog('Error', errorInfo);
    }
  }

  private async testDestroyAbilityConnectionSession(): Promise<void> {
    if (!this.validateSession()) return;

    try {
      abilityConnectionManager.destroyAbilityConnectionSession(this.currentSessionId);
      hilog.info(1, 'testDestroyAbilityConnectionSession', 'Session destroyed');
      this.showDialog('Success', `Session ${this.currentSessionId} destroyed`);
      this.currentSessionId = -1;
      this.connectionStatus = 'Disconnected';
    } catch (error) {
      hilog.warn(1, 'testDestroyAbilityConnectionSession', `error: ${JSON.stringify(error)}`);
      this.showDialog('Error', JSON.stringify(error));
    }
  }

  private async testGetPeerInfoById(): Promise<void> {
    if (!this.validateSession()) return;

    try {
      const peerInfo = abilityConnectionManager.getPeerInfoById(this.currentSessionId);
      hilog.info(1, 'testGetPeerInfoById', `peerInfo: ${JSON.stringify(peerInfo)}`);
      const infoStr = `Device: ${peerInfo?.deviceId}\nBundle: ${peerInfo?.bundleName}\nModule: ${peerInfo?.moduleName}\nAbility: ${peerInfo?.abilityName}\nService: ${peerInfo?.serviceName}`;
      this.showDialog('Peer Info', infoStr);
    } catch (error) {
      hilog.warn(1, 'testGetPeerInfoById', `error: ${JSON.stringify(error)}`);
      this.showDialog('Error', JSON.stringify(error));
    }
  }

  private async testConnect(): Promise<void> {
    if (!this.validateSession()) return;

    try {
      await abilityConnectionManager.connect(this.currentSessionId);
      this.connectionStatus = 'Connecting...';
      hilog.info(1, 'testConnect', 'Connection initiated');
      this.showDialog('Info', 'Connection initiated. Wait for callback.');
    } catch (error) {
      hilog.warn(1, 'testConnect', `error: ${JSON.stringify(error)}`);
      this.connectionStatus = 'Connection Failed';
      this.showDialog('Error', JSON.stringify(error));
    }
  }

  private async testAcceptConnect(): Promise<void> {
    if (!this.validateSession()) return;

    try {
      await abilityConnectionManager.acceptConnect(this.currentSessionId, '');
      hilog.info(1, 'testAcceptConnect', 'Connection accepted');
      this.showDialog('Success', 'Connection accepted');
    } catch (error) {
      hilog.warn(1, 'testAcceptConnect', `error: ${JSON.stringify(error)}`);
      this.showDialog('Error', JSON.stringify(error));
    }
  }

  private async testDisconnect(): Promise<void> {
    if (!this.validateSession()) return;

    try {
      abilityConnectionManager.disconnect(this.currentSessionId);
      this.connectionStatus = 'Disconnected';
      hilog.info(1, 'testDisconnect', 'Disconnected');
      this.showDialog('Success', 'Disconnected');
    } catch (error) {
      hilog.warn(1, 'testDisconnect', `error: ${JSON.stringify(error)}`);
      this.showDialog('Error', JSON.stringify(error));
    }
  }

  private async testReject(): Promise<void> {
    if (!this.validateSession()) return;

    try {
      abilityConnectionManager.reject('', 'User rejected');
      this.connectionStatus = 'Rejected';
      hilog.info(1, 'testReject', 'Connection rejected');
      this.showDialog('Success', 'Connection rejected');
    } catch (error) {
      hilog.warn(1, 'testReject', `error: ${JSON.stringify(error)}`);
      this.showDialog('Error', JSON.stringify(error));
    }
  }

  private async testSendMessage(): Promise<void> {
    if (!this.validateSession()) return;

    try {
      await abilityConnectionManager.sendMessage(this.currentSessionId, this.messageToSend);
      hilog.info(1, 'testSendMessage', `Message sent: ${this.messageToSend}`);
      this.showDialog('Success', `Message sent: ${this.messageToSend}`);
    } catch (error) {
      hilog.warn(1, 'testSendMessage', `error: ${JSON.stringify(error)}`);
      this.showDialog('Error', JSON.stringify(error));
    }
  }

  private async testSendData(): Promise<void> {
    if (!this.validateSession()) return;

    try {
      const encoder = new util.TextEncoder();
      const dataBuffer = encoder.encode(this.dataToSend);
      await abilityConnectionManager.sendData(this.currentSessionId, dataBuffer);
      hilog.info(1, 'testSendData', `Data sent: ${this.dataToSend}`);
      this.showDialog('Success', `Data sent: ${this.dataToSend}`);
    } catch (error) {
      hilog.warn(1, 'testSendData', `error: ${JSON.stringify(error)}`);
      this.showDialog('Error', JSON.stringify(error));
    }
  }

  private async testSendImage(): Promise<void> {
    if (!this.validateSession()) return;

    try {
      this.showDialog('Info', 'SendImage requires a valid PixelMap. This is a placeholder implementation.');
      hilog.info(1, 'testSendImage', 'SendImage called (placeholder)');
    } catch (error) {
      hilog.warn(1, 'testSendImage', `error: ${JSON.stringify(error)}`);
      this.showDialog('Error', JSON.stringify(error));
    }
  }

  private testOnConnect(): void {
    if (!this.validateSession()) return;
    if (this.listenersActive.get('connect')) {
      this.showDialog('Warning', 'Connect listener already active');
      return;
    }

    try {
      const callback = (callbackInfo: Object) => {
        this.connectionStatus = 'Connected';
        this.logEvent('connect', callbackInfo);
        hilog.info(1, 'onConnect', `Connected: ${JSON.stringify(callbackInfo)}`);
      };
      this.connectCallback = callback;
      abilityConnectionManager.on('connect', this.currentSessionId, callback);
      this.listenersActive.set('connect', true);
      hilog.info(1, 'testOnConnect', 'Connect listener registered');
      this.showDialog('Success', 'Connect listener registered');
    } catch (error) {
      hilog.warn(1, 'testOnConnect', `error: ${JSON.stringify(error)}`);
      this.showDialog('Error', JSON.stringify(error));
    }
  }

  private testOffConnect(): void {
    if (!this.validateSession()) return;
    if (!this.listenersActive.get('connect')) {
      this.showDialog('Warning', 'No active connect listener');
      return;
    }

    try {
      abilityConnectionManager.off('connect', this.currentSessionId);
      this.connectCallback = null;
      this.listenersActive.set('connect', false);
      hilog.info(1, 'testOffConnect', 'Connect listener removed');
      this.showDialog('Success', 'Connect listener removed');
    } catch (error) {
      hilog.warn(1, 'testOffConnect', `error: ${JSON.stringify(error)}`);
      this.showDialog('Error', JSON.stringify(error));
    }
  }

  private testOnDisconnect(): void {
    if (!this.validateSession()) return;
    if (this.listenersActive.get('disconnect')) {
      this.showDialog('Warning', 'Disconnect listener already active');
      return;
    }

    try {
      const callback = (callbackInfo: Object) => {
        this.connectionStatus = 'Disconnected';
        this.logEvent('disconnect', callbackInfo);
        hilog.info(1, 'onDisconnect', `Disconnected: ${JSON.stringify(callbackInfo)}`);
      };
      this.disconnectCallback = callback;
      abilityConnectionManager.on('disconnect', this.currentSessionId, callback);
      this.listenersActive.set('disconnect', true);
      hilog.info(1, 'testOnDisconnect', 'Disconnect listener registered');
      this.showDialog('Success', 'Disconnect listener registered');
    } catch (error) {
      hilog.warn(1, 'testOnDisconnect', `error: ${JSON.stringify(error)}`);
      this.showDialog('Error', JSON.stringify(error));
    }
  }

  private testOffDisconnect(): void {
    if (!this.validateSession()) return;
    if (!this.listenersActive.get('disconnect')) {
      this.showDialog('Warning', 'No active disconnect listener');
      return;
    }

    try {
      abilityConnectionManager.off('disconnect', this.currentSessionId);
      this.disconnectCallback = null;
      this.listenersActive.set('disconnect', false);
      hilog.info(1, 'testOffDisconnect', 'Disconnect listener removed');
      this.showDialog('Success', 'Disconnect listener removed');
    } catch (error) {
      hilog.warn(1, 'testOffDisconnect', `error: ${JSON.stringify(error)}`);
      this.showDialog('Error', JSON.stringify(error));
    }
  }

  private testOnReceiveMessage(): void {
    if (!this.validateSession()) return;
    if (this.listenersActive.get('receiveMessage')) {
      this.showDialog('Warning', 'ReceiveMessage listener already active');
      return;
    }

    try {
      const callback = (callbackInfo: Object) => {
        const message = (callbackInfo as ESObject).data as string;
        this.logEvent('receiveMessage', message);
        hilog.info(1, 'onReceiveMessage', `Message received: ${message}`);
      };
      this.receiveMessageCallback = callback;
      abilityConnectionManager.on('receiveMessage', this.currentSessionId, callback);
      this.listenersActive.set('receiveMessage', true);
      hilog.info(1, 'testOnReceiveMessage', 'ReceiveMessage listener registered');
      this.showDialog('Success', 'ReceiveMessage listener registered');
    } catch (error) {
      hilog.warn(1, 'testOnReceiveMessage', `error: ${JSON.stringify(error)}`);
      this.showDialog('Error', JSON.stringify(error));
    }
  }

  private testOffReceiveMessage(): void {
    if (!this.validateSession()) return;
    if (!this.listenersActive.get('receiveMessage')) {
      this.showDialog('Warning', 'No active receiveMessage listener');
      return;
    }

    try {
      abilityConnectionManager.off('receiveMessage', this.currentSessionId);
      this.receiveMessageCallback = null;
      this.listenersActive.set('receiveMessage', false);
      hilog.info(1, 'testOffReceiveMessage', 'ReceiveMessage listener removed');
      this.showDialog('Success', 'ReceiveMessage listener removed');
    } catch (error) {
      hilog.warn(1, 'testOffReceiveMessage', `error: ${JSON.stringify(error)}`);
      this.showDialog('Error', JSON.stringify(error));
    }
  }

  private testOnReceiveData(): void {
    if (!this.validateSession()) return;
    if (this.listenersActive.get('receiveData')) {
      this.showDialog('Warning', 'ReceiveData listener already active');
      return;
    }

    try {
      const callback = (callbackInfo: Object) => {
        const decoder = new util.TextDecoder('utf-8');
        const data = (callbackInfo as ESObject).data as ArrayBuffer;
        const dataUint8Array = new Uint8Array(data);
        const dataStr = decoder.decodeWithStream(dataUint8Array);
        this.logEvent('receiveData', dataStr);
        hilog.info(1, 'onReceiveData', `Data received: ${dataStr}`);
      };
      this.receiveDataCallback = callback;
      abilityConnectionManager.on('receiveData', this.currentSessionId, callback);
      this.listenersActive.set('receiveData', true);
      hilog.info(1, 'testOnReceiveData', 'ReceiveData listener registered');
      this.showDialog('Success', 'ReceiveData listener registered');
    } catch (error) {
      hilog.warn(1, 'testOnReceiveData', `error: ${JSON.stringify(error)}`);
      this.showDialog('Error', JSON.stringify(error));
    }
  }

  private testOffReceiveData(): void {
    if (!this.validateSession()) return;
    if (!this.listenersActive.get('receiveData')) {
      this.showDialog('Warning', 'No active receiveData listener');
      return;
    }

    try {
      abilityConnectionManager.off('receiveData', this.currentSessionId);
      this.receiveDataCallback = null;
      this.listenersActive.set('receiveData', false);
      hilog.info(1, 'testOffReceiveData', 'ReceiveData listener removed');
      this.showDialog('Success', 'ReceiveData listener removed');
    } catch (error) {
      hilog.warn(1, 'testOffReceiveData', `error: ${JSON.stringify(error)}`);
      this.showDialog('Error', JSON.stringify(error));
    }
  }

  private testOnPrepareContinue(): void {
    if (this.listenersActive.get('prepareContinue')) {
      this.showDialog('Warning', 'PrepareContinue listener already active');
      return;
    }

    try {
      const context = getContext(this) as common.UIAbilityContext;
      const callback = (callbackInfo: Object) => {
        this.logEvent('prepareContinue', callbackInfo);
        hilog.info(1, 'onPrepareContinue', `Prepare continue: ${JSON.stringify(callbackInfo)}`);
      };
      this.prepareContinueCallback = callback;
      continueManager.on('prepareContinue', context, callback);
      this.listenersActive.set('prepareContinue', true);
      hilog.info(1, 'testOnPrepareContinue', 'PrepareContinue listener registered');
      this.showDialog('Success', 'PrepareContinue listener registered');
    } catch (error) {
      hilog.warn(1, 'testOnPrepareContinue', `error: ${JSON.stringify(error)}`);
      this.showDialog('Error', JSON.stringify(error));
    }
  }

  private testOffPrepareContinue(): void {
    if (!this.listenersActive.get('prepareContinue')) {
      this.showDialog('Warning', 'No active prepareContinue listener');
      return;
    }

    try {
      const context = getContext(this) as common.UIAbilityContext;
      continueManager.off('prepareContinue', context);
      this.prepareContinueCallback = null;
      this.listenersActive.set('prepareContinue', false);
      hilog.info(1, 'testOffPrepareContinue', 'PrepareContinue listener removed');
      this.showDialog('Success', 'PrepareContinue listener removed');
    } catch (error) {
      hilog.warn(1, 'testOffPrepareContinue', `error: ${JSON.stringify(error)}`);
      this.showDialog('Error', JSON.stringify(error));
    }
  }
}
