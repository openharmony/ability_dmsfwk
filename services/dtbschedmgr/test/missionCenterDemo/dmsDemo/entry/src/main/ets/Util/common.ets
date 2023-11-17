import Device from './Device';
export default class CommonTools {
  private static instance: CommonTools;

  private constructor() {
  }

  public static getInstance() {
    if (!CommonTools.instance) {
      CommonTools.instance = new CommonTools();
    }
    return CommonTools.instance;
  }

  getNetworkId(device: Device): string {
    if (device.deviceInfo.networkId) {
      return device.deviceInfo.networkId;
    }
    return '';
  }
}