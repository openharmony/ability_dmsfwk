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
import CommonConstants from '../commom/Constants';
import logger from '../commom/Logger';

class SourceObject {
  name: string | undefined
  assets: Object | undefined // 分布式数据对象的中添加一个Object属性

  constructor(name: string | undefined, assets: Object | undefined) {
    this.name = name
    this.assets = assets;
  }
}

@Entry
@Component
struct MultiAsset {
  @StorageLink('sourceObjMultiAsset') sourceObjMultiAsset: SourceObject | undefined = undefined;

  onPageShow(): void {
    logger.info('this.sourceObjMultiAsset: ' + JSON.stringify(this.sourceObjMultiAsset));
  }

  build() {
    Column() {
      Text('验证分布式对象多个资产数据迁移:')
        .id('DataObjHelloWorld')
        .fontSize($r('app.float.page_text_font_size'))
        .fontWeight(FontWeight.Bold)
        .margin({ top: CommonConstants.TEXT_MARGIN_TOP, bottom: CommonConstants.TEXT_MARGIN_BOTTOM })

      Text(JSON.stringify(this.sourceObjMultiAsset))
        .id('DataObjHelloWorld')
        .fontSize($r('app.float.page_text_font_size'))
        .fontWeight(FontWeight.Bold)
    }
    .height('100%')
    .width('100%')
  }
}