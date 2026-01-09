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
import { commonType } from '@kit.ArkData';
import CommonConstants from '../commom/Constants';
import logger from '../commom/Logger';

// 业务数据定义
class ParentObject {
  mother: string
  father: string

  constructor(mother: string, father: string) {
    this.mother = mother
    this.father = father
  }
}

// 支持字符、数字、布尔值、对象的传递
class SourceObject {
  name: string | undefined
  age: number | undefined
  isVis: boolean | undefined
  parent: ParentObject | undefined

  constructor(name: string | undefined, age: number | undefined, isVis: boolean | undefined,
    parent: ParentObject | undefined) {
    this.name = name
    this.age = age
    this.isVis = isVis
    this.parent = parent
  }
}

class SourceObject2 {
  name: string | undefined
  age: number | undefined
  isVis: boolean | undefined
  parent: ParentObject | undefined
  attachment: commonType.Asset | undefined // 新增资产属性

  constructor(name: string | undefined, age: number | undefined, isVis: boolean | undefined,
    parent: ParentObject | undefined, attachment: commonType.Asset | undefined) {
    this.name = name
    this.age = age
    this.isVis = isVis
    this.parent = parent
    this.attachment = attachment;
  }
}

let parentSource: ParentObject = new ParentObject('xxx mom', 'xxx Dad');

@Entry
@Component
struct DataObj {
  @StorageLink('sourceObj') sourceObj: SourceObject | undefined = new SourceObject('xxx', 0, false, parentSource);
  @StorageLink('sourceObjAsset') sourceObjAsset: SourceObject2 | undefined = undefined;

  onPageShow(): void {
    logger.info('this.sourceObj: ' + JSON.stringify(this.sourceObj));
    logger.info('this.sourceObjAsset: ' + JSON.stringify(this.sourceObjAsset));
  }

  build() {
    Column() {
      Text($r('app.string.verify_migrate_data_using_dataObject'))
        .fontSize($r('app.float.page_text_font_size'))
        .fontWeight(FontWeight.Bold)
        .margin({ top: CommonConstants.TEXT_MARGIN_TOP, bottom: CommonConstants.TEXT_MARGIN_BOTTOM })

      Text(JSON.stringify(this.sourceObj))
        .fontSize($r('app.float.page_text_font_size'))
        .fontWeight(FontWeight.Bold)

      Text($r('app.string.verify_migrate_data_using_dataObject_asset'))
        .fontSize($r('app.float.page_text_font_size'))
        .fontWeight(FontWeight.Bold)
        .margin({ top: CommonConstants.TEXT_MARGIN_TOP, bottom: CommonConstants.TEXT_MARGIN_BOTTOM })

      Text(JSON.stringify(this.sourceObjAsset))
        .fontSize($r('app.float.page_text_font_size'))
        .fontWeight(FontWeight.Bold)

    }
    .height('100%')
    .width('100%')
  }
}