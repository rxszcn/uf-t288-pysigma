# 处理管道合并导致操作数字段映射台账丢失——根因定位与修复交付文档

## 1. 背景与问题现象

威胁检测规则治理平台按 pySigma 官方推荐的多管道组合方式，将**字段规范化管道**与**平台管道**
合并为一条管道完成规则集转换；随后治理工具又**单独复用**参与合并的字段管道处理另一批规则并
生成字段映射台账。观测到：

- 被复用的字段管道，其字段映射台账（`ProcessingPipeline.field_mappings`）**恒为空**；
- 但同一批规则的检测字段转换结果**完全正确**；
- 未参与合并的等价管道（对照组）台账完整；
- 字段覆盖率报告与实际处理脱节，治理结论失真；
- 滚动升级并存期，新旧两版治理工具并行处理规则集并各自产出覆盖率报告；合规审计会定期回读
  历史批次的台账与覆盖率报告核对治理结论，因此空台账会污染审计链。

## 2. 根因链条与定位依据

### 2.1 字段台账是通过"转换 → 所属管道"的反向引用写入的

- 字段映射转换 `FieldMappingTransformationBase.apply_detection_item` 在实际改名时，通过
  `self._pipeline.field_mappings.add_mapping(...)` 写入台账
  （`sigma/processing/transformations/base.py:335`），并通过
  `self._pipeline.track_field_processing_items(...)` 维护字段级处理项记录
  （`base.py:182`）。
- 每个 `ProcessingItem` / `Transformation` / `ProcessingCondition` 都持有一个 `_pipeline`
  反向引用，指向"自己当前所属的管道"。该引用由 `ProcessingPipeline.set_pipeline()` 在管道
  构造时建立，并且 `set_pipeline()` 带有"只能设置一次"的保护，重复绑定会抛
  `SigmaProcessingItemError` / `SigmaTransformationError`。
- 因此，台账写到哪条管道，完全由转换对象上的 `_pipeline` 引用决定。

### 2.2 旧版合并实现会"解绑操作数 + 共享同一批 item 对象"

修复前 `ProcessingPipeline.__add__`（官方 `ProcessingPipelineResolver.resolve()` 内部也是用
`sum(...)` 即 `__add__` 完成合并）的关键两步是：

```python
self._clear_pipeline()
other._clear_pipeline()
return self.__class__(items=self.items + other.items, ...)
```

- `_clear_pipeline()` 把两条操作数管道里**原有 item（及其 transformation、condition）的
  `_pipeline` 全部置空**；
- 然后新合并管道的 `__post_init__ → set_pipeline()` 把**同一批 item 对象**重新绑定到合并管道。

也就是说，合并不是"复制 item"，而是**把操作数管道的 item 对象搬走、改绑到合并管道**。

### 2.3 复用操作数管道时台账被重定向到合并管道（症状根因）

合并之后，字段管道对象本身仍然存在、可以再次 `apply`，但其 item 的 `_pipeline` 已经指向
**合并管道**。于是再次单独 `apply` 字段管道时：

- 转换逻辑照常执行，检测字段依然被正确改名（转换只依赖 transformation 自身配置，不依赖
  `_pipeline` 是谁）——这解释了"转换结果完全正确"；
- 但 `add_mapping` / `track_field_processing_items` 经由 `_pipeline` 把台账写进了
  **合并管道**的 `field_mappings`，字段管道自己的台账在每次 `apply` 开头被重置为空后再无写入
  ——这解释了"台账恒为空"。
- 未参与合并的等价管道从未被 `_clear_pipeline()`，item 始终绑定自身，故台账完整——这解释了
  对照组正常。

### 2.4 实测定位证据（修复前）

在内存构造的两条操作数管道与样例规则集上（构造方式见第 5 节），修复前实测：

| 读数 | 修复前实测值 |
| --- | --- |
| 复用后字段管道台账条目数 | **0** |
| 复用后字段管道台账键值 | `{}`（空） |
| 复用后转换字段 | `['mappedA', 'fieldB']`（正确） |
| 操作数 item 的 `_pipeline is 合并管道` | **True** |
| 操作数 item 的 `_pipeline is 自身` | **False** |
| 对照组（未合并等价管道）台账条目数 | 1 |
| 对照组台账键值 | `{'fieldA': {'mappedA'}}` |

"转换正确但台账为空、且 item 已被改绑到合并管道"与上述静态链路完全吻合，根因成立。

## 3. 修复方案与理由

### 3.1 核心思路：合并改为"深拷贝 item"，不再搬走操作数的 item

`ProcessingPipeline.__add__` 不再对操作数调用 `_clear_pipeline()`，改为：

1. 对两条操作数管道的 `items` / `postprocessing_items` / `finalizers` 逐项 **深拷贝**；
2. 对副本执行解绑（`_clear_pipeline()`，finalizer 无该方法则直接置 `_pipeline=None`）；
3. 用副本构造合并管道，合并管道 `__post_init__ → set_pipeline()` 再把副本绑定到合并管道；
4. 两条操作数管道及其原有 item、`_pipeline` 绑定**完全不被触碰**，合并后仍可独立使用。

这样：

- 操作数再次单独 `apply` 时，item 仍绑定自身，台账写入自身——复用台账完整；
- 合并管道持有独立副本，转换顺序、优先级语义、台账语义与旧实现完全一致；
- 单条管道从不合并时，根本不经过新代码路径，行为不变。

### 3.2 深拷贝遇到的两类"不可拷贝/不应拷贝"对象及处理

深拷贝不是无脑 `deepcopy`，实测暴露两类需要特殊处理的协作者：

1. **`SigmaPolicy` 与 `RegexEngine`（无状态配置/单例式对象）**
   - `RE2RegexEngine` 内部 `self._re2 = re2` 持有 `re2` 模块对象，模块不可深拷贝
     （`TypeError: cannot pickle 'module' object`）。
   - policy 是无状态配置，合并语义本就要求两条管道运行在同一个 `merged_policy` 上；正则引擎
     也是无状态单例式对象，且还会经 transformation/condition 的惰性正则缓存 `_re_engine`
     被间接引用。
   - 处理：通过 `deepcopy` 的 **memo 共享**而非复制。`__add__` 把两条操作数的显式 policy、
     以及各自"有效 policy 的正则引擎"（无显式 policy 时即全局默认引擎）种入 memo；
     `_seed_shared_engines()` 再兜底把 item 图（含 `NestedProcessingTransformation` /
     `NestedQueryPostprocessingTransformation` 的嵌套管道、三类条件）中已缓存的引擎种入 memo。
     只检查已知的 `_re_engine` 缓存属性，不泛化遍历任意对象。

2. **Jinja2 模板（`TemplateBase.j2template`）**
   - `TemplateBase.__post_init__` 构造的 `j2template` 是派生运行时对象，Jinja2 的
     `Template.__new__` 不接受拷贝协议（`Template.__new__() missing 1 required positional
     argument: 'source'`），不可深拷贝。
   - 但它可由 dataclass 配置字段（`template`/`path`/`autoescape`/`vars`/`policy`/
     `restrict_template_path`）完整重建。
   - 处理：在 `sigma/processing/templates.py` 的 `TemplateBase` 上实现 `__deepcopy__`，仅深拷贝
     初始化字段后重新构造对象，由 `__post_init__` 重新编译模板；policy 仍经 memo 共享。

### 3.3 为什么选择深拷贝而不是其他方案

- "复用前重新 `set_pipeline` 回自身"不可行：`set_pipeline()` 有一次性保护，重复绑定直接抛错，
  且无法区分 item 当前属于哪条管道。
- "台账层面做分流/双写"会把所有权问题下沉到 tracking，改动面扩散且无法修复 `state`、
  `applied_ids` 等同样经由 `_pipeline` 写入的运行时状态，治标不治本。
- 深拷贝在合并边界一次性切断对象共享，语义最清晰：每条管道独占自己的 item 与运行时状态，
  符合"管道是可重复独立使用的对象"这一既有契约（对照组行为即该契约的体现）。

## 4. 改动面登记

改动严格收在处理管道实现及其测试，共 3 个文件：

| 文件 | 改动内容 |
| --- | --- |
| `sigma/processing/pipeline.py` | 新增 `import copy.deepcopy`；新增 `ProcessingPipeline._seed_shared_engines()`（引擎 memo 播种，覆盖嵌套管道与三类条件）；新增 `ProcessingPipeline._detached_copy()`（逐项深拷贝 + 副本解绑）；重写 `ProcessingPipeline.__add__()`，删除对操作数的 `_clear_pipeline()`，改为深拷贝构造合并管道，并用 memo 共享 policy 与有效正则引擎、深拷贝 `vars`。 |
| `sigma/processing/templates.py` | 新增 `from copy import deepcopy`；为 `TemplateBase` 增加 `__deepcopy__()`，由配置字段重建不可深拷贝的 Jinja2 模板。 |
| `tests/test_processing_pipeline.py` | 在既有合并测试所在文件末尾追加 3 个回归用例（见第 6 节），框架与断言形态沿用文件既有风格（pytest + 内存构造，无外部依赖）。 |

未改动：resolver、tracking、transformations、conditions、backends 等其他模块；既有测试逻辑零修改。

## 5. 构造输入与读数口径（写死）

### 5.1 构造输入（全程内存构造，零外部依赖，可在快照环境直接复现）

两条操作数管道：

- **字段规范化管道** `field-normalization`：1 个 `ProcessingItem`，
  `FieldMappingTransformation({"fieldA": "mappedA"})`，identifier 为
  `field_normalization_mapping`。
- **平台管道** `platform`：1 个 `ProcessingItem`，
  `AddFieldnamePrefixTransformation("winlog.")`，identifier 为 `platform_prefix`。

样例规则集（`SigmaRule.from_yaml`，内存 YAML 字符串）：

```yaml
title: Test
status: test
logsource:
  category: test
detection:
  sel:
    fieldA: valueA
    fieldB: valueB
  condition: sel
```

合并方式：`merged = field_pipeline + platform_pipeline`（resolver 的 `resolve()` 内部等价于按
优先级排序后用 `__add__` 求和）。复用方式：合并后再次 `field_pipeline.apply(规则)`。

### 5.2 读数口径（三项，题面指定）

1. **操作数复用后台账条目数**：`len(field_pipeline.field_mappings)`。
2. **台账键值**：`dict(field_pipeline.field_mappings)`（源字段 → 目标字段集合）。
3. **合并管道自身台账条目数**：`len(merged.field_mappings)`。

辅助佐证读数：转换后检测字段名列表、操作数 item 的 `_pipeline` 归属。

## 6. 题面要求到改动的逐条对照

| 题面要求 | 落实位置与方式 |
| --- | --- |
| 参与合并的操作数管道再次单独使用时，台账必须完整记录在自身 | `__add__` 不再解绑操作数，操作数 item 始终绑定自身；回归用例 `test_processingpipeline_merge_keeps_operand_ledger_on_reuse` 断言复用后台账条目数=1、键值=`{'fieldA': {'mappedA'}}`、item 绑定自身。 |
| 复用操作数时转换行为与合并前一致 | 同上用例断言复用转换字段=`['mappedA', 'fieldB']`，与对照组/合并前一致。 |
| 合并管道自身的台账与转换与优先级语义不变 | 用例 `test_processingpipeline_merge_behavior_and_ledger_unchanged` 断言合并后 item 顺序（字段管道在前、平台管道在后）、转换字段=`['winlog.mappedA','winlog.fieldB']`、合并台账 3 条键值均与旧实现一致；resolver 路径端到端验证优先级排序不变。 |
| 单条管道不经合并的正常使用行为不变 | 用例 `test_processingpipeline_single_without_merge_behavior_unchanged` 以未合并的等价独立管道为对照，断言转换字段与台账完全一致；新代码只在 `__add__` 路径生效，单管道 `apply` 路径未改。 |
| 三类断言用例补入既有合并测试所在文件，框架与断言形态照旧 | 三个用例均加入 `tests/test_processing_pipeline.py`（`test_processingpipeline_concatenation` 等同文件），使用同款 pytest 函数式用例与 `assert`。 |
| 改动面收在处理管道实现及其测试 | 仅 `pipeline.py`、`templates.py`（处理管道实现）与 `test_processing_pipeline.py`（测试），见第 4 节。 |
| 既有测试保持通过 | 三验收文件 136 passed；全量 `tests/` 1948 passed（较基线 +3 新用例），无新增失败。 |
| 构造全程快照环境内零外部依赖可复现 | 全部对象内存构造，仅依赖已安装的 pySigma 及其声明依赖；复现脚本置于 `scratch/`，不读外部数据、不联网。 |
| 根因链条与修复方式、定位依据与理由写入交付文档 | 见第 2、3 节。 |
| 记录验收命令最终读数与构造输入下实测读数两组证据 | 见第 7 节。 |

## 7. 两组证据

### 7.1 验收命令最终读数

命令（题面指定）：

```
python -m pytest tests/test_processing_pipeline.py tests/test_processing_resolver.py tests/test_processing_tracking.py -q
```

最终读数：

```
136 passed in 0.67s
```

（133 个既有用例 + 3 个新增回归用例，零失败。）

全量回归（确定性顺序）`python -m pytest tests/ -q -p no:randomly`：

```
1948 passed, 2 skipped, 1 error
```

其中唯一 `ERROR tests/files/template_vars.py::parse_json` 为**基线既有**的测试夹具文件收集
问题（该文件是被引用的 vars 夹具而非测试用例），在未改动的基线上同样出现；修复前后全量
通过数从 1945 增至 1948（恰为新增 3 用例），无回归。

### 7.2 构造输入下的实测读数（口径见 5.2）

修复后实测：

| 读数 | 修复后实测值 |
| --- | --- |
| 操作数复用后台账条目数 | **1** |
| 操作数复用后台账键值 | `{'fieldA': {'mappedA'}}` |
| 复用转换字段 | `['mappedA', 'fieldB']` |
| 合并管道自身台账条目数 | **3** |
| 合并管道台账键值 | `{'fieldA': {'winlog.mappedA'}, 'mappedA': {'winlog.mappedA'}, 'fieldB': {'winlog.fieldB'}}` |
| 合并转换字段 | `['winlog.mappedA', 'winlog.fieldB']` |
| 对照组台账条目数 / 键值 | 1 / `{'fieldA': {'mappedA'}}` |
| 操作数 item `_pipeline is 自身` / `is 合并管道` | True / **False** |

与修复前对照（同构造、同口径）：

| 读数 | 修复前 | 修复后 |
| --- | --- | --- |
| 操作数复用后台账条目数 | 0 | **1** |
| 操作数复用后台账键值 | `{}` | `{'fieldA': {'mappedA'}}` |
| 复用转换字段 | `['mappedA','fieldB']`（已正确） | `['mappedA','fieldB']`（不变） |
| 合并管道台账条目数 | 3 | 3（不变） |
| 操作数 item 绑定 | 被改绑到合并管道 | 保持绑定自身 |

补充端到端验证（`scratch/e2e.py`）：经 `ProcessingPipelineResolver` 按优先级（10/20）逆序
传入仍正确排序合并；模拟新旧两版工具各自 resolver 并行合并互不污染；同一操作数可被反复合并，
每次合并管道台账均为 3 条、复用台账始终为 1 条。

## 8. 复现方式

仓库内 `scratch/` 目录提供三个内存脚本（验证后可整体删除，不属于交付改动面）：

- `scratch/repro.py`：第 5 节构造输入与 5.2 读数口径的最小复现；
- `scratch/e2e.py`：resolver 优先级合并、并存期并行、反复合并的端到端断言；
- `scratch/complex.py`：正则缓存转换、嵌套处理/后处理管道、Jinja 模板、finalizer、字段条件等
  棘手结构的合并深拷贝断言。

运行：

```
python scratch/repro.py
python scratch/e2e.py
python scratch/complex.py
```
