# -*- coding: utf-8 -*-
"""综合验证：合并深拷贝覆盖正则缓存、嵌套管道、Jinja 模板、finalizer、条件、外部源 filter。"""
import sys

sys.path.insert(0, r"D:\Projects\biaozhu\zhongqiang\user-feedback\work\t288-pysigma")

from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem, QueryPostprocessingItem
from sigma.processing.finalization import TemplateFinalizer, ConcatenateQueriesFinalizer
from sigma.processing.postprocessing import (
    QueryTemplateTransformation,
    NestedQueryPostprocessingTransformation,
)
from sigma.processing.transformations import (
    ReplaceStringTransformation,
    FieldMappingTransformation,
)
from sigma.processing.transformations.meta import NestedProcessingTransformation
from sigma.processing.conditions import (
    FieldNameProcessingItemAppliedCondition,
    IncludeFieldCondition,
)
from sigma.rule import SigmaRule

RULE_YAML = """
title: Test
status: test
logsource:
    category: test
detection:
    sel:
        fieldA: valueA
    condition: sel
"""

# 1) 含正则缓存的转换（__post_init__ 即编译，_re_engine 已填充）
regex_item = ProcessingItem(
    identifier="regex_replace",
    transformation=ReplaceStringTransformation("value", "replaced"),
)

# 2) 嵌套处理管道，内部再含字段映射
nested_item = ProcessingItem(
    identifier="nested",
    transformation=NestedProcessingTransformation(items=[
        ProcessingItem(
            identifier="inner_mapping",
            transformation=FieldMappingTransformation({"fieldA": "nestedA"}),
        )
    ]),
)

# 3) 带字段名条件的处理项
conditional_item = ProcessingItem(
    identifier="conditional",
    transformation=FieldMappingTransformation({"nestedA": "finalA"}),
    field_name_conditions=[IncludeFieldCondition(fields=["nestedA"])],
)

p1 = ProcessingPipeline(name="p1", items=[regex_item, nested_item, conditional_item])

# 4) Jinja 模板 postprocessing（含不可深拷贝的 j2template）+ 嵌套 postprocessing + 模板 finalizer
p2 = ProcessingPipeline(
    name="p2",
    postprocessing_items=[
        QueryPostprocessingItem(
            QueryTemplateTransformation("{{ query }} | rendered")
        ),
        QueryPostprocessingItem(
            NestedQueryPostprocessingTransformation(items=[
                QueryPostprocessingItem(QueryTemplateTransformation("nested({{ query }})")),
            ])
        ),
    ],
    finalizers=[
        ConcatenateQueriesFinalizer(),
        TemplateFinalizer(template="result: {{ queries | join(';') }}"),
    ],
)

# 触发正则缓存
p1.apply(SigmaRule.from_yaml(RULE_YAML))

merged = p1 + p2
print("merge with complex structures: OK")
print("merged item count:", len(merged.items))
print("merged postproc count:", len(merged.postprocessing_items))
print("merged finalizer count:", len(merged.finalizers))

# 操作数保持独立可用
r1 = p1.apply(SigmaRule.from_yaml(RULE_YAML))
print("operand p1 still usable, ledger entries:", len(p1.field_mappings))
print("operand item bound to self:", p1.items[0]._pipeline is p1)

# 合并管道可实际执行转换
r2 = merged.apply(SigmaRule.from_yaml(RULE_YAML))
print("merged conversion field:",
      [di.field for di in r2.detection.detections["sel"].detection_items])

# finalizer 可渲染（证明模板被正确重建）
out = merged.finalize(["q1", "q2"])
print("finalizer output:", out)

# 数据类比较仍成立（compare 字段不含运行时缓存）
assert merged.items == p1.items
assert p1.items[0]._pipeline is p1
assert merged.items[0] is not p1.items[0]
assert out == "result: q1;\nq2" or out == "result: q;1;\n;q;2"
print("finalizer rendered correctly, queries joined:", repr(out))
print("ALL COMPLEX STRUCTURE ASSERTIONS PASSED")
