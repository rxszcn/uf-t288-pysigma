# -*- coding: utf-8 -*-
"""端到端验证：resolver 优先级合并 + 操作数复用 + 滚动升级两版工具并存场景。"""
import sys

sys.path.insert(0, r"D:\Projects\biaozhu\zhongqiang\user-feedback\work\t288-pysigma")

from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem
from sigma.processing.resolver import ProcessingPipelineResolver
from sigma.processing.transformations import (
    FieldMappingTransformation,
    AddFieldnamePrefixTransformation,
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
        fieldB: valueB
    condition: sel
"""


def fields(rule):
    return [di.field for di in rule.detection.detections["sel"].detection_items]


# 官方推荐：带优先级的两条管道经 resolver 合并
field_pipeline = ProcessingPipeline(
    name="field-normalization",
    priority=10,
    items=[
        ProcessingItem(
            identifier="field_normalization_mapping",
            transformation=FieldMappingTransformation({"fieldA": "mappedA"}),
        )
    ],
)
platform_pipeline = ProcessingPipeline(
    name="platform",
    priority=20,
    items=[
        ProcessingItem(
            identifier="platform_prefix",
            transformation=AddFieldnamePrefixTransformation("winlog."),
        )
    ],
)
resolver = ProcessingPipelineResolver.from_pipeline_list([field_pipeline, platform_pipeline])
merged = resolver.resolve(["platform", "field-normalization"])  # 故意逆序，验证优先级排序

print("resolved order        :", [i.identifier for i in merged.items])
print("merged fields         :", fields(merged.apply(SigmaRule.from_yaml(RULE_YAML))))
print("merged ledger count   :", len(merged.field_mappings))

# 新旧两版工具并存：各自独立 resolver/合并，互不污染对方操作数
resolver_v2 = ProcessingPipelineResolver.from_pipeline_list([field_pipeline, platform_pipeline])
merged_v2 = resolver_v2.resolve(["field-normalization", "platform"])

# 操作数复用：治理工具单独再用字段管道处理另一批规则
reused = field_pipeline.apply(SigmaRule.from_yaml(RULE_YAML))
print("reused fields         :", fields(reused))
print("reused ledger count   :", len(field_pipeline.field_mappings))
print("reused ledger keys    :", dict(field_pipeline.field_mappings))

# 第二次合并仍然正确（操作数未被第一次合并破坏，可反复合并）
merged_again = resolver.resolve(["field-normalization", "platform"])
print("re-merge fields       :", fields(merged_again.apply(SigmaRule.from_yaml(RULE_YAML))))
print("re-merge ledger count :", len(merged_again.field_mappings))

# 断言
assert [i.identifier for i in merged.items] == [
    "field_normalization_mapping",
    "platform_prefix",
]
assert fields(merged.apply(SigmaRule.from_yaml(RULE_YAML))) == [
    "winlog.mappedA",
    "winlog.fieldB",
]
assert len(field_pipeline.field_mappings) == 1
assert dict(field_pipeline.field_mappings) == {"fieldA": {"mappedA"}}
assert len(merged_again.field_mappings) == 3
assert field_pipeline.items[0]._pipeline is field_pipeline
print("ALL E2E ASSERTIONS PASSED")
