# -*- coding: utf-8 -*-
"""临时复现脚本：验证合并后操作数管道字段台账被劫持（验证后删除）。"""
import sys

sys.path.insert(0, r"D:\Projects\biaozhu\zhongqiang\user-feedback\work\t288-pysigma")

from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem
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


def make_field_pipeline():
    # 字段规范化管道：fieldA -> mappedA
    return ProcessingPipeline(
        name="field-normalization",
        items=[
            ProcessingItem(
                identifier="field_mapping",
                transformation=FieldMappingTransformation({"fieldA": "mappedA"}),
            )
        ],
    )


def make_platform_pipeline():
    # 平台管道：给字段统一加前缀 winlog.
    return ProcessingPipeline(
        name="platform",
        items=[
            ProcessingItem(
                identifier="platform_prefix",
                transformation=AddFieldnamePrefixTransformation("winlog."),
            )
        ],
    )


def rule_fields(rule):
    return [di.field for di in rule.detection.detections["sel"].detection_items]


field_pipeline = make_field_pipeline()
platform_pipeline = make_platform_pipeline()

# 1) 官方推荐方式：按优先级合并（resolver 内部也是 __add__ 求和）
merged = field_pipeline + platform_pipeline
merged_rule = merged.apply(SigmaRule.from_yaml(RULE_YAML))
print("merged conversion fields      :", rule_fields(merged_rule))
print("merged ledger entry count     :", len(merged.field_mappings))
print("merged ledger keys            :", dict(merged.field_mappings))

# 2) 治理工具再次单独复用参与合并的字段管道处理另一批规则
reused_rule = field_pipeline.apply(SigmaRule.from_yaml(RULE_YAML))
print("reused conversion fields      :", rule_fields(reused_rule))
print("reused ledger entry count     :", len(field_pipeline.field_mappings))
print("reused ledger keys            :", dict(field_pipeline.field_mappings))

# 3) 未参与合并的等价管道对照组
control = make_field_pipeline()
control_rule = control.apply(SigmaRule.from_yaml(RULE_YAML))
print("control conversion fields     :", rule_fields(control_rule))
print("control ledger entry count    :", len(control.field_mappings))
print("control ledger keys           :", dict(control.field_mappings))

# 4) 绑定状态取证
print("operand item _pipeline is merged?:",
      field_pipeline.items[0]._pipeline is merged)
print("operand item _pipeline is self?  :",
      field_pipeline.items[0]._pipeline is field_pipeline)
