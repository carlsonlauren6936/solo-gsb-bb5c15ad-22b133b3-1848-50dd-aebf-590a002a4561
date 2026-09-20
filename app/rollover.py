"""ZSK 双签（double-signature）轮换时序校验（不落库）。

双签 ZSK 轮换的四个关键时刻（UTC）：

1. **新钥发布**（publish）：新 ZSK 加入 DNSKEY RRset 并随区发布；
2. **新钥启签**（activate）：开始使用新 ZSK 对区数据签名（新旧签名并存）；
3. **旧钥停签**（deactivate）：停止使用旧 ZSK 签名；
4. **旧钥移除**（remove）：旧 ZSK 从 DNSKEY RRset 中移除。

四个时刻必须严格递增（由请求模型校验，失败为 HTTP 422）。两处等待要求：

- **发布 → 启签**：至少等待 ``DNSKEY TTL + 时钟偏差`` 秒，保证含新钥的
  DNSKEY RRset 已传播到所有缓存（含时钟偏差余量）后再启用新钥签名；
- **停签 → 移除**：至少等待 ``区记录最大 TTL + 时钟偏差`` 秒，保证缓存中
  由旧钥签名的区记录全部过期后再移除旧钥。

等待不足不视为请求错误（仍返回 HTTP 200），而是以 violations 按阶段顺序
列出；整个校验仅在内存中计算，不写入数据库。
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

#: 阶段标识：新钥发布 → 启签
PHASE_PUBLISH_TO_ACTIVATE = "publish_to_activate"
#: 阶段标识：旧钥停签 → 移除
PHASE_DEACTIVATE_TO_REMOVE = "deactivate_to_remove"


def _format_utc(value: datetime) -> str:
    """格式化为以 Z 结尾的 UTC ISO 8601 字符串。"""
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def check_zsk_rollover(
    zone: str,
    new_key_published_at: datetime,
    new_key_activated_at: datetime,
    old_key_deactivated_at: datetime,
    old_key_removed_at: datetime,
    dnskey_ttl: int,
    max_zone_ttl: int,
    clock_skew_seconds: int,
) -> dict:
    """校验一次 ZSK 双签轮换的两处等待时长，返回结果字典；不写库。

    :param zone: 已规范化的区域名；
    :param new_key_published_at: 新钥发布时刻（UTC，严格递增性由请求模型保证）；
    :param new_key_activated_at: 新钥启签时刻；
    :param old_key_deactivated_at: 旧钥停签时刻；
    :param old_key_removed_at: 旧钥移除时刻；
    :param dnskey_ttl: DNSKEY RRset 的 TTL（秒）；
    :param max_zone_ttl: 区内记录的最大 TTL（秒）；
    :param clock_skew_seconds: 允许的时钟偏差（秒）；
    :return: 含 safe、两阶段明细与 violations 的结果字典。
    """
    # (阶段标识, 阶段名, 起点, 终点, 要求的最短等待秒数)
    phase_specs = [
        (
            PHASE_PUBLISH_TO_ACTIVATE,
            "新钥发布 → 启签",
            new_key_published_at,
            new_key_activated_at,
            dnskey_ttl + clock_skew_seconds,
        ),
        (
            PHASE_DEACTIVATE_TO_REMOVE,
            "旧钥停签 → 移除",
            old_key_deactivated_at,
            old_key_removed_at,
            max_zone_ttl + clock_skew_seconds,
        ),
    ]

    phases: list[dict] = []
    violations: list[dict] = []
    for phase, label, start, end, required_seconds in phase_specs:
        # required_seconds 为整数秒，向下取整的实际秒数与之比较结果一致
        actual_seconds = int((end - start).total_seconds())
        earliest_safe = start + timedelta(seconds=required_seconds)
        ok = actual_seconds >= required_seconds
        phases.append(
            {
                "phase": phase,
                "from_at": _format_utc(start),
                "to_at": _format_utc(end),
                "actual_seconds": actual_seconds,
                "required_seconds": required_seconds,
                "earliest_safe_at": _format_utc(earliest_safe),
                "ok": ok,
            }
        )
        if not ok:
            violations.append(
                {
                    "phase": phase,
                    "actual_seconds": actual_seconds,
                    "required_seconds": required_seconds,
                    "shortfall_seconds": required_seconds - actual_seconds,
                    "earliest_safe_at": _format_utc(earliest_safe),
                    "message": (
                        f"阶段{label}实际等待 {actual_seconds} 秒，"
                        f"不足要求的 {required_seconds} 秒"
                        f"（还差 {required_seconds - actual_seconds} 秒），"
                        f"终点事件最早安全时间为 {_format_utc(earliest_safe)}"
                    ),
                }
            )

    return {
        "zone": zone,
        "safe": not violations,
        "dnskey_ttl": dnskey_ttl,
        "max_zone_ttl": max_zone_ttl,
        "clock_skew_seconds": clock_skew_seconds,
        "phases": phases,
        "violations": violations,
        "note": (
            "轮换时序校验仅依据本次请求即时计算，不写入数据库；"
            "新钥发布 → 启签至少等待 DNSKEY TTL + 时钟偏差，"
            "旧钥停签 → 移除至少等待区记录最大 TTL + 时钟偏差"
        ),
    }
