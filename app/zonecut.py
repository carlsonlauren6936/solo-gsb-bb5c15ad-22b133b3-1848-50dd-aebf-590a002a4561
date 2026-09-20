"""区域切割（zone cut）与胶水记录预检（不落库）。

输入为扁平 RR 列表（owner/type/class/ttl/rdata，规范化由请求模型完成）。
处理规则：

1. **区域边界**：所有记录的 owner 与所有 NS 记录的目标（rdata）都必须
   位于区域内（等于区域名，或按标签边界以其为后缀），否则抛
   :class:`ZoneCutNameError`（API 层转换为 HTTP 422）；
2. **委派切割识别**：属主不等于区域顶点的 NS 记录即委派切割；同一切割
   点的多条 NS 记录合并为该委派的 NS 目标集合；
3. **最近切割定位**：每条记录按**最长后缀**定位其最近切割——切割点名
   是属主名按标签边界的最长后缀（属主等于切割点，或以其为后缀）；
4. **分类**（每条记录恰属一类）：

   - 不在任何切割之下，或恰为切割点的 NS 记录 → ``authoritative``
     （切割点 NS 即委派记录本身，保留为本区权威数据）；
   - 位于切割之下（切割点处的非 NS 记录视同切割之下）且类型为
     A/AAAA：owner 恰为该委派 NS 目标 → ``glue``（胶水记录，保留），
     否则 → ``orphan_glue``（未被该委派引用的地址记录）；
   - 位于切割之下的其他类型记录 → ``occluded``（被切割遮蔽）；

5. **结果**：authoritative/glue 记录分别以规范化形式返回，
   occluded/orphan_glue 记录逐条生成 violation；所有结果列表按
   ``(owner, type, rdata)`` 稳定排序（并列时保持请求中的先后顺序）。

整个预检仅在内存中计算，不写入数据库。
"""
from __future__ import annotations

# 记录分类取值
CAT_AUTHORITATIVE = "authoritative"
CAT_GLUE = "glue"
CAT_OCCLUDED = "occluded"
CAT_ORPHAN_GLUE = "orphan_glue"

# ZoneCutNameError.code 取值（用于 422 响应中的 reason 字段）
ERR_OUT_OF_ZONE = "out_of_zone_name"

# 可作为胶水记录的地址类型
_GLUE_TYPES = frozenset({"A", "AAAA"})

# 扁平 RR：(owner, type, class, ttl, rdata)，均已由请求模型规范化
FlatRecord = tuple[str, str, str, int, str]


class ZoneCutNameError(Exception):
    """记录 owner 或 NS 目标超出区域（对应 HTTP 422）。

    :param owners: 越界 owner 列表（``{"index", "owner"}``，按下标升序）；
    :param ns_targets: 越界 NS 目标列表（``{"index", "owner", "target"}``，
        按下标升序）。
    """

    def __init__(
        self, message: str, owners: list[dict], ns_targets: list[dict]
    ) -> None:
        super().__init__(message)
        self.code = ERR_OUT_OF_ZONE
        self.owners = owners
        self.ns_targets = ns_targets


def _canonical_zone(zone: str) -> str:
    """区域名规范化用于后缀比较：去首尾空白、去末尾根点、转小写。"""
    return zone.strip().rstrip(".").lower()


def _in_zone(name: str, zone_key: str) -> bool:
    """判断（已规范化的）名字是否位于区域内：等于区域名或按标签边界以其为后缀。"""
    return name == zone_key or name.endswith("." + zone_key)


def _normalize_ns_target(rdata: str) -> str:
    """规范化 NS 目标名用于比较：去首尾空白、去末尾根点、转小写。"""
    return rdata.strip().rstrip(".").lower()


def _nearest_cut(owner: str, cuts: dict[str, set[str]]) -> str | None:
    """按最长后缀定位 owner 的最近切割点；不在任何切割之下时返回 None。"""
    best: str | None = None
    for cut in cuts:
        if owner == cut or owner.endswith("." + cut):
            if best is None or len(cut) > len(best):
                best = cut
    return best


def _record_out(record: FlatRecord) -> dict:
    """把内部扁平 RR 转换为响应结构。"""
    owner, rtype, rrclass, ttl, rdata = record
    return {
        "owner": owner,
        "type": rtype,
        "class": rrclass,
        "ttl": ttl,
        "rdata": rdata,
    }


def _record_sort_key(record: FlatRecord) -> tuple[str, str, str]:
    """结果列表排序键：(owner, type, rdata)；sorted 稳定，并列保持请求顺序。"""
    owner, rtype, _rrclass, _ttl, rdata = record
    return (owner, rtype, rdata)


def run_zone_cut_check(zone: str, records: list[FlatRecord]) -> dict:
    """对扁平 RR 列表做区域切割与胶水记录预检，返回结果字典；不写库。

    :param zone: 已校验的区域名（内部再规范化为小写无尾点用于比较）；
    :param records: 扁平 RR 列表（owner/type/class/ttl/rdata，
        须已由请求模型规范化）；
    :return: 预检结果字典（delegation_cuts、authoritative_records、
        glue_records、violations、summary）；
    :raises ZoneCutNameError: 任一记录 owner 或 NS 目标超出区域。
    """
    zone_key = _canonical_zone(zone)

    # 1. 区域边界校验：所有 owner 与所有 NS 目标都必须在区域内
    out_owners: list[dict] = []
    out_targets: list[dict] = []
    for index, (owner, rtype, _rrclass, _ttl, rdata) in enumerate(records):
        if not _in_zone(owner, zone_key):
            out_owners.append({"index": index, "owner": owner})
        if rtype == "NS":
            target = _normalize_ns_target(rdata)
            if not _in_zone(target, zone_key):
                out_targets.append(
                    {"index": index, "owner": owner, "target": rdata}
                )
    if out_owners or out_targets:
        problems: list[str] = []
        if out_owners:
            problems.append(f"{len(out_owners)} 条记录的 owner 超出区域")
        if out_targets:
            problems.append(f"{len(out_targets)} 条 NS 记录的目标超出区域")
        raise ZoneCutNameError(
            f"区域 {zone_key} 的切割预检失败：" + "，".join(problems),
            owners=out_owners,
            ns_targets=out_targets,
        )

    # 2. 委派切割识别：非区域顶点 NS → 切割点 → 该委派的 NS 目标集合
    cuts: dict[str, set[str]] = {}
    for owner, rtype, _rrclass, _ttl, rdata in records:
        if rtype == "NS" and owner != zone_key:
            cuts.setdefault(owner, set()).add(_normalize_ns_target(rdata))

    # 3. 逐条分类：每条记录按最长后缀定位最近切割
    authoritative: list[FlatRecord] = []
    glue: list[FlatRecord] = []
    violations: list[dict] = []
    counts = {
        CAT_AUTHORITATIVE: 0,
        CAT_GLUE: 0,
        CAT_OCCLUDED: 0,
        CAT_ORPHAN_GLUE: 0,
    }

    for index, record in enumerate(records):
        owner, rtype, _rrclass, _ttl, _rdata = record
        cut = _nearest_cut(owner, cuts)
        if cut is None or (owner == cut and rtype == "NS"):
            # 不在任何切割之下，或恰为切割点的 NS（委派记录本身）：保留
            category = CAT_AUTHORITATIVE
        elif rtype in _GLUE_TYPES:
            # 切割下的地址记录：owner 恰为该委派 NS 目标才可作胶水保留
            category = CAT_GLUE if owner in cuts[cut] else CAT_ORPHAN_GLUE
        else:
            # 切割下的普通记录：被切割遮蔽
            category = CAT_OCCLUDED
        counts[category] += 1

        if category == CAT_AUTHORITATIVE:
            authoritative.append(record)
        elif category == CAT_GLUE:
            glue.append(record)
        else:
            if category == CAT_OCCLUDED:
                message = (
                    f"记录 {owner} {rtype} 位于委派切割 {cut} 之下，"
                    "被切割遮蔽（occluded），不作为本区权威数据"
                )
            else:
                message = (
                    f"地址记录 {owner} {rtype} 位于委派切割 {cut} 之下，"
                    "但 owner 不是该委派的 NS 目标，未被引用（orphan_glue）"
                )
            violations.append(
                {
                    "index": index,
                    "category": category,
                    "cut": cut,
                    "record": _record_out(record),
                    "message": message,
                }
            )

    # 4. 汇总：结果列表按 (owner, type, rdata) 稳定排序（并列保持请求顺序）
    return {
        "zone": zone,
        "delegation_cuts": [
            {"owner": cut, "ns_targets": sorted(targets)}
            for cut, targets in sorted(cuts.items())
        ],
        "authoritative_records": [
            _record_out(record)
            for record in sorted(authoritative, key=_record_sort_key)
        ],
        "glue_records": [
            _record_out(record) for record in sorted(glue, key=_record_sort_key)
        ],
        "violations": sorted(
            violations,
            key=lambda item: (
                item["record"]["owner"],
                item["record"]["type"],
                item["record"]["rdata"],
            ),
        ),
        "summary": {
            "total": len(records),
            "authoritative": counts[CAT_AUTHORITATIVE],
            "glue": counts[CAT_GLUE],
            "occluded": counts[CAT_OCCLUDED],
            "orphan_glue": counts[CAT_ORPHAN_GLUE],
        },
    }
