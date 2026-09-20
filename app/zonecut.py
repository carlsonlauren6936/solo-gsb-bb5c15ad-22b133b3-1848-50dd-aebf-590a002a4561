"""区域切割与胶水记录预检（不落库）。

输入为区域名与**扁平 RR 列表**（每条 RR 为 ``(owner, type, class, ttl,
rdata)`` 五元组，规范化由请求模型完成）。处理规则：

1. **区域归属**：所有记录的属主名、以及所有 NS 记录的目标（rdata）都必须
   位于区域内（等于区域名或为其子域），否则抛 :class:`OutOfZoneError`
   （API 层转换为 HTTP 422）；
2. **委派切割**：属主名不是区域顶点（zone apex）的 NS 记录即委派切割，
   切割点为该 NS 的属主名；同一切割点的全部 NS 记录的 rdata 构成该委派的
   NS 目标集合；
3. **最近切割**：每条记录按**最长后缀**匹配定位其最近切割——切割点名等于
   记录属主或为其祖先域，取其中最长（最近）者；
4. **逐条分类**：

   - 不在任何切割之下 → ``authoritative``（含区域顶点 NS）；
   - 切割点上的 NS 记录 → ``authoritative``（切割点 NS 保留）；
   - 切割之下（含切割点）的 A/AAAA 记录，属主**恰为**最近切割委派的
     NS 目标 → ``glue``（作为胶水保留）；
   - 切割之下的 A/AAAA 记录但未被该委派引用 → ``orphan_glue``（违规）；
   - 切割之下的其余记录 → ``occluded``（违规）。

响应中 ``authoritative_records`` / ``glue_records`` / ``violations`` 均按
``(owner, type, rdata)`` 稳定排序（键相同保持提交顺序）。整个预检仅在
内存中计算，不写入数据库。
"""
from __future__ import annotations

#: 422 detail.reason：存在区域外属主或区域外 NS 目标
ERR_OUT_OF_ZONE = "out_of_zone_name"

#: 可作为胶水保留的地址记录类型
_ADDRESS_TYPES = frozenset({"A", "AAAA"})

# 扁平 RR：(owner, type, class, ttl, rdata)，均已规范化
FlatRR = tuple[str, str, str, int, str]


class OutOfZoneError(Exception):
    """存在区域外属主或区域外 NS 目标（对应 HTTP 422）。

    :param owners: 属主名越界的记录（``[{"index": ..., "owner": ...}]``，
        按提交顺序）；
    :param ns_targets: 目标越界的 NS 记录
        （``[{"index": ..., "owner": ..., "target": ...}]``，按提交顺序）。
    """

    def __init__(
        self, message: str, owners: list[dict], ns_targets: list[dict]
    ) -> None:
        super().__init__(message)
        self.code = ERR_OUT_OF_ZONE
        self.owners = owners
        self.ns_targets = ns_targets


def _in_zone(name: str, zone_key: str) -> bool:
    """判断名字是否位于区域内（等于区域名或为其子域）。"""
    return name == zone_key or name.endswith("." + zone_key)


def _nearest_cut(owner: str, cut_names: set[str]) -> str | None:
    """按最长后缀定位最近切割点：从属主名自身逐级向根上溯，返回首个切割点名。"""
    name = owner
    while name:
        if name in cut_names:
            return name
        name = name.partition(".")[2]
    return None


def _sort_key(item: dict) -> tuple[str, str, str]:
    """输出列表的稳定排序键：(owner, type, rdata)。"""
    return (item["owner"], item["type"], item["rdata"])


def check_zone_cuts(zone: str, records: list[FlatRR]) -> dict:
    """对扁平 RR 列表做区域切割与胶水预检，返回分类结果；不写库。

    :param zone: 已校验的区域名（比较时规范化为小写无尾点）；
    :param records: 规范化后的扁平 RR 列表（``(owner, type, class, ttl,
        rdata)`` 五元组）；
    :return: 含 counts、authoritative_records、glue_records 与 violations
        的结果字典；
    :raises OutOfZoneError: 存在区域外属主或区域外 NS 目标；异常的
        ``owners`` / ``ns_targets`` 属性携带越界记录明细。
    """
    zone_key = zone.rstrip(".").lower()

    # 1) 区域归属：属主名与 NS 目标都必须在区域内
    bad_owners: list[dict] = []
    bad_ns_targets: list[dict] = []
    for index, (owner, rtype, _rrclass, _ttl, rdata) in enumerate(records):
        if not _in_zone(owner, zone_key):
            bad_owners.append({"index": index, "owner": owner})
        if rtype == "NS" and not _in_zone(rdata, zone_key):
            bad_ns_targets.append(
                {"index": index, "owner": owner, "target": rdata}
            )
    if bad_owners or bad_ns_targets:
        parts: list[str] = []
        if bad_owners:
            parts.append(f"{len(bad_owners)} 条记录的属主名在区域 {zone_key} 之外")
        if bad_ns_targets:
            parts.append(
                f"{len(bad_ns_targets)} 条 NS 记录的目标在区域 {zone_key} 之外"
            )
        raise OutOfZoneError("；".join(parts), bad_owners, bad_ns_targets)

    # 2) 委派切割：非区域顶点的 NS 记录；目标集合为同切割点全部 NS 的 rdata
    cuts: dict[str, set[str]] = {}
    for owner, rtype, _rrclass, _ttl, rdata in records:
        if rtype == "NS" and owner != zone_key:
            cuts.setdefault(owner, set()).add(rdata)
    cut_names = set(cuts)

    # 3) 逐条分类
    authoritative_records: list[dict] = []
    glue_records: list[dict] = []
    violations: list[dict] = []
    counts = {"authoritative": 0, "glue": 0, "occluded": 0, "orphan_glue": 0}

    for owner, rtype, rrclass, ttl, rdata in records:
        record = {
            "owner": owner,
            "type": rtype,
            "class": rrclass,
            "ttl": ttl,
            "rdata": rdata,
        }
        cut = _nearest_cut(owner, cut_names)
        if cut is None or (owner == cut and rtype == "NS"):
            classification = "authoritative"
        elif rtype in _ADDRESS_TYPES:
            classification = "glue" if owner in cuts[cut] else "orphan_glue"
        else:
            classification = "occluded"
        counts[classification] += 1

        if classification == "authoritative":
            authoritative_records.append(record)
        elif classification == "glue":
            glue_records.append(record)
        else:
            if classification == "occluded":
                message = (
                    f"记录位于委派切割 {cut} 之下，既不是切割点 NS 也不是该委派"
                    f"的胶水记录，发布后将被切割遮蔽"
                )
            else:
                message = (
                    f"地址记录位于委派切割 {cut} 之下，但属主未被该委派的 NS "
                    f"目标引用，属于孤儿胶水"
                )
            violations.append(
                {
                    **record,
                    "classification": classification,
                    "cut": cut,
                    "message": message,
                }
            )

    # 4) 按 (owner, type, rdata) 稳定排序（键相同保持提交顺序）
    authoritative_records.sort(key=_sort_key)
    glue_records.sort(key=_sort_key)
    violations.sort(key=_sort_key)

    return {
        "zone": zone,
        "counts": {"total": len(records), **counts},
        "authoritative_records": authoritative_records,
        "glue_records": glue_records,
        "violations": violations,
        "note": (
            "预检结果仅依据本次请求即时计算，不写入数据库；非区域顶点的 NS 记录"
            "即委派切割，每条记录按最长后缀定位最近切割：切割点 NS 保留为 "
            "authoritative，切割下属主恰为该委派 NS 目标的 A/AAAA 记录保留为 "
            "glue，切割下未被该委派引用的地址记录记为 orphan_glue，切割下其余"
            "记录记为 occluded"
        ),
    }
