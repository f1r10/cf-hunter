#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CF-HUNTER v7.2.2 SAFE @f1r10
v7.2.1 təməli üzərində daha güclü analyst-grade wrapper.

Nə əlavə edir:
- executive/analyst/raw-evidence report layer
- severity buckets və candidate comparison əlavələri
- timeout profiling və environment diagnostics
- stronger evidence ledger / scoring explanation summary
- checkpoint/state faylları (stage-level)
- CSV/JSON/Markdown yanında text summary export
- explain mode üçün daha dərin səbəb çıxışı
- adaptive nəticə normallaşdırması və top candidate review

Qeyd:
- Bu versiya v7.2.1-in bütün təhlükəsiz imkanlarını saxlayır.
- Bypass, auth bypass, exploitation və destructive logic əlavə etmir.
"""

import argparse
import copy
import csv
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import time
from datetime import datetime
from typing import Any, Dict, List, Tuple

BASE_PATH = "cf_hunter_v7.2.1.py"


def _load_base():
    spec = importlib.util.spec_from_file_location("cf_hunter_v721_base", BASE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Base file not found or not loadable: {BASE_PATH}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


base = _load_base()
C = base.C


def banner():
    print(f"""{C.CYAN}{C.BOLD}
 ██████╗███████╗      ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
██╔════╝██╔════╝      ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
██║     █████╗  █████╗███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
██║     ██╔══╝  ╚════╝██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
╚██████╗██║           ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
 ╚═════╝╚═╝           ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
{C.RESET}{C.DIM}  CF-HUNTER v7.2.2 SAFE — Precision, Diagnostics, Analyst Pack{C.RESET}
""")


class CheckpointStore:
    def __init__(self, domain: str, enabled: bool = True, state_dir: str = ".cfhunter_state"):
        self.enabled = enabled
        self.domain = domain
        self.state_dir = Path(state_dir)
        if self.enabled:
            self.state_dir.mkdir(parents=True, exist_ok=True)
        safe = re.sub(r"[^a-zA-Z0-9._-]+", "_", domain)
        self.path = self.state_dir / f"{safe}.v7_2_2.checkpoints.json"

    def load(self) -> Dict[str, Any]:
        if not self.enabled or not self.path.exists():
            return {}
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def save_stage(self, stage: str, payload: Dict[str, Any]):
        if not self.enabled:
            return
        cur = self.load()
        cur[stage] = {"saved_at": time.time(), **payload}
        try:
            self.path.write_text(json.dumps(cur, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception:
            pass


def _bucket_timeout(msg: str) -> str:
    m = (msg or "").lower()
    if not m:
        return "unknown"
    if "network is unreachable" in m:
        return "unreachable"
    if "timed out" in m or "timeout" in m:
        return "timeout"
    if "empty response" in m:
        return "empty-response"
    if "refused" in m:
        return "refused"
    if "ssl" in m or "handshake" in m:
        return "tls"
    return "other"


def build_timeout_profile(result: Dict[str, Any]) -> Dict[str, Any]:
    counts: Dict[str, int] = {}
    by_ip: Dict[str, Dict[str, Any]] = {}
    verify = result.get("verify_results") or result.get("verify_summary", {}).get("details", {}) or {}
    for ip, data in verify.items():
        local = {"http": {}, "https": {}}
        if isinstance(data, dict) and "paths" in data:
            for scheme in ("http", "https"):
                for path, fp in (data.get("paths", {}).get(scheme, {}) or {}).items():
                    status = fp.get("status")
                    if status is None:
                        local[scheme][path] = "no-response"
        else:
            for side in ("raw_http", "raw_https"):
                raw = data.get(side, {}) if isinstance(data, dict) else {}
                bucket = _bucket_timeout(raw.get("error", ""))
                counts[bucket] = counts.get(bucket, 0) + 1
                local[side.replace("raw_", "")] = bucket
        # Also collect raw errors if present.
        if isinstance(data, dict):
            for side in ("raw_http", "raw_https"):
                raw = data.get(side, {})
                if isinstance(raw, dict):
                    bucket = _bucket_timeout(raw.get("error", ""))
                    counts[bucket] = counts.get(bucket, 0) + 1
                    local[side.replace("raw_", "")] = bucket
        by_ip[ip] = local
    env = "healthy"
    total = sum(counts.values())
    if total:
        if counts.get("timeout", 0) + counts.get("tls", 0) + counts.get("unreachable", 0) >= max(3, int(total * 0.65)):
            env = "blocked-or-unreachable"
        elif counts.get("empty-response", 0) >= max(2, int(total * 0.4)):
            env = "filtered-or-proxying"
    return {"summary": counts, "by_ip": by_ip, "environment_signal": env}


def infer_service_role(ip: str, sources: List[str], related_subs: List[str], shodan: Dict[str, Any] | None = None) -> Tuple[str, List[str]]:
    reasons = []
    s = set(sources or [])
    subs = " ".join(related_subs or []).lower()
    shodan = shodan or {}
    ports = set(shodan.get("ports") or [])

    if any(x in s for x in ["mx-record", "spf-record"]) or any(k in subs for k in ["mail", "smtp", "mx", "webmail"]):
        reasons.append("mail siqnalları üstünlük təşkil edir")
        return "mail-related", reasons
    if any(k in subs for k in ["cdn", "static", "assets", "img", "media"]):
        reasons.append("cdn/static alt-domain pattern-i")
        return "cdn-or-static", reasons
    if ports & {2082, 2083, 2086, 2087, 8443, 8880, 8080}:
        reasons.append("admin/service port pattern-i")
        return "service-panel", reasons
    if any(k in subs for k in ["api", "auth", "gateway", "app", "www", "forum", "common"]):
        reasons.append("app-facing subdomain pattern-i")
        return "app-facing", reasons
    return "unknown", reasons


STRONG_WEIGHTS = {
    "multi_path_match": 18,
    "content_match": 14,
    "same_redirect": 12,
    "sub_non_cf": 8,
    "tls_san": 7,
    "cross_validated": 6,
    "verified_api_pair": 5,
    "tech_overlap": 4,
}
NEGATIVE_WEIGHTS = {
    "google_mx": -14,
    "mail_only": -12,
    "cloudflare_cpe": -12,
    "unreachable_ipv6": -9,
    "only_scraped_sources": -5,
    "no_verify_signal": -10,
}


def build_evidence_ledger(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    verify = result.get("verify_results") or result.get("verify_summary", {}).get("details", {}) or {}
    all_ips = result.get("all_ips") or {}
    sub_resolved = (result.get("subdomains") or {}).get("resolved", {}) or {}
    origin_candidates = result.get("origin_candidates") or []
    origin_map = {c.get("ip"): c for c in origin_candidates if isinstance(c, dict)}
    google_mx_ips = set((result.get("dns_records") or {}).get("mx_ips") or [])

    related_by_ip: Dict[str, List[str]] = {}
    for sub, ips in sub_resolved.items():
        for ip in ips:
            related_by_ip.setdefault(ip, []).append(sub)

    rows = []
    for ip, sources in all_ips.items():
        v = verify.get(ip, {})
        related = sorted(set(related_by_ip.get(ip, [])))
        cand = origin_map.get(ip, {})
        shodan = cand.get("shodan") or {}
        verdict = v.get("verdict") or cand.get("verdict") or "UNKNOWN"
        score = 0
        positives, negatives = [], []
        srcs = list(sources or [])
        src_text = " ".join(srcs)
        role, role_reasons = infer_service_role(ip, srcs, related, shodan)

        if any(s.startswith("sub:") for s in srcs) or any(s in srcs for s in ["urlscan.io", "crtsh", "certspotter"]):
            positives.append({"signal": "sub_non_cf", "weight": STRONG_WEIGHTS["sub_non_cf"], "why": "non-CF subdomain və ya recon source siqnalı"})
            score += STRONG_WEIGHTS["sub_non_cf"]
        if cand.get("cross_validated"):
            positives.append({"signal": "cross_validated", "weight": STRONG_WEIGHTS["cross_validated"], "why": "ən azı iki müstəqil siqnal kəsişib"})
            score += STRONG_WEIGHTS["cross_validated"]
        if v.get("matches", 0) >= 2:
            positives.append({"signal": "multi_path_match", "weight": STRONG_WEIGHTS["multi_path_match"], "why": f"{v.get('matches')} path fingerprint oxşarlığı"})
            score += STRONG_WEIGHTS["multi_path_match"]
        if len(set([s for s in srcs if s in ["urlscan.io", "shodan-idb", "alienvault-otx", "crtsh", "certspotter"]])) >= 2:
            positives.append({"signal": "verified_api_pair", "weight": STRONG_WEIGHTS["verified_api_pair"], "why": "birdən çox verified API siqnalı"})
            score += STRONG_WEIGHTS["verified_api_pair"]
        if "tls-san" in src_text:
            positives.append({"signal": "tls_san", "weight": STRONG_WEIGHTS["tls_san"], "why": "TLS SAN ilə əlaqə"})
            score += STRONG_WEIGHTS["tls_san"]

        if ip in google_mx_ips:
            negatives.append({"signal": "google_mx", "weight": NEGATIVE_WEIGHTS["google_mx"], "why": "Google MX infrastrukturu origin üçün zəif siqnaldır"})
            score += NEGATIVE_WEIGHTS["google_mx"]
        if role == "mail-related":
            negatives.append({"signal": "mail_only", "weight": NEGATIVE_WEIGHTS["mail_only"], "why": "yalnız mail-related rol görünür"})
            score += NEGATIVE_WEIGHTS["mail_only"]
        cpes = (shodan.get("cpes") or []) if isinstance(shodan, dict) else []
        if any("cloudflare" in str(c).lower() for c in cpes):
            negatives.append({"signal": "cloudflare_cpe", "weight": NEGATIVE_WEIGHTS["cloudflare_cpe"], "why": "Shodan CPE Cloudflare göstərir"})
            score += NEGATIVE_WEIGHTS["cloudflare_cpe"]
        if ":" in ip and any(_bucket_timeout((v.get("raw_http") or {}).get("error", "")) == "unreachable" or _bucket_timeout((v.get("raw_https") or {}).get("error", "")) == "unreachable" for _ in [0]):
            negatives.append({"signal": "unreachable_ipv6", "weight": NEGATIVE_WEIGHTS["unreachable_ipv6"], "why": "IPv6 reachable deyil"})
            score += NEGATIVE_WEIGHTS["unreachable_ipv6"]
        source_tiers = [base.source_trust(s)[0] for s in srcs]
        if source_tiers and all(t == "SCRAPED" for t in source_tiers):
            negatives.append({"signal": "only_scraped_sources", "weight": NEGATIVE_WEIGHTS["only_scraped_sources"], "why": "yalnız zəif source-lar"})
            score += NEGATIVE_WEIGHTS["only_scraped_sources"]
        if (v.get("score", 0) <= 0) and (v.get("matches", 0) == 0):
            negatives.append({"signal": "no_verify_signal", "weight": NEGATIVE_WEIGHTS["no_verify_signal"], "why": "verify mərhələsindən müsbət siqnal çıxmayıb"})
            score += NEGATIVE_WEIGHTS["no_verify_signal"]

        confidence_band = "LOW"
        if score >= 20:
            confidence_band = "HIGH"
        elif score >= 8:
            confidence_band = "MEDIUM"

        rows.append({
            "ip": ip,
            "role_inference": role,
            "role_reasons": role_reasons,
            "verdict": verdict,
            "weighted_score": score,
            "confidence_band": confidence_band,
            "sources": srcs,
            "related_subdomains": related,
            "verify_score": v.get("score", 0),
            "verify_matches": v.get("matches", 0),
            "positive_evidence": positives,
            "negative_evidence": negatives,
        })
    rows.sort(key=lambda x: (x["weighted_score"], x["verify_matches"], x["verify_score"]), reverse=True)
    return rows


def severity_bucketize(result: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    buckets = {"high": [], "medium": [], "low": [], "info": []}
    posture = result.get("public_posture") or {}
    for item in posture.get("interesting_paths", []) or []:
        sev = str(item.get("severity", "info")).lower()
        buckets.setdefault(sev, []).append(item)
    for an in result.get("anomalies", []) or []:
        sev = str(an.get("severity", "low")).lower()
        buckets.setdefault(sev, []).append(an)
    return buckets


def build_timeline(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    meta = result.get("meta") or {}
    out = []
    if meta.get("generated_at"):
        out.append({"time": meta.get("generated_at"), "event": "scan-finished"})
    if meta.get("elapsed_seconds") is not None:
        out.append({"time": f"+{meta.get('elapsed_seconds')}s", "event": "total-elapsed"})
    for k, v in (result.get("source_health") or {}).items():
        out.append({"time": "runtime", "event": f"source:{k}", "detail": v})
    return out


def build_exec_summary(result: Dict[str, Any]) -> Dict[str, Any]:
    posture = result.get("public_posture") or {}
    env = result.get("environment") or {}
    ledger = result.get("evidence_ledger") or []
    top = ledger[:5]
    return {
        "domain": (result.get("meta") or {}).get("domain") or result.get("domain"),
        "tool": (result.get("meta") or {}).get("tool", "CF-HUNTER v7.2.2 SAFE"),
        "scan_elapsed_seconds": (result.get("meta") or {}).get("elapsed_seconds"),
        "public_risk_level": posture.get("risk_level", "UNKNOWN"),
        "public_risk_score": posture.get("risk_score", 0),
        "environment_signal": (env.get("timeout_profile") or {}).get("environment_signal", "unknown"),
        "top_candidates": [
            {
                "ip": c.get("ip"),
                "weighted_score": c.get("weighted_score"),
                "confidence_band": c.get("confidence_band"),
                "role_inference": c.get("role_inference"),
                "verdict": c.get("verdict"),
            }
            for c in top
        ],
        "strong_candidates_count": len([x for x in ledger if x.get("confidence_band") in ["HIGH", "MEDIUM"]]),
        "excluded_weak_candidates_count": len([x for x in ledger if x.get("confidence_band") == "LOW"]),
    }


def build_analyst_summary(result: Dict[str, Any]) -> Dict[str, Any]:
    ledger = result.get("evidence_ledger") or []
    posture = result.get("public_posture") or {}
    buckets = result.get("severity_buckets") or {}
    non_cf = (result.get("subdomains") or {}).get("non_cf", []) or []
    return {
        "analysis_summary": (result.get("meta") or {}).get("analysis_summary", ""),
        "candidate_compare": [
            {
                "ip": x.get("ip"),
                "weighted_score": x.get("weighted_score"),
                "verify_score": x.get("verify_score"),
                "verify_matches": x.get("verify_matches"),
                "confidence_band": x.get("confidence_band"),
                "role_inference": x.get("role_inference"),
                "top_positive": [p.get("signal") for p in x.get("positive_evidence", [])[:3]],
                "top_negative": [n.get("signal") for n in x.get("negative_evidence", [])[:3]],
            }
            for x in ledger[:10]
        ],
        "non_cf_exposures_count": len(non_cf),
        "public_posture": {
            "risk_level": posture.get("risk_level"),
            "risk_score": posture.get("risk_score"),
            "interesting_paths": len(posture.get("interesting_paths", []) or []),
        },
        "severity_overview": {k: len(v) for k, v in buckets.items()},
    }


def build_raw_evidence_summary(result: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "source_health": result.get("source_health") or {},
        "dns_records": result.get("dns_records") or {},
        "subdomain_families": result.get("subdomain_families") or {},
        "certificate_san_clusters": result.get("certificate_san_clusters") or {},
        "historical_dns_diff": result.get("historical_dns_diff") or {},
        "timeout_profile": (result.get("environment") or {}).get("timeout_profile") or {},
    }


def augment_markdown(base_md: str, result: Dict[str, Any]) -> str:
    exec_sum = result.get("executive_summary") or {}
    analyst = result.get("analyst_summary") or {}
    raw = result.get("raw_evidence_summary") or {}
    comp = result.get("candidate_comparison") or result.get("evidence_ledger") or []
    weak = [x for x in result.get("evidence_ledger", []) if x.get("confidence_band") == "LOW"][:10]
    lines = []
    lines.append("\n\n## Executive summary\n")
    lines.append(f"- Domain: {exec_sum.get('domain')}\n")
    lines.append(f"- Public risk: {exec_sum.get('public_risk_level')} ({exec_sum.get('public_risk_score')})\n")
    lines.append(f"- Environment signal: {exec_sum.get('environment_signal')}\n")
    lines.append(f"- Strong candidates: {exec_sum.get('strong_candidates_count')}\n")
    lines.append(f"- Excluded weak candidates: {exec_sum.get('excluded_weak_candidates_count')}\n")
    lines.append("\n## Analyst summary\n")
    lines.append(f"- Summary: {analyst.get('analysis_summary','')}\n")
    lines.append(f"- Severity overview: {json.dumps(analyst.get('severity_overview', {}), ensure_ascii=False)}\n")
    lines.append("\n## Top candidate comparison\n")
    lines.append("| IP | Weighted | Verify | Matches | Band | Role |\n|---|---:|---:|---:|---|---|\n")
    for row in comp[:10]:
        lines.append(f"| {row.get('ip')} | {row.get('weighted_score', row.get('score',''))} | {row.get('verify_score','')} | {row.get('verify_matches','')} | {row.get('confidence_band','')} | {row.get('role_inference','')} |\n")
    if weak:
        lines.append("\n## Weak candidates excluded and why\n")
        for row in weak:
            neg = ", ".join([f"{n.get('signal')}({n.get('weight')})" for n in row.get('negative_evidence', [])[:5]])
            lines.append(f"- {row.get('ip')}: {neg}\n")
    lines.append("\n## Raw evidence summary\n")
    lines.append(f"```json\n{json.dumps(raw, ensure_ascii=False, indent=2)[:5000]}\n```\n")
    return base_md + "".join(lines)


def save_text_summary(result: Dict[str, Any], output_path: str):
    exec_sum = result.get("executive_summary") or {}
    analyst = result.get("analyst_summary") or {}
    lines = [
        f"Tool: {exec_sum.get('tool','CF-HUNTER v7.2.2 SAFE')}",
        f"Domain: {exec_sum.get('domain','')}",
        f"Public risk: {exec_sum.get('public_risk_level','UNKNOWN')} ({exec_sum.get('public_risk_score',0)})",
        f"Environment signal: {exec_sum.get('environment_signal','unknown')}",
        f"Summary: {analyst.get('analysis_summary','')}",
        "",
        "Top candidates:",
    ]
    for row in (result.get("evidence_ledger") or [])[:10]:
        lines.append(f"- {row.get('ip')} | weighted={row.get('weighted_score')} | verify={row.get('verify_score')} | band={row.get('confidence_band')} | role={row.get('role_inference')} | verdict={row.get('verdict')}")
    Path(output_path).write_text("\n".join(lines), encoding="utf-8")


def save_full_csv(result: Dict[str, Any], output_path: str):
    rows = result.get("evidence_ledger") or []
    fields = [
        "ip", "weighted_score", "confidence_band", "verdict", "role_inference",
        "verify_score", "verify_matches", "sources", "related_subdomains",
        "positive_signals", "negative_signals"
    ]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for row in rows:
            w.writerow({
                "ip": row.get("ip"),
                "weighted_score": row.get("weighted_score"),
                "confidence_band": row.get("confidence_band"),
                "verdict": row.get("verdict"),
                "role_inference": row.get("role_inference"),
                "verify_score": row.get("verify_score"),
                "verify_matches": row.get("verify_matches"),
                "sources": ";".join(row.get("sources", [])),
                "related_subdomains": ";".join(row.get("related_subdomains", [])),
                "positive_signals": ";".join([p.get("signal","") for p in row.get("positive_evidence", [])]),
                "negative_signals": ";".join([n.get("signal","") for n in row.get("negative_evidence", [])]),
            })


def deepen_explain(result: Dict[str, Any], ip: str) -> str:
    ledger = {r.get("ip"): r for r in result.get("evidence_ledger", [])}
    row = ledger.get(ip)
    if not row:
        return f"{ip} üçün dərin explain tapılmadı."
    parts = [
        f"IP: {ip}",
        f"Weighted score: {row.get('weighted_score')}",
        f"Confidence band: {row.get('confidence_band')}",
        f"Role inference: {row.get('role_inference')}",
        f"Verdict: {row.get('verdict')}",
        f"Sources: {', '.join(row.get('sources', []))}",
        f"Related subdomains: {', '.join(row.get('related_subdomains', [])) or '-'}",
        "Positive evidence:",
    ]
    for p in row.get("positive_evidence", []):
        parts.append(f"  + {p.get('signal')} ({p.get('weight')}): {p.get('why')}")
    parts.append("Negative evidence:")
    for n in row.get("negative_evidence", []):
        parts.append(f"  - {n.get('signal')} ({n.get('weight')}): {n.get('why')}")
    return "\n".join(parts)


def enhance_result(result: Dict[str, Any], domain: str, checkpoint: CheckpointStore) -> Dict[str, Any]:
    result = copy.deepcopy(result)
    result.setdefault("meta", {})
    result["meta"]["tool"] = "CF-HUNTER v7.2.2 SAFE"
    checkpoint.save_stage("base_analysis_complete", {"elapsed_seconds": result.get("meta", {}).get("elapsed_seconds")})

    timeout_profile = build_timeout_profile(result)
    env = result.get("environment") or {}
    env["timeout_profile"] = timeout_profile
    result["environment"] = env
    checkpoint.save_stage("timeout_profile_complete", {"summary": timeout_profile.get("summary", {})})

    result["evidence_ledger"] = build_evidence_ledger(result)
    checkpoint.save_stage("evidence_ledger_complete", {"count": len(result.get("evidence_ledger", []))})

    # Stronger candidate comparison prefers weighted evidence.
    result["candidate_comparison"] = [
        {
            "ip": r.get("ip"),
            "weighted_score": r.get("weighted_score"),
            "verify_score": r.get("verify_score"),
            "verify_matches": r.get("verify_matches"),
            "confidence_band": r.get("confidence_band"),
            "role_inference": r.get("role_inference"),
            "verdict": r.get("verdict"),
            "related_subdomains": r.get("related_subdomains"),
        }
        for r in result.get("evidence_ledger", [])
    ]
    result["severity_buckets"] = severity_bucketize(result)
    result["timeline"] = build_timeline(result)
    result["executive_summary"] = build_exec_summary(result)
    result["analyst_summary"] = build_analyst_summary(result)
    result["raw_evidence_summary"] = build_raw_evidence_summary(result)
    checkpoint.save_stage("report_layers_complete", {"time": time.time()})

    # Better analysis summary text.
    top = result.get("evidence_ledger", [])[:1]
    top_text = "yoxdur"
    if top:
        t = top[0]
        top_text = f"{t.get('ip')} | weighted={t.get('weighted_score')} | band={t.get('confidence_band')} | role={t.get('role_inference')}"
    result["meta"]["analysis_summary"] = (
        f"Hədəf: {domain} | Public risk: {(result.get('public_posture') or {}).get('risk_level','UNKNOWN')} "
        f"({(result.get('public_posture') or {}).get('risk_score',0)}) | "
        f"Environment: {timeout_profile.get('environment_signal','unknown')} | "
        f"Top namizəd: {top_text}"
    )
    return result


def analyze(domain: str, output_file: str | None = None, verbose: bool = False, skip_github: bool = False,
            skip_verify: bool = False, verify_workers: int = 12, resolve_workers: int = 60,
            posture_workers: int = 10, full: bool = False, cache_enabled: bool = True,
            cache_ttl: int = 21600, resume: bool = True, write_md: bool = False,
            probe_timeout: int = 6, probe_retries: int = 2, quick: bool = False,
            recon_only: bool = False, posture_only: bool = False, verify_only: bool = False,
            top_n: int = 50, export_csv: str | None = None, explain_ip_addr: str | None = None,
            save_state: bool = False, export_txt: str | None = None, full_csv: str | None = None):
    checkpoint = CheckpointStore(domain, enabled=resume or save_state)
    checkpoint.save_stage("start", {"ts": time.time(), "domain": domain})

    result = base.analyze(
        domain=domain,
        output_file=None,
        verbose=verbose,
        skip_github=skip_github,
        skip_verify=skip_verify,
        verify_workers=verify_workers,
        resolve_workers=resolve_workers,
        posture_workers=posture_workers,
        full=full,
        cache_enabled=cache_enabled,
        cache_ttl=cache_ttl,
        resume=resume,
        write_md=False,
        probe_timeout=probe_timeout,
        probe_retries=probe_retries,
        quick=quick,
        recon_only=recon_only,
        posture_only=posture_only,
        verify_only=verify_only,
        top_n=max(1, top_n),
        export_csv=None,
        explain_ip_addr=None,
        save_state=save_state,
    )
    result = enhance_result(result, domain, checkpoint)
    result["evidence_ledger"] = result.get("evidence_ledger", [])[:max(1, top_n)]
    result["candidate_comparison"] = result.get("candidate_comparison", [])[:max(1, top_n)]

    if output_file:
        Path(output_file).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\n{C.GREEN}[+] JSON saxlandı: {output_file}{C.RESET}")
    md_path = None
    if write_md:
        md_base = base.build_markdown_report(result)
        md_aug = augment_markdown(md_base, result)
        md_path = output_file.rsplit('.', 1)[0] + '.md' if output_file else f"{domain}_cfhunter_v7_2_2.md"
        Path(md_path).write_text(md_aug, encoding="utf-8")
        print(f"{C.GREEN}[+] Markdown saxlandı: {md_path}{C.RESET}")
    if export_csv:
        base.save_csv_report(result, export_csv)
        print(f"{C.GREEN}[+] CSV saxlandı: {export_csv}{C.RESET}")
    if full_csv:
        save_full_csv(result, full_csv)
        print(f"{C.GREEN}[+] Full CSV saxlandı: {full_csv}{C.RESET}")
    if export_txt:
        save_text_summary(result, export_txt)
        print(f"{C.GREEN}[+] TXT summary saxlandı: {export_txt}{C.RESET}")
    if explain_ip_addr:
        print("\n" + deepen_explain(result, explain_ip_addr))
    checkpoint.save_stage("complete", {"ts": time.time(), "output": output_file, "md": md_path})
    return result


def main():
    banner()
    ap = argparse.ArgumentParser(description="CF-Hunter v7.2.2: v7.2.1 üstündə daha detallı, daha dürüst, analyst-grade precision report engine")
    ap.add_argument("domain", help="Hədəf domain")
    ap.add_argument("-o", "--output", help="JSON faylına yaz")
    ap.add_argument("-v", "--verbose", action="store_true", help="Ətraflı çıxış")
    ap.add_argument("--full", action="store_true", help="Adaptive full coverage")
    ap.add_argument("--quick", action="store_true", help="Daha sürətli, yüngül rejim")
    ap.add_argument("--recon-only", action="store_true", help="Əsasən recon yönümlü rejim")
    ap.add_argument("--posture-only", action="store_true", help="Yalnız public posture yönümlü rejim")
    ap.add_argument("--verify-only", action="store_true", help="Verify yönümlü rejim")
    ap.add_argument("--no-github", action="store_true", help="GitHub leak detection-u atla")
    ap.add_argument("--skip-verify", action="store_true", help="Verify mərhələsini atla")
    ap.add_argument("--verify-workers", type=int, default=12, help="Verify worker sayı")
    ap.add_argument("--resolve-workers", type=int, default=60, help="Resolve worker sayı")
    ap.add_argument("--posture-workers", type=int, default=10, help="Posture/audit worker sayı")
    ap.add_argument("--no-cache", action="store_true", help="Cache-i söndür")
    ap.add_argument("--cache-ttl", type=int, default=21600, help="Cache TTL (saniyə)")
    ap.add_argument("--no-resume", action="store_true", help="Daxili state/resume faylını söndür")
    ap.add_argument("--save-state", action="store_true", help="Əlavə checkpoint state faylları saxla")
    ap.add_argument("--md-report", action="store_true", help="Markdown report da yarat")
    ap.add_argument("--export-csv", help="Əvvəlki candidate comparison üçün CSV çıxış yolu")
    ap.add_argument("--full-csv", help="Tam evidence ledger CSV çıxış yolu")
    ap.add_argument("--export-txt", help="Executive/analyst summary text çıxış yolu")
    ap.add_argument("--top", type=int, default=50, help="Top N namizədi saxla/göstər")
    ap.add_argument("--explain", dest="explain_ip_addr", help="Müəyyən IP üçün səbəbləri göstər")
    ap.add_argument("--probe-timeout", type=int, default=6, help="IP probe timeout (saniyə)")
    ap.add_argument("--probe-retries", type=int, default=2, help="IP probe retry sayı")
    args = ap.parse_args()

    domain = args.domain.strip().lower()
    domain = re.sub(r'^https?://', '', domain).split('/')[0].split('?')[0]
    if not re.match(r'^[a-z0-9][a-z0-9._-]+\.[a-z]{2,}$', domain):
        print(f"{C.RED}[!] Yanlış domain formatı: {domain}{C.RESET}")
        sys.exit(1)

    analyze(
        domain=domain,
        output_file=args.output,
        verbose=args.verbose,
        skip_github=args.no_github,
        skip_verify=args.skip_verify,
        verify_workers=max(1, min(args.verify_workers, 100)),
        resolve_workers=max(1, min(args.resolve_workers, 250)),
        posture_workers=max(1, min(args.posture_workers, 60)),
        full=args.full,
        cache_enabled=not args.no_cache,
        cache_ttl=max(60, args.cache_ttl),
        resume=not args.no_resume,
        write_md=args.md_report,
        probe_timeout=args.probe_timeout,
        probe_retries=args.probe_retries,
        quick=args.quick,
        recon_only=args.recon_only,
        posture_only=args.posture_only,
        verify_only=args.verify_only,
        top_n=args.top,
        export_csv=args.export_csv,
        explain_ip_addr=args.explain_ip_addr,
        save_state=args.save_state,
        export_txt=args.export_txt,
        full_csv=args.full_csv,
    )


if __name__ == "__main__":
    main()
