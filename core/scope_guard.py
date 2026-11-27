from collections.abc import Iterable
import ipaddress
import re
from urllib.parse import urlparse
from urllib3.util import parse_url as urllib3_parse_url


class ScopeGuard:
    """
    Rules of Engagement (RoE) Scope Enforcer.
    Har bir domen, IP yoki URL ruxsat berilgan (In-Scope) doirada ekanligini
    va Out-of-Scope ro'yxatiga tushmasligini qat'iy tekshiradi.
    """

    CDN_SIGNATURES = (
        "cloudflare.com",
        "Cloudflare",
        "akamai.net",
        "akamaiedge.net",
        "cloudfront.net",
        "fastly.net",
        "incapdns.net",
        "googleapis.com",
        "gstatic.com",
        "googletagmanager.com",
        "google-analytics.com",
        "facebook.com",
        "doubleclick.net",
    )

    def __init__(self, in_scope_raw: str | Iterable[str] = "", out_of_scope_raw: str | Iterable[str] = ""):
        self.in_scope = self._parse_rules(in_scope_raw)
        self.out_of_scope = self._parse_rules(out_of_scope_raw)

    @staticmethod
    def _parse_rules(raw_text: str | Iterable[str]) -> list[str]:
        if not raw_text:
            return []
        chunks = [raw_text] if isinstance(raw_text, str) else [str(x) for x in raw_text if x is not None]
        items: list[str] = []
        for entry in chunks:
            for line in re.split(r"[,;\n\r]+", entry):
                cleaned = line.strip().lower()
                if cleaned and not cleaned.startswith("#"):
                    items.append(cleaned)
        return items

    _VALID_HOST_RE = re.compile(
        r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9\-_]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9\-]{2,59})$"
    )

    @classmethod
    def extract_host(cls, target: str, _allow_wildcard_rule: bool = False) -> str:
        raw = (target or "").strip().lower()
        if not raw or "\\" in raw or any(ord(c) <= 0x20 or ord(c) == 0x7F for c in raw):
            return ""
        if raw.startswith("//"):
            raw = "http:" + raw
        if _allow_wildcard_rule:
            if raw.startswith("*."):
                raw = raw[2:]
            elif "://*." in raw:
                raw = raw.replace("://*.", "://", 1)
        if "://" in raw:
            parsed = urlparse(raw)
            if parsed.username or parsed.password or "@" in (parsed.netloc or ""):
                return ""
            try:
                u3 = urllib3_parse_url(raw)
            except Exception:
                return ""
            if u3.auth:
                return ""
            h_std = (parsed.hostname or "").strip().lower()
            h_u3 = (u3.host or "").strip("[]").strip().lower()
            if "%" in h_std:
                h_std = h_std.split("%", 1)[0]
            if "%" in h_u3:
                h_u3 = h_u3.split("%", 1)[0]
            h_std = h_std.strip(".")
            h_u3 = h_u3.strip(".")
            if not h_std or h_std != h_u3:
                return ""
            host = h_std
        else:
            path_stripped = raw.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
            if "@" in path_stripped:
                return ""
            if path_stripped.startswith("[") and "]" in path_stripped:
                host = path_stripped[1 : path_stripped.index("]")]
            elif path_stripped.count(":") >= 2:
                host = path_stripped
            else:
                host = path_stripped.split(":", 1)[0]
            if "%" in host:
                host = host.split("%", 1)[0]
            host = host.strip(".")
        if "*" in host:
            return ""
        if host and not host.isascii():
            try:
                host = host.encode("idna").decode("ascii")
            except Exception:
                return ""
        return host

    SECOND_LEVEL_TLDS = {
        "co.uk", "org.uk", "ac.uk", "gov.uk",
        "com.uz", "org.uz", "gov.uz", "edu.uz", "net.uz", "mil.uz", "ac.uz",
        "com.tr", "gov.tr", "com.ru", "pp.ua", "co.jp", "com.br", "com.au", "co.za",
    }

    @classmethod
    def _is_multi_label_psl(cls, tail: str) -> bool:
        tail = (tail or "").strip(".").lower()
        if tail in cls.SECOND_LEVEL_TLDS:
            return True
        if "." not in tail:
            return False
        try:
            from core.threat_intel_pack import get_public_suffix_rules
            normal_psl, wildcard_bases, exceptions = get_public_suffix_rules()
            if tail in exceptions:
                return False
            if tail in normal_psl:
                return True
            parent = tail.split(".", 1)[1]
            return parent in wildcard_bases
        except Exception:
            return False

    @classmethod
    def extract_apex_domain(cls, target: str) -> str:
        host = cls.extract_host(target, _allow_wildcard_rule=True)
        if not host:
            return ""
        try:
            ipaddress.ip_address(host)
            return host
        except ValueError:
            pass
        parts = host.split(".")
        if len(parts) >= 4 and cls._is_multi_label_psl(".".join(parts[-3:])):
            return ".".join(parts[-4:])
        if len(parts) >= 3:
            last_two = f"{parts[-2]}.{parts[-1]}"
            if cls._is_multi_label_psl(last_two):
                return ".".join(parts[-3:])
            return ".".join(parts[-2:])
        return host

    def _matches_rule(self, host: str, rule: str, is_out_of_scope: bool = False) -> bool:
        raw_rule = (rule or "").strip().lower()
        if not raw_rule:
            return False

        if "/" in raw_rule and "://" not in raw_rule and not raw_rule.startswith("//"):
            try:
                net = ipaddress.ip_network(raw_rule, strict=False)
                ip_obj = ipaddress.ip_address(host)
                return ip_obj in net
            except ValueError:
                pass

        is_wildcard = raw_rule.startswith("*.") or "://*." in raw_rule or raw_rule.startswith("//*.")
        rule_host = self.extract_host(raw_rule, _allow_wildcard_rule=True)
        if not rule_host or self._is_multi_label_psl(rule_host):
            return False

        try:
            ip_rule = ipaddress.ip_address(rule_host)
            ip_host = ipaddress.ip_address(host)
            return ip_rule == ip_host
        except ValueError:
            pass

        if is_out_of_scope or is_wildcard:
            return host == rule_host or host.endswith("." + rule_host)

        apex = self.extract_apex_domain(rule_host)
        if rule_host == apex and not self._is_multi_label_psl(apex):
            return host == rule_host or host.endswith("." + rule_host)
        return host == rule_host

    def is_in_scope(self, target: str) -> tuple[bool, str]:
        host = self.extract_host(target)
        if not host:
            return False, "Bo'sh yoki noto'g'ri host"
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if not self._VALID_HOST_RE.match(host):
                return False, f"Noto'g'ri hostname formati ({host})"

        for cdn in self.CDN_SIGNATURES:
            cdn_l = cdn.lower()
            if (host == cdn_l or host.endswith("." + cdn_l)) and not any(cdn_l in r for r in self.in_scope):
                return False, f"Uchinchi tomon CDN/Analitika domeni ({cdn_l})"

        for out_rule in self.out_of_scope:
            if self._matches_rule(host, out_rule, is_out_of_scope=True):
                return False, f"Out-of-Scope qoidasiga tushdi: {out_rule}"

        if not self.in_scope:
            return False, "In-Scope ro'yxati kiritilmagan"

        for in_rule in self.in_scope:
            if self._matches_rule(host, in_rule, is_out_of_scope=False):
                return True, f"In-Scope ({in_rule})"

        return False, f"'{host}' In-Scope ro'yxatiga mos kelmadi"
