import ipaddress
import re
from urllib.parse import urlparse


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

    def __init__(self, in_scope_raw: str = "", out_of_scope_raw: str = ""):
        self.in_scope = self._parse_rules(in_scope_raw)
        self.out_of_scope = self._parse_rules(out_of_scope_raw)

    @staticmethod
    def _parse_rules(raw_text: str) -> list[str]:
        if not raw_text:
            return []
        items = []
        for line in re.split(r"[,;\n\r]+", raw_text):
            cleaned = line.strip().lower()
            if cleaned and not cleaned.startswith("#"):
                items.append(cleaned)
        return items

    _VALID_HOST_RE = re.compile(
        r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9\-_]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9\-]{2,59})$"
    )

    @staticmethod
    def extract_host(target: str) -> str:
        target = (target or "").strip().lower()
        if not target:
            return ""
        if target.startswith("//"):
            target = "http:" + target
        if "://" not in target and "@" in target:
            return ""
        if "://" in target:
            parsed = urlparse(target)
            host = parsed.hostname or ""
        else:
            path_stripped = target.split("/")[0].split("?")[0].split("#")[0]
            if path_stripped.startswith("[") and "]" in path_stripped:
                host = path_stripped[1 : path_stripped.index("]")]
            elif path_stripped.count(":") >= 2:
                host = path_stripped
            else:
                host = path_stripped.split(":")[0]
        if "%" in host:
            host = host.split("%", 1)[0]
        if host.startswith("*."):
            host = host[2:]
        host = host.strip(".")
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
    def extract_apex_domain(cls, target: str) -> str:
        host = cls.extract_host(target)
        try:
            ipaddress.ip_address(host)
            return host
        except ValueError:
            pass
        parts = host.split(".")
        if len(parts) >= 3:
            last_two = f"{parts[-2]}.{parts[-1]}"
            if last_two in cls.SECOND_LEVEL_TLDS:
                return ".".join(parts[-3:])
            return ".".join(parts[-2:])
        return host

    def _matches_rule(self, host: str, rule: str, allow_apex_expansion: bool = True) -> bool:
        raw_rule = (rule or "").strip().lower()
        is_wildcard = raw_rule.startswith("*.") or "://*." in raw_rule or raw_rule.startswith("//*.")
        rule_host = self.extract_host(raw_rule)
        if not rule_host or rule_host in self.SECOND_LEVEL_TLDS:
            return False

        # CIDR yoki IP (IPv4 / IPv6) tekshiruvi
        try:
            if "/" in raw_rule and "://" not in raw_rule:
                net = ipaddress.ip_network(raw_rule, strict=False)
                ip_obj = ipaddress.ip_address(host)
                return ip_obj in net
            ip_rule = ipaddress.ip_address(rule_host)
            ip_host = ipaddress.ip_address(host)
            return ip_rule == ip_host
        except ValueError:
            pass

        if is_wildcard or not allow_apex_expansion:
            return host == rule_host or host.endswith("." + rule_host)

        apex = self.extract_apex_domain(rule_host)
        if apex in self.SECOND_LEVEL_TLDS:
            return host == rule_host or host.endswith("." + rule_host)
        return host == rule_host or host.endswith("." + rule_host) or host == apex or host.endswith("." + apex)


    def is_in_scope(self, target: str) -> tuple[bool, str]:
        host = self.extract_host(target)
        if not host:
            return False, "Bo'sh yoki noto'g'ri host"
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if not self._VALID_HOST_RE.match(host):
                return False, f"Noto'g'ri hostname formati ({host})"

        # Tashqi analitika va uchinchi tomon CDN domenlarini avtomatik cheklash
        # (Faqat foydalanuvchi o'zi In-Scope ga shu domenni kiritmagan bo'lsagina bloklanadi!)
        for cdn in self.CDN_SIGNATURES:
            cdn_l = cdn.lower()
            if (host == cdn_l or host.endswith("." + cdn_l)) and not any(cdn_l in r for r in self.in_scope):
                return False, f"Uchinchi tomon CDN/Analitika domeni ({cdn_l})"

        # Out-of-Scope tekshiruvi birinchi ustuvorlikda (faqat aniq host/sub-tree bloklanadi, apex emas!)
        for out_rule in self.out_of_scope:
            if self._matches_rule(host, out_rule, allow_apex_expansion=False):
                return False, f"Out-of-Scope qoidasiga tushdi: {out_rule}"

        # Agar in_scope bo'sh bo'lsa, ruxsat berilmaydi
        if not self.in_scope:
            return False, "In-Scope ro'yxati kiritilmagan"

        for in_rule in self.in_scope:
            if self._matches_rule(host, in_rule, allow_apex_expansion=True):
                return True, f"In-Scope ({in_rule})"

        return False, f"'{host}' In-Scope ro'yxatiga mos kelmadi"
