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

    @staticmethod
    def extract_host(target: str) -> str:
        target = target.strip().lower()
        if "://" in target:
            parsed = urlparse(target)
            host = parsed.hostname or target
        else:
            host = target.split("/")[0].split(":")[0]
        return host.strip(".")

    SECOND_LEVEL_TLDS = {"co.uk", "org.uk", "ac.uk", "com.uz", "org.uz", "gov.uz", "edu.uz", "net.uz", "com.tr", "com.ru"}

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
            if last_two in cls.SECOND_LEVEL_TLDS and len(parts) >= 3:
                return ".".join(parts[-3:])
            return ".".join(parts[-2:])
        return host


    def _matches_rule(self, host: str, rule: str) -> bool:
        rule_host = self.extract_host(rule)
        if not rule_host:
            return False

        # CIDR yoki IP tekshiruvi
        try:
            if "/" in rule:
                net = ipaddress.ip_network(rule, strict=False)
                ip_obj = ipaddress.ip_address(host)
                return ip_obj in net
            else:
                ip_rule = ipaddress.ip_address(rule_host)
                ip_host = ipaddress.ip_address(host)
                return ip_rule == ip_host
        except ValueError:
            pass

        # Wildcard domen (*.example.com) yoki www.example.com -> example.com o'zak domeni
        if rule_host.startswith("*."):
            base_domain = rule_host[2:]
            return host == base_domain or host.endswith("." + base_domain)

        apex = self.extract_apex_domain(rule_host)
        return host == rule_host or host.endswith("." + rule_host) or host == apex or host.endswith("." + apex)


    def is_in_scope(self, target: str) -> tuple[bool, str]:
        host = self.extract_host(target)
        if not host:
            return False, "Bo'sh yoki noto'g'ri host"

        # Tashqi analitika va uchinchi tomon CDN domenlarini avtomatik cheklash
        for cdn in self.CDN_SIGNATURES:
            cdn_l = cdn.lower()
            if host == cdn_l or host.endswith("." + cdn_l):
                return False, f"Uchinchi tomon CDN/Analitika domeni ({cdn_l})"

        # Out-of-Scope tekshiruvi birinchi ustuvorlikda
        for out_rule in self.out_of_scope:
            if self._matches_rule(host, out_rule):
                return False, f"Out-of-Scope qoidasiga tushdi: {out_rule}"

        # Agar in_scope bo'sh bo'lsa, ruxsat berilmaydi
        if not self.in_scope:
            return False, "In-Scope ro'yxati kiritilmagan"

        for in_rule in self.in_scope:
            if self._matches_rule(host, in_rule):
                return True, f"In-Scope ({in_rule})"

        return False, f"'{host}' In-Scope ro'yxatiga mos kelmadi"
