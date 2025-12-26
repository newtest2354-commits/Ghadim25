import os
import re
import json
import base64
import socket
import geoip2.database
from datetime import datetime
import concurrent.futures
from threading import Lock

class CountryCategorizer:
    def __init__(self, db_path="GeoLite2-Country.mmdb", skipped_countries=None):
        self.db_path = db_path
        self.geoip_reader = None
        self.geoip_lock = Lock()
        self.dns_lock = Lock()
        self.dns_cache = {}
        self.skipped_countries = skipped_countries or ['CN', 'TW']
        self.init_geoip()
        self.protocol_patterns = {
            'vmess': r'vmess://',
            'vless': r'vless://',
            'trojan': r'trojan://',
            'ss': r'ss://',
            'hysteria2': r'hysteria2://|hy2://',
            'hysteria': r'hysteria://',
            'tuic': r'tuic://',
            'wireguard': r'wireguard://'
        }
        
        self.country_flags = self._init_country_flags()

    def _init_country_flags(self):
        flags = {}
        for code in range(ord('A'), ord('Z') + 1):
            for code2 in range(ord('A'), ord('Z') + 1):
                country_code = chr(code) + chr(code2)
                flags[country_code] = self._get_flag_emoji(country_code)
        
        flags["UNKNOWN"] = "🏴"
        flags["SKIPPED"] = "🚫"
        flags["INVALID"] = "❌"
        flags["NO_HOST"] = "🔍"
        flags["UNKNOWN_PROTOCOL"] = "❓"
        flags["DNS_FAIL"] = "🌐"
        flags["NO_GEOIP_DB"] = "📂"
        flags["ERROR"] = "⚠️"
        
        return flags

    def _get_flag_emoji(self, country_code):
        if len(country_code) != 2:
            return "🏴"
        
        offset = 127397
        try:
            return chr(ord(country_code[0]) + offset) + chr(ord(country_code[1]) + offset)
        except:
            return "🏴"

    def init_geoip(self):
        if os.path.exists(self.db_path):
            try:
                self.geoip_reader = geoip2.database.Reader(self.db_path)
            except:
                self.geoip_reader = None
        else:
            self.geoip_reader = None

    def extract_host_from_config(self, config_str):
        if config_str.startswith('vmess://'):
            try:
                b = config_str[8:]
                if len(b) % 4 != 0:
                    b += '=' * (4 - len(b) % 4)
                d = json.loads(base64.b64decode(b).decode())
                return d.get('add') or d.get('host') or d.get('sni')
            except:
                return "INVALID"
        for proto in ['vless://', 'trojan://', 'hysteria2://', 'hy2://', 'hysteria://', 'tuic://']:
            if config_str.startswith(proto):
                m = re.search(r'@([^:/#]+)', config_str)
                return m.group(1) if m else "NO_HOST"
        if config_str.startswith('ss://'):
            p = config_str.split('#', 1)[0][5:]
            if '@' in p:
                try:
                    return p.split('@', 1)[1].split(':', 1)[0]
                except:
                    pass
            try:
                if len(p) % 4 != 0:
                    p += '=' * (4 - len(p) % 4)
                d = base64.b64decode(p).decode()
                if '@' in d:
                    return d.split('@', 1)[1].split(':', 1)[0]
            except:
                return "INVALID"
            return "NO_HOST"
        if config_str.startswith('wireguard://'):
            m = re.search(r'Peer=([^&]+)', config_str)
            if m and ':' in m.group(1):
                return m.group(1).split(':', 1)[0]
            return "NO_HOST"
        return "UNKNOWN_PROTOCOL"

    def get_country_code(self, host):
        if not host or host in ["INVALID", "NO_HOST", "UNKNOWN_PROTOCOL", "DNS_FAIL"]:
            return host or "UNKNOWN"
        if not self.geoip_reader:
            return "NO_GEOIP_DB"
        try:
            h = host.strip()
            if not re.match(r'^\d+\.\d+\.\d+\.\d+$', h):
                with self.dns_lock:
                    if h in self.dns_cache:
                        ip = self.dns_cache[h]
                    else:
                        ip = socket.gethostbyname(h)
                        self.dns_cache[h] = ip
            else:
                ip = h
            with self.geoip_lock:
                cc = self.geoip_reader.country(ip).country.iso_code
            if cc in self.skipped_countries:
                return "SKIPPED"
            return cc or "UNKNOWN"
        except:
            return "UNKNOWN"

    def read_all_combined_configs(self):
        out = []
        d = "configs/combined"
        if os.path.exists(d):
            for f in os.listdir(d):
                if f.endswith('.txt'):
                    with open(os.path.join(d, f), encoding='utf-8') as fh:
                        out += [l.strip() for l in fh if l.strip() and not l.startswith('#')]
        if not out and os.path.exists(f"{d}/all.txt"):
            with open(f"{d}/all.txt", encoding='utf-8') as fh:
                out += [l.strip() for l in fh if l.strip() and not l.startswith('#')]
        return out

    def process_with_threads(self, configs, max_workers=10):
        m = {}
        futures = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
            for config in configs:
                future = ex.submit(self._process_single_config, config)
                futures.append(future)
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    k, v = future.result()
                    m.setdefault(k, []).append(v)
                except Exception as e:
                    m.setdefault("ERROR", []).append(str(e))
        return m
    
    def _process_single_config(self, config):
        h = self.extract_host_from_config(config)
        return (self.get_country_code(h) if h else "UNKNOWN", config)

    def get_protocol(self, c):
        for p, r in self.protocol_patterns.items():
            if re.search(r, c, re.I):
                return p
        return "other"

    def save_country_results(self, country_map):
        t = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        os.makedirs('configs/country', exist_ok=True)
        total = sum(len(v) for v in country_map.values())
        summary = {}
        for cc, cfgs in country_map.items():
            if cc == "SKIPPED" or not cfgs:
                continue
            pm = {}
            for c in cfgs:
                pm.setdefault(self.get_protocol(c), []).append(c)
            summary[cc] = {'total': len(cfgs), 'protocols': {p: len(v) for p, v in pm.items()}}
            
            flag = self.country_flags.get(cc, "🏴")
            
            for p, v in pm.items():
                with open(f"configs/country/{cc}_{p}.txt", 'w', encoding='utf-8') as f:
                    f.write(f"# {flag} {cc} - {p.upper()}\n# Updated: {t}\n# Count: {len(v)}\n\n" + "\n".join(v))
            
            with open(f"configs/country/{cc}_all.txt", 'w', encoding='utf-8') as f:
                f.write(f"# {flag} {cc} - All Configurations\n# Updated: {t}\n# Total: {len(cfgs)}\n\n")
                for p, v in pm.items():
                    f.write(f"\n# {p.upper()} ({len(v)})\n" + "\n".join(v) + "\n")
        
        s = f"# Summary\n# Updated: {t}\n# Total: {total}\n# GeoIP: {'OK' if self.geoip_reader else 'NO'}\n# Skipped: {', '.join(self.skipped_countries)}\n\n"
        s += "COUNTRIES:\n"
        
        for cc, d in sorted(summary.items(), key=lambda x: x[1]['total'], reverse=True):
            if cc not in ["INVALID","NO_HOST","UNKNOWN_PROTOCOL","DNS_FAIL","NO_GEOIP_DB","UNKNOWN"]:
                flag = self.country_flags.get(cc, "🏴")
                s += f"  {flag} {cc}: {d['total']} configs\n"
                for p, c in d['protocols'].items():
                    s += f"    {p}: {c}\n"
        
        error_categories = ["INVALID","NO_HOST","UNKNOWN_PROTOCOL","DNS_FAIL","NO_GEOIP_DB","UNKNOWN","ERROR"]
        for cat in error_categories:
            if cat in country_map:
                flag = self.country_flags.get(cat, "🏴")
                s += f"\n{flag} {cat}: {len(country_map[cat])}\n"
        
        if "SKIPPED" in country_map:
            flag = self.country_flags.get("SKIPPED", "🚫")
            s += f"\n{flag} SKIPPED: {len(country_map['SKIPPED'])} configs (China/Taiwan)\n"
        
        with open("configs/country/summary.txt", 'w', encoding='utf-8') as f:
            f.write(s)
        
        return len(country_map), total

    def process(self):
        print("=" * 60)
        print("COUNTRY CATEGORIZER")
        print("=" * 60)
        cfgs = self.read_all_combined_configs()
        if not cfgs:
            print("NO CONFIGS")
            return
        print(f"Processing {len(cfgs)} configurations...")
        m = self.process_with_threads(cfgs)
        c, t = self.save_country_results(m)
        print(f"\n✅ DONE | {t} configs | {c} categories")
        error_stats = []
        for cat in ["INVALID","NO_HOST","UNKNOWN_PROTOCOL","DNS_FAIL","SKIPPED","ERROR"]:
            if cat in m:
                flag = self.country_flags.get(cat, "🏴")
                error_stats.append(f"{flag} {cat}: {len(m[cat])}")
        if error_stats:
            print(f"📊 Errors: {', '.join(error_stats)}")
        print(f"\n📁 Files saved in configs/country/")
        print("=" * 60)

def main():
    CountryCategorizer().process()

if __name__ == "__main__":
    main()
    
