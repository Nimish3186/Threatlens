# test_enrichment.py  — run from project root
import sys, os
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from enrichment.ioc_enricher import enrich_ip, get_threat_label

# 1.1.1.1 = Cloudflare (clean), 222.186.42.137 = known SSH scanner
test_ips = ["1.1.1.1", "222.186.42.137", "192.168.1.1"]

for ip in test_ips:
    result = enrich_ip(ip)
    if result:
        label = get_threat_label(result["abuse_score"])
        print(f"""
  IP       : {result['ip']}
  Score    : {result['abuse_score']}/100  [{label}]
  Reports  : {result['total_reports']}
  Country  : {result['country_code']}
  ISP      : {result['isp']}
  Type     : {result['usage_type']}
  Cached   : {'yes' if result.get('queried_at') else 'no'}
""")
    else:
        print(f"  {ip} → skipped (private or error)")