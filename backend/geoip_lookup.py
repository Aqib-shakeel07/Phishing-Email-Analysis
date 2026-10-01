import requests
from database import cache_get, cache_set
from logger import logger


GEO_API = "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,lat,lon,isp,org,as,query"
REQUEST_TIMEOUT = 8


def lookup_ip(ip: str) -> dict:
    """Resolve an IP to geo info. Cached for 30 days."""
    if not ip:
        return {"ip": ip, "error": "empty", "skip": True}

    # Skip private / reserved ranges
    if (ip.startswith("10.") or ip.startswith("192.168.") or
        ip.startswith("127.") or ip.startswith("169.254.") or
        ip.startswith("172.16.") or ip.startswith("172.17.") or
        ip.startswith("172.18.") or ip.startswith("172.19.") or
        ip.startswith("172.2") or ip.startswith("172.30.") or
        ip.startswith("172.31.")):
        return {"ip": ip, "error": "private", "skip": True}

    cached = cache_get(f"geo:{ip}")
    if cached:
        return cached

    try:
        r = requests.get(GEO_API.format(ip=ip), timeout=REQUEST_TIMEOUT)
        if r.status_code != 200:
            return {"ip": ip, "error": f"http {r.status_code}"}
        data = r.json()
        if data.get("status") != "success":
            result = {"ip": ip, "error": data.get("message", "lookup failed")}
            cache_set(f"geo:{ip}", result)
            return result

        result = {
            "ip": ip,
            "country": data.get("country"),
            "country_code": data.get("countryCode"),
            "region": data.get("regionName"),
            "city": data.get("city"),
            "lat": data.get("lat"),
            "lon": data.get("lon"),
            "isp": data.get("isp"),
            "org": data.get("org"),
            "asn": data.get("as"),
            "error": None,
        }
        cache_set(f"geo:{ip}", result)
        return result
    except Exception as e:
        logger.warning(f"GeoIP lookup failed for {ip}: {e}")
        return {"ip": ip, "error": str(e)}