import sys
import requests

TOKEN = "7DEYkF85Fj1pFLts"

if len(sys.argv) < 2:
    print(f"İstifadə: python3 {sys.argv[0]} <TikTok_URL>")
    sys.exit(1)

url = sys.argv[1]

api = "https://ensembledata.com/apis/tt/post/info"

try:
    res = requests.get(
        api,
        params={
            "url": url,
            "token": TOKEN
        },
        timeout=30
    )
    res.raise_for_status()
    data = res.json()
except Exception as e:
    print("API xətası:", e)
    sys.exit(1)

# data həm obyekt, həm də massiv ola bilər
post = data.get("data")
if isinstance(post, list):
    if not post:
        print("❌ Post tapılmadı.")
        sys.exit(1)
    post = post[0]

poi = post.get("poi_data")

if not poi:
    print("❌ Bu postda location (POI) yoxdur.")
    sys.exit(0)

addr = poi.get("address_info", {})

address = addr.get("address", "Yoxdur")
city = addr.get("city_name", "")
lat = addr.get("lat")
lng = addr.get("lng")
poi_name = poi.get("poi_name", "Yoxdur")

print("====== LOCATION ======")
print(f"POI adı      : {poi_name}")
print(f"Ölkə/Ünvan   : {address}")

if city:
    print(f"Şəhər        : {city}")

print(f"Koordinatlar : {lat}, {lng}")

if lat and lng:
    print(f"Google Maps  : https://www.google.com/maps?q={lat},{lng}")
else:
    print("Google Maps  : Yoxdur")
