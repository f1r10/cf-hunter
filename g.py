
import requests

TOKEN = "7DEYkF85Fj1pFLts"

url = input("TikTok linkini daxil et: ").strip()

api = "https://ensembledata.com/apis/tt/post/info"

res = requests.get(api, params={
    "url": url,
    "token": TOKEN
})

res.raise_for_status()
data = res.json()

# data həm obyekt, həm də massiv ola bilər
post = data.get("data")
if isinstance(post, list):
    if not post:
        print("❌ Post tapılmadı.")
        exit()
    post = post[0]

poi = post.get("poi_data")

if not poi:
    print("❌ Bu postda location (POI) yoxdur.")
    exit()

addr = poi.get("address_info", {})

address = addr.get("address", "Yoxdur")
city = addr.get("city_name", "")
lat = addr.get("lat")
lng = addr.get("lng")
poi_name = poi.get("poi_name", "Yoxdur")

print("\n====== LOCATION ======")
print(f"POI adı      : {poi_name}")
print(f"Ölkə/Ünvan   : {address}")

if city:
    print(f"Şəhər        : {city}")

print(f"Koordinatlar : {lat}, {lng}")

if lat and lng:
    print(f"Google Maps  : https://www.google.com/maps?q={lat},{lng}")
else:
    print("Google Maps  : Yoxdur")
