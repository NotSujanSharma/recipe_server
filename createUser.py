import requests

url = "http://127.0.0.1:9292/users/"
data = {
    "email": "order@bigcitycatering.ca",
    "username": "bigcity",
    "password": "bigcityops"
}

response = requests.post(url, json=data)

if response.status_code == 200:
    print("User created:", response.json())
else:
    print("Error:", response.json())
