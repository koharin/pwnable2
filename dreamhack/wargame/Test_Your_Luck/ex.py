import requests, json
from tqdm import tqdm
import aiohttp
import asyncio

async def fetch(session,num):
    data={ "guess": num }
    #async with session.post("http://127.0.0.1:5001/guess",data=data) as response:
    async with session.post("http://host8.dreamhack.games:20217/guess",data=data) as response:
        res = await response.text()
        return res


async def main():
    async with aiohttp.ClientSession() as session:
        tasks = [fetch(session,num) for num in tqdm(range(1,10001))]
        results = await asyncio.gather(*tasks)
        return results

results = asyncio.run(main())
print(results)
file = open("result.txt", "w")
file.write(str(results))
file.close()
