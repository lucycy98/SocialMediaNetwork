
import json
import urllib.request

'''
sends a POST/GET request to the URL endpoint specified.
returns the JSON response
''' 
def postJson(payload, headers, url):

    if payload is not None:
        payload = json.dumps(payload).encode('utf-8')
    
    req = urllib.request.Request(url, data=payload, headers=headers)

    response = urllib.request.urlopen(req, timeout=2)
    data = response.read() # read the received bytes
    encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
    response.close()

    JSON_object = json.loads(data.decode(encoding))
    return JSON_object