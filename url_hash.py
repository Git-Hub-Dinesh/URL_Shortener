import hashlib
import base64

def urlshort(long_url):
    hash_object = hashlib.sha256(long_url.encode())
    shorthash = base64.urlsafe_b64encode(hash_object.digest())[:6].decode()
    print(shorthash)
    
    
urlshort("https://www.youtube.com/watch?v=pdlgI7X4rsk")