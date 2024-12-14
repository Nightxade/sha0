from sha0 import sha0
from secrets import token_bytes
import subprocess

for i in range(100):
    m1 = token_bytes(96)
    m2 = token_bytes(96)

    python_hash = sha0(m1)
    python_hash.digest()
    python_hash.hexdigest()
    python_hash.update(m2)

    h1 = python_hash.digest()
    h2 = sha0(m1 + m2).digest()
    assert h1 == h2

    h1 = python_hash.hexdigest()
    h2 = sha0(m1 + m2).hexdigest()
    assert h1 == h2

    f = open('test/test_data', 'wb')
    f.write(m1 + m2)
    f.close()
    
    c_hash = subprocess.Popen(["./test/sha0", "test/test_data"], stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[1].strip()
    assert h1 == c_hash