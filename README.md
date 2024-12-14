# sha0

This is a purely Python implementation of the broken SHA-0 hash algorithm. The usage is exactly the same as the hashes provided in the Python builtin `hashlib` library.  

# Credit
This repository is based off of the C implementation of SHA-0 in [this repo](https://github.com/johndoe31415/sha0/blob/master/README.md) by [@johndoe31415](https://github.com/johndoe31415).  

# Usage
```py
# SHA-0 of b"Nobody inspects the spammish repetition"
>>> import sha0
>>> m = sha0.sha0(b"Nobody inspects")
>>> m.update(b" the spammish repetition")
>>> m.digest()
b'\xe2\xb0\xa8`\x9bG\xc5\x8e]\x98L\x9c\xcf\xe6\x9f\x9beK\x03+'
>>> m.hexdigest()
b'e2b0a8609b47c58e5d984c9ccfe69f9b654b032b'

# More condensed
>>> import sha0
>>> m = sha0.sha0(b"Nobody inspects the spammish repetition")
>>> m.hexdigest()
b'e2b0a8609b47c58e5d984c9ccfe69f9b654b032b'
```

# License
MIT License  