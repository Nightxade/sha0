### IMPORTS
from enum import Enum
from copy import deepcopy

### SETUP
# macros
def _SHA_ch(x: int, y: int, z: int) -> int:
    return (((x) & (y)) ^ ((~(x)) & (z)))

def _SHA_maj(x: int, y: int, z: int) -> int:
    return (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

def _SHA_parity(x:int, y: int, z: int) -> int:
    return ((x) ^ (y) ^ (z))

# status
class _Status(Enum):
    SUCCESS = 0
    NULL = 1
    INPUT_TOO_LONG = 2
    STATE_ERROR = 3
    BAD_PARAM = 4

# constants
_SHA0_BLOCK_SIZE = 64
_SHA0_HASH_SIZE = 20
_BYTE_SIZE = 256

# SHA0 context class
class _SHA0_context:

    def __init__(self,
                 length_high: int=0, length_low: int=0, message_block_index: int=0, computed: int=0, corrupted: _Status=_Status.SUCCESS):
        self.intermediate_hash = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
        self.length_high = length_high
        self.length_low = length_low
        self.message_block_index = message_block_index
        self.message_block = bytearray(_SHA0_BLOCK_SIZE)
        self.computed = computed
        self.corrupted = corrupted

    def __str__(self):
        s = ""
        s += f"intermediate_hash: {str(self.intermediate_hash)}\n"
        s += f"length_high: {str(self.length_high)}\n"
        s += f"length_low: {str(self.length_low)}\n"
        s += f"message_block_index: {str(self.message_block_index)}\n"
        s += f"computed: {self.computed == 1}\n"
        s += f"corrupted: {self.corrupted}\n"
        return s

    def __repr__(self):
        return str(self)

### ALGORITHM
# macros
def _SHA0_rotl(bits: int, word: int) -> int:
    return (((word) << (bits)) | ((word) >> (32-(bits)))) % (_BYTE_SIZE**4)

def _SHA0_add_length(context: _SHA0_context, length: int):
    add_temp = context.length_low
    context.length_low += length
    if context.length_low < add_temp:
        context.length_high += 1
        if context.length_high == 0:
            context.corrupted = _Status.INPUT_TOO_LONG
    return context.corrupted

# functions
def _SHA0_input(context: _SHA0_context, message: bytes, length: int) -> _Status:
    if not context: return _Status.NULL
    if length == 0: return _Status.SUCCESS
    if not message or len(message) == 0: return _Status.NULL
    if context.computed:
        context.corrupted = _Status.STATE_ERROR
        return context.corrupted
    if context.corrupted is not _Status.SUCCESS: return context.corrupted

    i = 0
    message_array = bytearray(message)
    while length > 0:
        context.message_block[context.message_block_index] = message_array[i]
        context.message_block_index += 1

        if _SHA0_add_length(context, 8) is _Status.SUCCESS and context.message_block_index == _SHA0_BLOCK_SIZE:
            _SHA0_process_message_block(context)

        i += 1
        length -= 1

    return context.corrupted

def _SHA0_final_bits(context: _SHA0_context, message_bits: int, length: int) -> _Status:
    masks = [0x00, 0x80, 0xC0, 0xE0, 0xF0, 0xF8, 0xFC, 0xFE]
    markbit = [0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01]
    
    if not context: return _Status.NULL
    if length == 0: return _Status.SUCCESS
    if context.corrupted is not _Status.SUCCESS: return context.corrupted
    if context.computed:
        context.corrupted = _Status.STATE_ERROR
        return context.corrupted
    if length >= 8:
        context.corrupted = _Status.BAD_PARAM
        return context.corrupted

    _SHA0_add_length(context, length)
    _SHA0_finalize(context, (message_bits & masks[length]) | markbit[length])

    return context.corrupted

def _SHA0_result(context: _SHA0_context, message_digest: bytearray) -> _Status:
    if not context: return _Status.NULL
    if not message_digest: return _Status.NULL
    if context.corrupted is not _Status.SUCCESS:
        return context.corrupted
    
    context_copy = deepcopy(context)

    if not context_copy.computed:
        _SHA0_finalize(context_copy, 0x80)

    for i in range(_SHA0_HASH_SIZE):
        message_digest[i] = (context_copy.intermediate_hash[i>>2] >> (8 * ( 3 - ( i & 0x03 ) ))) % _BYTE_SIZE

    return _Status.SUCCESS

def _SHA0_process_message_block(context: _SHA0_context):
    K = [0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6]
    W = [0 for i in range(80)]

    for t in range(16):
        W[t] = ((context.message_block[t * 4]) << 24) % (_BYTE_SIZE**4)
        W[t] |= ((context.message_block[t * 4 + 1]) << 16) % (_BYTE_SIZE**4)
        W[t] |= ((context.message_block[t * 4 + 2]) << 8) % (_BYTE_SIZE**4)
        W[t] |= ((context.message_block[t * 4 + 3])) % (_BYTE_SIZE**4)

    for t in range(16, 80):
        W[t] = W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]

    A = context.intermediate_hash[0]
    B = context.intermediate_hash[1]
    C = context.intermediate_hash[2]
    D = context.intermediate_hash[3]
    E = context.intermediate_hash[4]

    for t in range(20):
        temp = (_SHA0_rotl(5, A) + _SHA_ch(B, C, D) + E + W[t] + K[0]) % (_BYTE_SIZE**4)
        E = D
        D = C
        C = _SHA0_rotl(30, B)
        B = A
        A = temp

    for t in range(20, 40):
        temp = (_SHA0_rotl(5, A) + _SHA_parity(B, C, D) + E + W[t] + K[1]) % (_BYTE_SIZE**4)
        E = D
        D = C
        C = _SHA0_rotl(30, B)
        B = A
        A = temp

    for t in range(40, 60):
        temp = (_SHA0_rotl(5, A) + _SHA_maj(B, C, D) + E + W[t] + K[2]) % (_BYTE_SIZE**4)
        E = D
        D = C
        C = _SHA0_rotl(30, B)
        B = A
        A = temp

    for t in range(60, 80):
        temp = (_SHA0_rotl(5, A) + _SHA_parity(B, C, D) + E + W[t] + K[3]) % (_BYTE_SIZE**4)
        E = D
        D = C
        C = _SHA0_rotl(30, B)
        B = A
        A = temp

    context.intermediate_hash[0] = (context.intermediate_hash[0] + A)
    context.intermediate_hash[1] = (context.intermediate_hash[1] + B)
    context.intermediate_hash[2] = (context.intermediate_hash[2] + C)
    context.intermediate_hash[3] = (context.intermediate_hash[3] + D)
    context.intermediate_hash[4] = (context.intermediate_hash[4] + E)
    context.intermediate_hash = [i % (_BYTE_SIZE**4) for i in context.intermediate_hash]
    context.message_block_index = 0

def _SHA0_finalize(context: _SHA0_context, pad_byte: int):
    _SHA0_pad_message(context, pad_byte)
    for i in range(_SHA0_BLOCK_SIZE):
        context.message_block[i] = 0
    context.length_high = 0
    context.length_low = 0
    context.computed = 1
    
def _SHA0_pad_message(context: _SHA0_context, pad_byte: int):
    if context.message_block_index >= _SHA0_BLOCK_SIZE - 8:

        context.message_block[context.message_block_index] = pad_byte
        context.message_block_index += 1

        while context.message_block_index < _SHA0_BLOCK_SIZE:
            context.message_block[context.message_block_index] = 0
            context.message_block_index += 1

        _SHA0_process_message_block(context)

    else:

        context.message_block[context.message_block_index] = pad_byte
        context.message_block_index += 1

    while context.message_block_index < _SHA0_BLOCK_SIZE - 8:
        context.message_block[context.message_block_index] = 0
        context.message_block_index += 1

    context.message_block[56] = (context.length_high >> 24) % _BYTE_SIZE
    context.message_block[57] = (context.length_high >> 16) % _BYTE_SIZE
    context.message_block[58] = (context.length_high >> 8) % _BYTE_SIZE
    context.message_block[59] = context.length_high % _BYTE_SIZE
    context.message_block[60] = (context.length_low >> 24) % _BYTE_SIZE
    context.message_block[61] = (context.length_low >> 16) % _BYTE_SIZE
    context.message_block[62] = (context.length_low >> 8) % _BYTE_SIZE
    context.message_block[63] = context.length_low % _BYTE_SIZE

    _SHA0_process_message_block(context)

### EXPORT
class sha0:

    digest_size = _SHA0_HASH_SIZE
    block_size = _SHA0_BLOCK_SIZE
    name = 'sha0'

    def __init__(self, data: bytes=b''):
        self.ctx = _SHA0_context()
        if len(data) > 0:
            self.update(data)

    def digest(self) -> bytes:
        _SHA0_result(self.ctx, self.dgst)
        return bytes(self.dgst)
    
    def hexdigest(self) -> bytes:
        return b''.join(map(lambda a: "{:02x}".format(a).encode(), list(self.digest())))

    def update(self, data: bytes):
        assert len(data) > 0, "Data cannot be of length 0"
        self.ctx.computed = False

        _SHA0_input(self.ctx, data, len(data))
        _SHA0_final_bits(self.ctx, 0, 0)
        self.dgst = bytearray(_SHA0_HASH_SIZE)

    def copy(self):
        new = sha0()

        new.ctx = deepcopy(self.ctx)

        return new