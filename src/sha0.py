### IMPORTS
from enum import Enum
from copy import deepcopy

### SETUP
# macros
def SHA_ch(x: int, y: int, z: int) -> int:
    return (((x) & (y)) ^ ((~(x)) & (z)))

def SHA_maj(x: int, y: int, z: int) -> int:
    return (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

def SHA_parity(x:int, y: int, z: int) -> int:
    return ((x) ^ (y) ^ (z))

# status
class Status(Enum):
    SUCCESS = 0
    NULL = 1
    INPUT_TOO_LONG = 2
    STATE_ERROR = 3
    BAD_PARAM = 4

# constants
SHA0_BLOCK_SIZE = 64
SHA0_HASH_SIZE = 20
SHA0_HASH_SIZE_BITS = SHA0_HASH_SIZE << 3
BYTE_SIZE = 256

# SHA0 context class
class SHA0_context:

    def __init__(self,
                 length_high: int=0, length_low: int=0, message_block_index: int=0, computed: int=0, corrupted: Status=Status.SUCCESS):
        self.intermediate_hash = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
        self.length_high = length_high
        self.length_low = length_low
        self.message_block_index = message_block_index
        self.message_block = bytearray(SHA0_BLOCK_SIZE)
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
def SHA0_rotl(bits: int, word: int) -> int:
    return (((word) << (bits)) | ((word) >> (32-(bits)))) % (BYTE_SIZE**4)

def SHA0_add_length(context: SHA0_context, length: int):
    add_temp = context.length_low
    context.length_low += length
    if context.length_low < add_temp:
        context.length_high += 1
        if context.length_high == 0:
            context.corrupted = Status.INPUT_TOO_LONG
    return context.corrupted

# functions
def SHA0_input(context: SHA0_context, message: bytes, length: int) -> Status:
    if not context: return Status.NULL
    if length == 0: return Status.SUCCESS
    if not message or len(message) == 0: return Status.NULL
    if context.computed:
        context.corrupted = Status.STATE_ERROR
        return context.corrupted
    if context.corrupted is not Status.SUCCESS: return context.corrupted

    i = 0
    message_array = bytearray(message)
    while length > 0:
        context.message_block[context.message_block_index] = message_array[i]
        context.message_block_index += 1

        if SHA0_add_length(context, 8) is Status.SUCCESS and context.message_block_index == SHA0_BLOCK_SIZE:
            SHA0_process_message_block(context)

        i += 1
        length -= 1

    return context.corrupted

def SHA0_final_bits(context: SHA0_context, message_bits: int, length: int) -> Status:
    masks = [0x00, 0x80, 0xC0, 0xE0, 0xF0, 0xF8, 0xFC, 0xFE]
    markbit = [0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01]
    
    if not context: return Status.NULL
    if length == 0: return Status.SUCCESS
    if context.corrupted is not Status.SUCCESS: return context.corrupted
    if context.computed:
        context.corrupted = Status.STATE_ERROR
        return context.corrupted
    if length >= 8:
        context.corrupted = Status.BAD_PARAM
        return context.corrupted

    SHA0_add_length(context, length)
    SHA0_finalize(context, (message_bits & masks[length]) | markbit[length])

    return context.corrupted

def SHA0_result(context: SHA0_context, message_digest: bytearray) -> Status:
    if not context: return Status.NULL
    if not message_digest: return Status.NULL
    if context.corrupted is not Status.SUCCESS:
        return context.corrupted
    
    context_copy = deepcopy(context)

    if not context_copy.computed:
        SHA0_finalize(context_copy, 0x80)

    for i in range(SHA0_HASH_SIZE):
        message_digest[i] = (context_copy.intermediate_hash[i>>2] >> (8 * ( 3 - ( i & 0x03 ) ))) % BYTE_SIZE

    return Status.SUCCESS

def SHA0_process_message_block(context: SHA0_context):
    K = [0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6]
    W = [0 for i in range(80)]

    for t in range(16):
        W[t] = ((context.message_block[t * 4]) << 24) % (BYTE_SIZE**4)
        W[t] |= ((context.message_block[t * 4 + 1]) << 16) % (BYTE_SIZE**4)
        W[t] |= ((context.message_block[t * 4 + 2]) << 8) % (BYTE_SIZE**4)
        W[t] |= ((context.message_block[t * 4 + 3])) % (BYTE_SIZE**4)

    for t in range(16, 80):
        W[t] = W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]

    A = context.intermediate_hash[0]
    B = context.intermediate_hash[1]
    C = context.intermediate_hash[2]
    D = context.intermediate_hash[3]
    E = context.intermediate_hash[4]

    for t in range(20):
        temp = (SHA0_rotl(5, A) + SHA_ch(B, C, D) + E + W[t] + K[0]) % (BYTE_SIZE**4)
        E = D
        D = C
        C = SHA0_rotl(30, B)
        B = A
        A = temp

    for t in range(20, 40):
        temp = (SHA0_rotl(5, A) + SHA_parity(B, C, D) + E + W[t] + K[1]) % (BYTE_SIZE**4)
        E = D
        D = C
        C = SHA0_rotl(30, B)
        B = A
        A = temp

    for t in range(40, 60):
        temp = (SHA0_rotl(5, A) + SHA_maj(B, C, D) + E + W[t] + K[2]) % (BYTE_SIZE**4)
        E = D
        D = C
        C = SHA0_rotl(30, B)
        B = A
        A = temp

    for t in range(60, 80):
        temp = (SHA0_rotl(5, A) + SHA_parity(B, C, D) + E + W[t] + K[3]) % (BYTE_SIZE**4)
        E = D
        D = C
        C = SHA0_rotl(30, B)
        B = A
        A = temp

    context.intermediate_hash[0] = (context.intermediate_hash[0] + A)
    context.intermediate_hash[1] = (context.intermediate_hash[1] + B)
    context.intermediate_hash[2] = (context.intermediate_hash[2] + C)
    context.intermediate_hash[3] = (context.intermediate_hash[3] + D)
    context.intermediate_hash[4] = (context.intermediate_hash[4] + E)
    context.intermediate_hash = [i % (BYTE_SIZE**4) for i in context.intermediate_hash]
    context.message_block_index = 0

def SHA0_finalize(context: SHA0_context, pad_byte: int):
    SHA0_pad_message(context, pad_byte)
    for i in range(SHA0_BLOCK_SIZE):
        context.message_block[i] = 0
    context.length_high = 0
    context.length_low = 0
    context.computed = 1
    
def SHA0_pad_message(context: SHA0_context, pad_byte: int):
    if context.message_block_index >= SHA0_BLOCK_SIZE - 8:

        context.message_block[context.message_block_index] = pad_byte
        context.message_block_index += 1

        while context.message_block_index < SHA0_BLOCK_SIZE:
            context.message_block[context.message_block_index] = 0
            context.message_block_index += 1

        SHA0_process_message_block(context)

    else:

        context.message_block[context.message_block_index] = pad_byte
        context.message_block_index += 1

    while context.message_block_index < SHA0_BLOCK_SIZE - 8:
        context.message_block[context.message_block_index] = 0
        context.message_block_index += 1

    context.message_block[56] = (context.length_high >> 24) % BYTE_SIZE
    context.message_block[57] = (context.length_high >> 16) % BYTE_SIZE
    context.message_block[58] = (context.length_high >> 8) % BYTE_SIZE
    context.message_block[59] = context.length_high % BYTE_SIZE
    context.message_block[60] = (context.length_low >> 24) % BYTE_SIZE
    context.message_block[61] = (context.length_low >> 16) % BYTE_SIZE
    context.message_block[62] = (context.length_low >> 8) % BYTE_SIZE
    context.message_block[63] = context.length_low % BYTE_SIZE

    SHA0_process_message_block(context)

### EXPORT
class sha0:

    digest_size = SHA0_HASH_SIZE
    block_size = SHA0_BLOCK_SIZE
    name = 'sha0'

    def __init__(self, data: bytes=b''):
        self.ctx = SHA0_context()
        if len(data) > 0:
            self.update(data)

    def digest(self) -> bytes:
        SHA0_result(self.ctx, self.dgst)
        return bytes(self.dgst)
    
    def hexdigest(self) -> bytes:
        return b''.join(map(lambda a: "{:02x}".format(a).encode(), list(self.digest())))

    def update(self, data: bytes):
        assert len(data) > 0, "Data cannot be of length 0"
        self.ctx.computed = False

        SHA0_input(self.ctx, data, len(data))
        SHA0_final_bits(self.ctx, 0, 0)
        self.dgst = bytearray(SHA0_HASH_SIZE)

    def copy(self):
        new = sha0()

        new.ctx = deepcopy(self.ctx)

        return new