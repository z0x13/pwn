from hashlib import sha256
import string

hash = 'a27019723705c0a8d30f500f954287fd0917798110d07c26a34db95720c35e64f54341909c72188b498dca71364c2a5caa46ccbe4be0b049eda8dec93cb61d24341354a1dcb2333366941553fbe3d07daf4fa9d8eb3d65708c6d2c18d62cd9f59b9362e2d80fb6b53130b0e913451a4e966121e31e2348d8eef33250774e73c025e265e3702340f3f4c3cb459c455c6ccb29d77b5882b69937fe1aa334a78c301c1a2f875583b43d9bd74ea3b89ebfe7069adef036404fb7e1198b8fecff443c9624816f855abd00e09f932c4cf3b8cc0c7e9a78654946d3a23f1b7cf46b2fe307ae616959326eed0562b61c46ec1d6f8bf4390272937fcafa178f4e05593265601be9710ae25f7fbcc7eca2e0a00a9c1beaf2a81185cc825ea75e38892d654925dc330b4b2249b8142b565df1ced881773dab2249c0cea9c8f6d7634bf0e9f3fa6408655b1700cf9aa6d23ff8957f0eaa712953a3c0d09ac71058b9ab35acdd17e117288642879110850b62f83cb13d07e7961e321c1c762ff5e5ab83029c7c9aeb7ea437db5c5d596b3f0c85564f6d6864fcc5353fdccdb7271093f2ca1a467065e70bb1a8db68c56c6f5940742d583212788743e825c4c2f4ef80ab6f125865ab4349582438e72ba51024770c0a54077ab7245dd26770336c7a8e0017781c8d9076b06873dd23f21405492e4cf803d4dc12fe9d475c0cb3e58f614860ebb13baeaad755eeb9cc2d8d3ed706919db9501f8df7ee778dbf42e5f463a6a7e371fcaae93768b1722dcefc0a06729388acfe35a4d08cbdfc996309a15fad7e62afa472fd4848d383a9d2a7b7db04b02dad623d6662b8f9564d3e8e5e7dbc9e02b58f66be440f005ae388fb224cae3feb4185dc4577cfaae780c2566bff77769a1083b22796eda8c3522a0cb9268fd30f9142b1fe1738a2e6e2c3dde787c70b4eda2bb6a22638ab7deb7cc6b6953d0e758e016c49d7b03915df31304acf997932d8863c8671eef947c3f2423a8aed2868bc051b394fbd6e54142799a48378ac9827379d327d5592ee38ac852b4207aede9bc569fdb7244e3acf0c3a533c441c8ec8128621a3908f193432ee174694a5ea455b01a0a84df44c1764edb9e6621aca210c56b6da4f748d5d8a5c9c3c4a34c925c964017b2fdf9f0fb03126f6fe3385b9ab1d3c0a3a12eddd2b13faed957d12cbb6fa616706240d424657a13fabaffc74c34b54f384d907fd9f6b93b8d1b2d7bcd6205b5e554fef4f26a4dd7375440bbc315148153fab431231d6d7e1d76635d1ff483d46e488aa5b4b78eb774131003066d96b6f4a6091cae5ee4641b289c9e4ac38314b9fc4fd8f468f00d675575f9c28f53a029fd723baa97a97b8913ac8d461bbdaec866d4ecff4a4a5911fdcf8d2873320a498c0fb58b2bb85a1fc1627ac15651abac85f4614321fc6c8117d5df3c8cab7bfa99909049b7823f947b1a2d4a79a50da5d94be0de87e5a97a640c3ee1854ada395d11549286d8d53d20e79d932a72cf98b9e44faa6eb3902b1ba99633f4aa8dc3da406a7028da027e22d288ef86d48b670641491655472ae83c2b5258ffbe21935e4cc1e0d82bb03fe7a25880d0c261085b3e22f397d4199b5470b538777dd1a58a7b29197af2ef18ec5dc0be90627ca83885f27b04465d13c05a5c9b438ef3dc64c00b40c8efaebdbdeb70b9ebd3921d96887e9a95d076c1bc84a58'

num3 = [0 for x in range(19)]
num4 = [b'0' for x in range(19)]
num5 = [b'0' for x in range(19)]

num3_hash = []
num4_hash = []
num5_hash = []
for i in range(0, len(hash), 128):
    num3_hash.append(hash[i:i + 128:])
    num4_hash.append(hash[i:i + 64:])
    num5_hash.append(hash[i + 64:i + 128:])

for i in range(0xffff):
    tmp = sha256(i.to_bytes(2, byteorder='little')).hexdigest()
    if tmp in num4_hash:
        num4[(num4_hash.index(tmp))] = i.to_bytes(2, byteorder='little')
    if tmp in num5_hash:
        num5[(num5_hash.index(tmp))] = i.to_bytes(2, byteorder='little')

for i in range(19):
    num3[i] = int.from_bytes(num4[i] + num5[i], byteorder='little')


def rol(val, r_bits):
    max_bits = 32
    return (val << r_bits % max_bits) & (2 ** max_bits - 1) | (
            (val & (2 ** max_bits - 1)) >> (max_bits - (r_bits % max_bits)))


def ror(val, r_bits):
    max_bits = 32
    return ((val & (2 ** max_bits - 1)) >> r_bits % max_bits) | (
            val << (max_bits - (r_bits % max_bits)) & (2 ** max_bits - 1))


def pongo_1EKCOBP4D0(value):
    n = 0
    for j in range(32):
        n = rol(n, 1)
        n = n | (value & 1)
        value = ror(value, 1) & ((1 << 31) - 1)
    return n


def pon_06W0JNA81N(n):
    return ror(n, 3) | rol(n, 0x1d)


def encrypt(flag, key):
    n = flag
    for j in range(5):
        n2 = rol(key, j + 1)
        n3 = ror(key, j + 1)
        print(hex(n2), hex(n3))
        n = n ^ n2
        n = n ^ n3
    return n


def reverse_pon_06W0JNA81N(n):
    return ror(n, 29)

    
def decrypt(n):
    key = 0x13371337
    for j in range(5):
        n2 = ror(key, j - 5)
        n3 = rol(key, j - 5)
        n = n ^ n3
        n = n ^ n2
        n = pongo_1EKCOBP4D0(n)
        n = reverse_pon_06W0JNA81N(n)

    return n

decrypted = b''
for i in num3:
    decrypted += decrypt(i).to_bytes(4, byteorder='little')

print(decrypted)