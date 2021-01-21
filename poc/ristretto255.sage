#!/usr/bin/sage
# vim: syntax=python

import binascii # for converting test vectors
import struct   # for I2OSP and OS2IP

p = 2^255 - 19
F = GF(p)

# little-endian version of I2OSP
def I2OSP_le(val, length):
    val = int(val)
    if val < 0 or val >= (1 << (8 * length)):
        raise ValueError("bad I2OSP call: val=%d length=%d" % (val, length))
    ret = [0] * length
    val_ = val
    for idx in range(0, length):
        ret[idx] = val_ & 0xff
        val_ = val_ >> 8
    ret = struct.pack("=" + "B" * length, *ret)
    assert OS2IP_le(ret, True) == val
    return ret

# little-endian version of OS2IP
def OS2IP_le(octets, skip_assert=False):
    ret = 0
    for octet in reversed(struct.unpack("=" + "B" * len(octets), octets)):
        ret = ret << 8
        ret += octet
    if not skip_assert:
        assert octets == I2OSP_le(ret, len(octets))
    return ret

# check that a point is on the curve
def _check_point(x, y, z, t):
    assert t * z == x * y
    xx = x / z
    yy = y / z
    tt = t / z
    assert tt == xx * yy
    assert 1 + D * xx^2 * yy^2 == yy^2 - xx^2

# Montgomery curve25519 to cross-check point arithmetic
sqrt_M486664 = F(6853475219497561581579357271197624642482790079785650197046958215289687604742)
assert sqrt_M486664^2 == F(-486664)
assert ZZ(sqrt_M486664) % 2 == 0
Ell = EllipticCurve(F, [0, 486662, 0, 1, 0])
assert is_prime(Ell.order() // 8)

# from RFC7748
def _to_monty(x, y, z, t):
    _check_point(x, y, z, t)
    (x, y, z) = (F(x), F(y), F(z))
    x = x / z
    y = y / z
    if (x, y) == (F(0), F(-1)):
        return Ell(0, 0)
    if x == F(0) or y == F(1):
        return Ell(0, 1, 0)
    u = (1 + y) / (1 - y)
    v = sqrt_M486664 * u / x
    return Ell(u, v)

# addition law for edwards25519
def _edw_add(p1, p2):
    (x1, y1, z1, t1) = [ F(e) for e in p1 ]
    (x2, y2, z2, t2) = [ F(e) for e in p2 ]

    a = (x1 * y2 + y1 * x2)
    b = (z1 * z2 - D * t1 * t2)
    c = (y1 * y2 + x1 * x2)
    d = (z1 * z2 + D * t1 * t2)

    x3 = a * b
    y3 = c * d
    z3 = b * d
    t3 = a * c

    _check_point(x3, y3, z3, t3)
    assert _to_monty(x3, y3, z3, t3) == _to_monty(*p1) + _to_monty(*p2)
    return (x3, y3, z3, t3)

# scalar multiplication
def _edw_mul(k, P):
    Q = (F(0), F(1), F(1), F(0))
    for b in format(k, 'b'):
        Q = _edw_add(Q, Q)
        if b == '1':
            Q = _edw_add(Q, P)
    assert _to_monty(*Q) == k * _to_monty(*P)
    return Q

def random_scalar():
    import os
    l = 2^252 + 27742317777372353535851937790883648493
    b = int.from_bytes(os.urandom(64), 'little')
    return b % l

def keygen():
    k = random_scalar()
    gen_bytes = binascii.unhexlify('e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76')
    gen = DECODE(gen_bytes)
    return (k, _edw_mul(k, gen))


# constants and functions defined in Section 4.1

D = 37095705934669439343138083508754565189542113879843219016388785533085940283555
D = F(D)

SQRT_M1 = 19681161376707505956807079304988542015446066515923890162744021073123829784752
SQRT_M1 = F(SQRT_M1)
assert SQRT_M1^2 == F(-1)

SQRT_AD_MINUS_ONE = 25063068953384623474111414158702152701244531502492656460079210482610430750235
SQRT_AD_MINUS_ONE = F(SQRT_AD_MINUS_ONE)

INVSQRT_A_MINUS_D = 54469307008909316920995813868745141605393597292927456921205312896311721017578
INVSQRT_A_MINUS_D = F(INVSQRT_A_MINUS_D)

ONE_MINUS_D_SQ = 1159843021668779879193775521855586647937357759715417654439879720876111806838
ONE_MINUS_D_SQ = F(ONE_MINUS_D_SQ)

D_MINUS_ONE_SQ = 40440834346308536858101042469323190826248399146238708352240133220865137265952
D_MINUS_ONE_SQ = F(D_MINUS_ONE_SQ)

def IS_NEGATIVE(u):
    return ZZ(u) % 2 == 1

def CT_EQ(u, v):
    return u == v

def CT_SELECT(cond, v, u):
    return v if cond else u

def CT_ABS(u):
    return -u if IS_NEGATIVE(u) else u

def POSITIVE_SQRT(u):
    return CT_ABS(F(u).sqrt())

def SQRT_RATIO_M1(u, v):
    u = F(u)
    v = F(v)

    v3 = v^2  * v
    v7 = v3^2 * v
    r = (u * v3) * (u * v7)^((p-5)/8)
    check = v * r^2

    correct_sign_sqrt   = CT_EQ(check,          u)
    flipped_sign_sqrt   = CT_EQ(check,         -u)
    flipped_sign_sqrt_i = CT_EQ(check, -u*SQRT_M1)

    r_prime = SQRT_M1 * r
    #r = CT_SELECT(r_prime IF flipped_sign_sqrt | flipped_sign_sqrt_i ELSE r)
    r = CT_SELECT(flipped_sign_sqrt | flipped_sign_sqrt_i, r_prime, r)

    #// Choose the nonnegative square root.
    r = CT_ABS(r)

    was_square = correct_sign_sqrt | flipped_sign_sqrt

    return (was_square, r)

def test_SQRT_RATIO_M1():
    u = F.random_element()
    v = F.random_element()
    ratio = u / v

    (w, s) = SQRT_RATIO_M1(u, v)
    if ratio.is_square():
        assert w
        assert s^2 == ratio
        assert s == CT_ABS(sqrt(ratio))
    else:
        assert not w
        assert s^2 == ratio * SQRT_M1
        assert s == CT_ABS(sqrt(ratio * SQRT_M1))

    assert (True, 0) == SQRT_RATIO_M1(0, v)
    assert (False, 0) == SQRT_RATIO_M1(u, 0)

def DECODE(instr):
    # precondition: length of string is 32 bytes
    if len(instr) != 32:
        raise ValueError("DECODE: input must be 32-byte string")

    # step 1
    s = OS2IP_le(instr)
    if s >= p:
        raise ValueError("DECODE: input must be reduced mod p")

    # Sage impl detail: treat s as a field element
    s = F(s)

    # step 2
    if IS_NEGATIVE(s):
        raise ValueError("DECODE: input must be non-negative")

    # step 3
    ss = s^2
    u1 = 1 - ss
    u2 = 1 + ss
    u2_sqr = u2^2

    v = -(D * u1^2) - u2_sqr

    (was_square, invsqrt) = SQRT_RATIO_M1(1, v * u2_sqr)

    den_x = invsqrt * u2
    den_y = invsqrt * den_x * v

    x = CT_ABS(2 * s * den_x)
    y = u1 * den_y
    t = x * y

    # step 4
    if not was_square:
        raise ValueError("DECODE: v * u2_sqr was nonsquare")
    if IS_NEGATIVE(t):
        raise ValueError("DECODE: t was negative")
    if y == 0:
        raise ValueError("DECODE: y was 0")

    return (x, y, 1, t)

def ENCODE(x0, y0, z0, t0):
    # step 1
    u1 = (z0 + y0) * (z0 - y0)
    u2 = x0 * y0

    #// Ignore was_square since this is always square
    (_, invsqrt) = SQRT_RATIO_M1(1, u1 * u2^2)

    den1 = invsqrt * u1
    den2 = invsqrt * u2
    z_inv = den1 * den2 * t0

    ix0 = x0 * SQRT_M1
    iy0 = y0 * SQRT_M1
    enchanted_denominator = den1 * INVSQRT_A_MINUS_D

    rotate = IS_NEGATIVE(t0 * z_inv)

    #x = CT_SELECT(iy0 IF rotate ELSE x0)
    x = CT_SELECT(rotate, iy0, x0)
    #y = CT_SELECT(ix0 IF rotate ELSE y0)
    y = CT_SELECT(rotate, ix0, y0)
    z = z0
    #den_inv = CT_SELECT(enchanted_denominator IF rotate ELSE den2)
    den_inv = CT_SELECT(rotate, enchanted_denominator, den2)

    #y = CT_SELECT(-y IF IS_NEGATIVE(x * z_inv) ELSE y)
    y = CT_SELECT(IS_NEGATIVE(x * z_inv), -y, y)

    s = CT_ABS(den_inv * (z - y))

    # step 2
    return I2OSP_le(s, 32)

def EQUALS(p1, p2):
    _check_point(*p1)
    _check_point(*p2)
    (x1, y1, _, _) = p1
    (x2, y2, _, _) = p2

    #return (x1 * y2 == y1 * x2 | y1 * y2 == x1 * x2)
    return (x1 * y2 == y1 * x2) or (y1 * y2 == x1 * x2)

def MAP(t):
    r = SQRT_M1 * t^2
    u = (r + 1) * ONE_MINUS_D_SQ
    v = (-1 - r*D) * (r + D)

    (was_square, s) = SQRT_RATIO_M1(u, v)
    s_prime = -CT_ABS(s*t)
    #s = CT_SELECT(s IF was_square ELSE s_prime)
    s = CT_SELECT(was_square, s, s_prime)
    #c = CT_SELECT(-1 IF was_square ELSE r)
    c = CT_SELECT(was_square, -1, r)

    N = c * (r - 1) * D_MINUS_ONE_SQ - v

    w0 = 2 * s * v
    w1 = N * SQRT_AD_MINUS_ONE
    w2 = 1 - s^2
    w3 = 1 + s^2

    return (w0*w3, w2*w1, w1*w3, w0*w2)

def FromUniformBytes(b):
    assert len(b) == 64
    b0 = F(OS2IP_le(b[:32]) & ((1 << 255) - 1))
    b1 = F(OS2IP_le(b[32:]) & ((1 << 255) - 1))
    p0 = MAP(b0)
    p1 = MAP(b1)
    ret = _edw_add(p0, p1)
    return ENCODE(*ret)

def test_MAP():
    t = F.random_element()
    _check_point(*MAP(t))

def test_ENCODE_DECODE():
    t = F.random_element()
    (x, y, z, t) = MAP(t)
    _check_point(x, y, z, t)

    # randomize projective repr
    zz = F.random_element()
    x *= zz
    y *= zz
    t *= zz
    z *= zz
    _check_point(x, y, z, t)

    enc = ENCODE(x, y, z, t)
    (xx, yy, zz, tt) = DECODE(enc)

    assert EQUALS((x, y, z, t), (xx, yy, zz, tt))

## test vectors from the appendix of draft-irtf-cfrg-ristretto-00
def test_generator():
    B = [None] * 16
    B[0] = binascii.unhexlify('0000000000000000000000000000000000000000000000000000000000000000')
    B[1] = binascii.unhexlify('e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76')
    B[2] = binascii.unhexlify('6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919')
    B[3] = binascii.unhexlify('94741f5d5d52755ece4f23f044ee27d5d1ea1e2bd196b462166b16152a9d0259')
    B[4] = binascii.unhexlify('da80862773358b466ffadfe0b3293ab3d9fd53c5ea6c955358f568322daf6a57')
    B[5] = binascii.unhexlify('e882b131016b52c1d3337080187cf768423efccbb517bb495ab812c4160ff44e')
    B[6] = binascii.unhexlify('f64746d3c92b13050ed8d80236a7f0007c3b3f962f5ba793d19a601ebb1df403')
    B[7] = binascii.unhexlify('44f53520926ec81fbd5a387845beb7df85a96a24ece18738bdcfa6a7822a176d')
    B[8] = binascii.unhexlify('903293d8f2287ebe10e2374dc1a53e0bc887e592699f02d077d5263cdd55601c')
    B[9] = binascii.unhexlify('02622ace8f7303a31cafc63f8fc48fdc16e1c8c8d234b2f0d6685282a9076031')
    B[10] = binascii.unhexlify('20706fd788b2720a1ed2a5dad4952b01f413bcf0e7564de8cdc816689e2db95f')
    B[11] = binascii.unhexlify('bce83f8ba5dd2fa572864c24ba1810f9522bc6004afe95877ac73241cafdab42')
    B[12] = binascii.unhexlify('e4549ee16b9aa03099ca208c67adafcafa4c3f3e4e5303de6026e3ca8ff84460')
    B[13] = binascii.unhexlify('aa52e000df2e16f55fb1032fc33bc42742dad6bd5a8fc0be0167436c5948501f')
    B[14] = binascii.unhexlify('46376b80f409b29dc2b5f6f0c52591990896e5716f41477cd30085ab7f10301e')
    B[15] = binascii.unhexlify('e0c418f7c8d9c4cdd7395b93ea124f3ad99021bb681dfc3302a9d99a2e53e64e')

    b1 = DECODE(B[1])
    for i in range(1, len(B)):
        p1 = DECODE(B[i - 1])
        p2 = DECODE(B[i])
        assert EQUALS(p2, _edw_add(p1, b1))

def test_invalid():
    invalids = [
        binascii.unhexlify('00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'),
        binascii.unhexlify('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f'),
        binascii.unhexlify('f3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f'),
        binascii.unhexlify('edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f'),
        binascii.unhexlify('0100000000000000000000000000000000000000000000000000000000000000'),
        binascii.unhexlify('01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f'),
        binascii.unhexlify('ed57ffd8c914fb201471d1c3d245ce3c746fcbe63a3679d51b6a516ebebe0e20'),
        binascii.unhexlify('c34c4e1826e5d403b78e246e88aa051c36ccf0aafebffe137d148a2bf9104562'),
        binascii.unhexlify('c940e5a4404157cfb1628b108db051a8d439e1a421394ec4ebccb9ec92a8ac78'),
        binascii.unhexlify('47cfc5497c53dc8e61c91d17fd626ffb1c49e2bca94eed052281b510b1117a24'),
        binascii.unhexlify('f1c6165d33367351b0da8f6e4511010c68174a03b6581212c71c0e1d026c3c72'),
        binascii.unhexlify('87260f7a2f12495118360f02c26a470f450dadf34a413d21042b43b9d93e1309'),
        binascii.unhexlify('26948d35ca62e643e26a83177332e6b6afeb9d08e4268b650f1f5bbd8d81d371'),
        binascii.unhexlify('4eac077a713c57b4f4397629a4145982c661f48044dd3f96427d40b147d9742f'),
        binascii.unhexlify('de6a7b00deadc788eb6b6c8d20c0ae96c2f2019078fa604fee5b87d6e989ad7b'),
        binascii.unhexlify('bcab477be20861e01e4a0e295284146a510150d9817763caf1a6f4b422d67042'),
        binascii.unhexlify('2a292df7e32cababbd9de088d1d1abec9fc0440f637ed2fba145094dc14bea08'),
        binascii.unhexlify('f4a9e534fc0d216c44b218fa0c42d99635a0127ee2e53c712f70609649fdff22'),
        binascii.unhexlify('8268436f8c4126196cf64b3c7ddbda90746a378625f9813dd9b8457077256731'),
        binascii.unhexlify('2810e5cbc2cc4d4eece54f61c6f69758e289aa7ab440b3cbeaa21995c2f4232b'),
        binascii.unhexlify('3eb858e78f5a7254d8c9731174a94f76755fd3941c0ac93735c07ba14579630e'),
        binascii.unhexlify('a45fdc55c76448c049a1ab33f17023edfb2be3581e9c7aade8a6125215e04220'),
        binascii.unhexlify('d483fe813c6ba647ebbfd3ec41adca1c6130c2beeee9d9bf065c8d151c5f396e'),
        binascii.unhexlify('8a2e1d30050198c65a54483123960ccc38aef6848e1ec8f5f780e8523769ba32'),
        binascii.unhexlify('32888462f8b486c68ad7dd9610be5192bbeaf3b443951ac1a8118419d9fa097b'),
        binascii.unhexlify('227142501b9d4355ccba290404bde41575b037693cef1f438c47f8fbf35d1165'),
        binascii.unhexlify('5c37cc491da847cfeb9281d407efc41e15144c876e0170b499a96a22ed31e01e'),
        binascii.unhexlify('445425117cb8c90edcbc7c1cc0e74f747f2c1efa5630a967c64f287792a48a4b'),
        binascii.unhexlify('ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f'),
    ]
    for inv in invalids:
        try:
            DECODE(inv)
        except ValueError as e:
            continue
        else:
            raise RuntimeError("failed to reject invalid encoding %s" % binascii.hexlify(inv))

def test_fromuniformbytes():
    inputs = [
        (binascii.unhexlify('5d1be09e3d0c82fc538112490e35701979d99e06ca3e2b5b54bffe8b4dc772c14d98b696a1bbfb5ca32c436cc61c16563790306c79eaca7705668b47dffe5bb6'), binascii.unhexlify('3066f82a1a747d45120d1740f14358531a8f04bbffe6a819f86dfe50f44a0a46')),
        (binascii.unhexlify('f116b34b8f17ceb56e8732a60d913dd10cce47a6d53bee9204be8b44f6678b270102a56902e2488c46120e9276cfe54638286b9e4b3cdb470b542d46c2068d38'), binascii.unhexlify('f26e5b6f7d362d2d2a94c5d0e7602cb4773c95a2e5c31a64f133189fa76ed61b')),
        (binascii.unhexlify('8422e1bbdaab52938b81fd602effb6f89110e1e57208ad12d9ad767e2e25510c27140775f9337088b982d83d7fcf0b2fa1edffe51952cbe7365e95c86eaf325c'), binascii.unhexlify('006ccd2a9e6867e6a2c5cea83d3302cc9de128dd2a9a57dd8ee7b9d7ffe02826')),
        (binascii.unhexlify('ac22415129b61427bf464e17baee8db65940c233b98afce8d17c57beeb7876c2150d15af1cb1fb824bbd14955f2b57d08d388aab431a391cfc33d5bafb5dbbaf'), binascii.unhexlify('f8f0c87cf237953c5890aec3998169005dae3eca1fbb04548c635953c817f92a')),
        (binascii.unhexlify('165d697a1ef3d5cf3c38565beefcf88c0f282b8e7dbd28544c483432f1cec7675debea8ebb4e5fe7d6f6e5db15f15587ac4d4d4a1de7191e0c1ca6664abcc413'), binascii.unhexlify('ae81e7dedf20a497e10c304a765c1767a42d6e06029758d2d7e8ef7cc4c41179')),
        (binascii.unhexlify('a836e6c9a9ca9f1e8d486273ad56a78c70cf18f0ce10abb1c7172ddd605d7fd2979854f47ae1ccf204a33102095b4200e5befc0465accc263175485f0e17ea5c'), binascii.unhexlify('e2705652ff9f5e44d3e841bf1c251cf7dddb77d140870d1ab2ed64f1a9ce8628')),
        (binascii.unhexlify('2cdc11eaeb95daf01189417cdddbf95952993aa9cb9c640eb5058d09702c74622c9965a697a3b345ec24ee56335b556e677b30e6f90ac77d781064f866a3c982'), binascii.unhexlify('80bd07262511cdde4863f8a7434cef696750681cb9510eea557088f76d9e5065')),
        (binascii.unhexlify('edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1200000000000000000000000000000000000000000000000000000000000000'), binascii.unhexlify('304282791023b73128d277bdcb5c7746ef2eac08dde9f2983379cb8e5ef0517f')),
        (binascii.unhexlify('edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'), binascii.unhexlify('304282791023b73128d277bdcb5c7746ef2eac08dde9f2983379cb8e5ef0517f')),
        (binascii.unhexlify('0000000000000000000000000000000000000000000000000000000000000080ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f'), binascii.unhexlify('304282791023b73128d277bdcb5c7746ef2eac08dde9f2983379cb8e5ef0517f')),
        (binascii.unhexlify('00000000000000000000000000000000000000000000000000000000000000001200000000000000000000000000000000000000000000000000000000000080'), binascii.unhexlify('304282791023b73128d277bdcb5c7746ef2eac08dde9f2983379cb8e5ef0517f')),
    ]
    for (i, o) in inputs:
        p1 = DECODE(FromUniformBytes(i))
        p2 = DECODE(o)
        assert EQUALS(p1, p2)

def test_sqrt():
    assert SQRT_RATIO_M1(F(0), F(0)) == (True, F(0))
    assert SQRT_RATIO_M1(F(0), F(1)) == (True, F(0))
    assert SQRT_RATIO_M1(F(1), F(0)) == (False, F(0))
    assert SQRT_RATIO_M1(F(2), F(1)) == (False, F(OS2IP_le(binascii.unhexlify('3c5ff1b5d8e4113b871bd052f9e7bcd0582804c266ffb2d4f4203eb07fdb7c54'))))
    assert SQRT_RATIO_M1(F(4), F(1)) == (True, F(2))
    assert SQRT_RATIO_M1(F(1), F(4)) == (True, F(OS2IP_le(binascii.unhexlify('f6ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3f'))))

if __name__ == "__main__":
    test_generator()
    test_invalid()
    test_fromuniformbytes()
    test_sqrt()
    _check_point(*MAP(F(0)))
    for _ in range(0, 1024):
        test_SQRT_RATIO_M1()
        test_MAP()
        test_ENCODE_DECODE()