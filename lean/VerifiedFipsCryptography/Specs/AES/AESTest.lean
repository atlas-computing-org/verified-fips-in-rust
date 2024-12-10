import VerifiedFipsCryptography.Specs.AES.AES
import AssertCmd

namespace AESTest

/-! CAVS 11.1 test vectors -/

namespace AES128

/-! ECBGFSbox128.rsp: AESVS GFSbox test data for ECB (Count = 0) -/
namespace ECBGFSbox128_0
def key : Array UInt8 := hexStringToUInt8Array "00000000000000000000000000000000"
def plain : Array UInt8 := hexStringToUInt8Array "f34481ec3cc627bacd5dc3fb08f273e6"
def cipher : Array UInt8 := hexStringToUInt8Array "0336763e966d92595a567cc9ce537f5e"
#assert (AES.AES128 plain key) == cipher
#assert (AES.AES128Inv cipher key) == plain
#assert (AES.AES128Inv (AES.AES128 plain key) key) == plain
end ECBGFSbox128_0

/-! ECBKeySbox128.rsp: AESVS KeySbox test data for ECB (Count = 0) -/
namespace ECBKeySbox128_0
def key : Array UInt8 := hexStringToUInt8Array "10a58869d74be5a374cf867cfb473859"
def plain : Array UInt8 := hexStringToUInt8Array "00000000000000000000000000000000"
def cipher : Array UInt8 := hexStringToUInt8Array "6d251e6944b051e04eaa6fb4dbf78465"
#assert (AES.AES128 plain key) == cipher
#assert (AES.AES128Inv cipher key) == plain
#assert (AES.AES128Inv (AES.AES128 plain key) key) == plain
end ECBKeySbox128_0

/-! ECBVarKey128.rsp: AESVS VarKey test data for ECB (Count = 0) -/
namespace ECBVarKey128_0
def key : Array UInt8 := hexStringToUInt8Array "80000000000000000000000000000000"
def plain : Array UInt8 := hexStringToUInt8Array "00000000000000000000000000000000"
def cipher : Array UInt8 := hexStringToUInt8Array "0edd33d3c621e546455bd8ba1418bec8"
#assert (AES.AES128 plain key) == cipher
#assert (AES.AES128Inv cipher key) == plain
#assert (AES.AES128Inv (AES.AES128 plain key) key) == plain
end ECBVarKey128_0

/-! ECBVarTxt128.rsp: AESVS VarTxt test data for ECB (Count = 0) -/
namespace ECBVarTxt128_0
def key : Array UInt8 := hexStringToUInt8Array "00000000000000000000000000000000"
def plain : Array UInt8 := hexStringToUInt8Array "80000000000000000000000000000000"
def cipher : Array UInt8 := hexStringToUInt8Array "3ad78e726c1ec02b7ebfe92b23d9ec34"
#assert (AES.AES128 plain key) == cipher
#assert (AES.AES128Inv cipher key) == plain
#assert (AES.AES128Inv (AES.AES128 plain key) key) == plain
end ECBVarTxt128_0

end AES128

namespace AES192

/-! ECBGFSbox192.rsp: AESVS GFSbox test data for ECB (Count = 0) -/
namespace ECBGFSbox192_0
def key : Array UInt8 := hexStringToUInt8Array "000000000000000000000000000000000000000000000000"
def plain : Array UInt8 := hexStringToUInt8Array "1b077a6af4b7f98229de786d7516b639"
def cipher : Array UInt8 := hexStringToUInt8Array "275cfc0413d8ccb70513c3859b1d0f72"
#assert (AES.AES192 plain key) == cipher
#assert (AES.AES192Inv cipher key) == plain
#assert (AES.AES192Inv (AES.AES192 plain key) key) == plain
end ECBGFSbox192_0

/-! ECBKeySbox192.rsp: AESVS KeySbox test data for ECB (Count = 0) -/
namespace ECBKeySbox192_0
def key : Array UInt8 := hexStringToUInt8Array "e9f065d7c13573587f7875357dfbb16c53489f6a4bd0f7cd"
def plain : Array UInt8 := hexStringToUInt8Array "00000000000000000000000000000000"
def cipher : Array UInt8 := hexStringToUInt8Array "0956259c9cd5cfd0181cca53380cde06"
#assert (AES.AES192 plain key) == cipher
#assert (AES.AES192Inv cipher key) == plain
#assert (AES.AES192Inv (AES.AES192 plain key) key) == plain
end ECBKeySbox192_0

/-! ECBVarKey192.rsp: AESVS VarKey test data for ECB (Count = 0) -/
namespace ECBVarKey192_0
def key : Array UInt8 := hexStringToUInt8Array "800000000000000000000000000000000000000000000000"
def plain : Array UInt8 := hexStringToUInt8Array "00000000000000000000000000000000"
def cipher : Array UInt8 := hexStringToUInt8Array "de885dc87f5a92594082d02cc1e1b42c"
#assert (AES.AES192 plain key) == cipher
#assert (AES.AES192Inv cipher key) == plain
#assert (AES.AES192Inv (AES.AES192 plain key) key) == plain
end ECBVarKey192_0

/-! ECBVarTxt192.rsp: AESVS VarTxt test data for ECB (Count = 0) -/
namespace ECBVarTxt192_0
def key : Array UInt8 := hexStringToUInt8Array "000000000000000000000000000000000000000000000000"
def plain : Array UInt8 := hexStringToUInt8Array "80000000000000000000000000000000"
def cipher : Array UInt8 := hexStringToUInt8Array "6cd02513e8d4dc986b4afe087a60bd0c"
#assert (AES.AES192 plain key) == cipher
#assert (AES.AES192Inv cipher key) == plain
#assert (AES.AES192Inv (AES.AES192 plain key) key) == plain
end ECBVarTxt192_0

end AES192

namespace AES256

/-! ECBGFSbox256.rsp: AESVS GFSbox test data for ECB (Count = 0) -/
namespace ECBGFSbox256_0
def key : Array UInt8 := hexStringToUInt8Array "0000000000000000000000000000000000000000000000000000000000000000"
def plain : Array UInt8 := hexStringToUInt8Array "014730f80ac625fe84f026c60bfd547d"
def cipher : Array UInt8 := hexStringToUInt8Array "5c9d844ed46f9885085e5d6a4f94c7d7"
#assert (AES.AES256 plain key) == cipher
#assert (AES.AES256Inv cipher key) == plain
#assert (AES.AES256Inv (AES.AES256 plain key) key) == plain
end ECBGFSbox256_0

/-! ECBKeySbox256.rsp: AESVS KeySbox test data for ECB (Count = 0) -/
namespace ECBKeySbox256_0
def key : Array UInt8 := hexStringToUInt8Array "c47b0294dbbbee0fec4757f22ffeee3587ca4730c3d33b691df38bab076bc558"
def plain : Array UInt8 := hexStringToUInt8Array "00000000000000000000000000000000"
def cipher : Array UInt8 := hexStringToUInt8Array "46f2fb342d6f0ab477476fc501242c5f"
#assert (AES.AES256 plain key) == cipher
#assert (AES.AES256Inv cipher key) == plain
#assert (AES.AES256Inv (AES.AES256 plain key) key) == plain
end ECBKeySbox256_0

/-! ECBVarKey256.rsp: AESVS VarKey test data for ECB (Count = 0) -/
namespace ECBVarKey256_0
def key : Array UInt8 := hexStringToUInt8Array "8000000000000000000000000000000000000000000000000000000000000000"
def plain : Array UInt8 := hexStringToUInt8Array "00000000000000000000000000000000"
def cipher : Array UInt8 := hexStringToUInt8Array "e35a6dcb19b201a01ebcfa8aa22b5759"
#assert (AES.AES256 plain key) == cipher
#assert (AES.AES256Inv cipher key) == plain
#assert (AES.AES256Inv (AES.AES256 plain key) key) == plain
end ECBVarKey256_0

/-! ECBVarTxt256.rsp: AESVS VarTxt test data for ECB (Count = 0) -/
namespace ECBVarTxt256_0
def key : Array UInt8 := hexStringToUInt8Array "0000000000000000000000000000000000000000000000000000000000000000"
def plain : Array UInt8 := hexStringToUInt8Array "80000000000000000000000000000000"
def cipher : Array UInt8 := hexStringToUInt8Array "ddc6bf790c15760d8d9aeb6f9a75fd4e"
#assert (AES.AES256 plain key) == cipher
#assert (AES.AES256Inv cipher key) == plain
#assert (AES.AES256Inv (AES.AES256 plain key) key) == plain
end ECBVarTxt256_0

end AES256

end AESTest
