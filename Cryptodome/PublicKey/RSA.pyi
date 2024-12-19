from typing import Callable, Union, Tuple, Optional, overload, Literal

from Cryptodome.Math.Numbers import Integer
from Cryptodome.IO._PBES import ProtParams

__all__ = ['generate', 'construct', 'import_key',
           'RsaKey', 'oid']

RNG = Callable[[int], bytes]

class RsaKey(object):
    def __init__(self, **kwargs: int) -> None: ...

    @property
    def n(self) -> int: ...
    @property
    def e(self) -> int: ...
    @property
    def d(self) -> int: ...
    @property
    def p(self) -> int: ...
    @property
    def q(self) -> int: ...
    @property
    def u(self) -> int: ...
    @property
    def invp(self) -> int: ...
    @property
    def invq(self) -> int: ...

    def size_in_bits(self) -> int: ...
    def size_in_bytes(self) -> int: ...
    def has_private(self) -> bool: ...
    def can_encrypt(self) -> bool: ...  # legacy
    def can_sign(self) -> bool:...     # legacy
    def public_key(self) -> RsaKey: ...
    def __eq__(self, other: object) -> bool: ...
    def __ne__(self, other: object) -> bool: ...
    def __getstate__(self) -> None: ...
    def __repr__(self) -> str: ...
    def __str__(self) -> str: ...

    @overload
    def export_key(self,
                   format: Optional[str]="PEM",
                   passphrase: Optional[str]=None,
                   pkcs: Optional[int]=1,
                   protection: Optional[str]=None,
                   randfunc: Optional[RNG]=None
                   ) -> bytes: ...
    @overload
    def export_key(self, *,
                   format: Optional[str]="PEM",
                   passphrase: str,
                   pkcs: Literal[8],
                   protection: str,
                   randfunc: Optional[RNG]=None,
                   prot_params: ProtParams,
                   ) -> bytes: ...

    # Backward compatibility
    exportKey = export_key
    publickey = public_key

Int = Union[int, Integer]

def generate(bits: int, randfunc: Optional[RNG]=None, e: Optional[int]=65537) -> RsaKey: ...
def construct(rsa_components: Union[Tuple[Int, Int], #  n, e
                                    Tuple[Int, Int, Int], #  n, e, d
                                    Tuple[Int, Int, Int, Int, Int], #  n, e, d, p, q
                                    Tuple[Int, Int, Int, Int, Int, Int]], #  n, e, d, p, q, crt_q
              consistency_check: Optional[bool]=True) -> RsaKey: ...
def import_key(extern_key: Union[str, bytes], passphrase: Optional[str]=None) -> RsaKey: ...

# Backward compatibility
importKey = import_key

oid: str
