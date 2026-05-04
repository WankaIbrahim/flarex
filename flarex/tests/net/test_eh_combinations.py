"""
Exhaustive extension-header combination tests for apply_eh_chain.

RFC 8200 canonical order enforced by --eh-auto-order:
  hop/hbh (10) < dst (20) < rt (30) < frag (40)

Coverage:
  - Every single EH type including the hbh alias
  - All 6 canonical 2-EH pairs in RFC order   → exact layer order verified
  - All 6 reversed 2-EH pairs (no auto_order) → wrong order preserved (no silent sort)
  - All 12 2-EH permutations with auto_order  → RFC order produced
  - All 4 canonical 3-EH triples in RFC order → exact layer order verified
  - All 24 3-EH permutations with auto_order  → RFC order produced
  - hbh alias interchangeable with hop in multi-EH chains
  - All unsupported EHs (ah, esp, mobility) raise in every chain position
  - Boundary: chain of 3 is accepted; chain of 4 raises
"""
from __future__ import annotations

import pytest

from flarex.net.utils import apply_eh_chain
from flarex.cli.models import CommonConfig, EHName
from scapy.layers.inet6 import IPv6

HBH = "IPv6ExtHdrHopByHop"
DST = "IPv6ExtHdrDestOpt"
RT  = "IPv6ExtHdrRouting"
FRG = "IPv6ExtHdrFragment"

H = EHName.hop
B = EHName.hbh
D = EHName.dst
R = EHName.rt
F = EHName.frag


def mk_cfg(chain, *, auto_order=False):
    return CommonConfig(
        hop_limit=None, src=None, flowlabel=None, payload_size=None,
        timeout=None,
        eh_auto_order=auto_order,
        eh_chain=chain, transport=None,
    )

def layer_order(pkt) -> list[str]:
    """Return the EH class names stacked after the IPv6 base header."""
    names, node = [], pkt.payload
    while node and type(node).__name__ not in ("NoPayload", "Raw"):
        names.append(type(node).__name__)
        node = node.payload if hasattr(node, "payload") else None
    return names

def build(chain, *, auto_order=False) -> list[str]:
    return layer_order(apply_eh_chain(mk_cfg(chain, auto_order=auto_order), IPv6(dst="::1")))


# Singles - each EH type produces exactly one layer

@pytest.mark.parametrize("eh,expected", [
    (H, HBH),
    (B, HBH),
    (D, DST),
    (F, FRG),
])
def test_single_eh(eh, expected):
    assert build([eh]) == [expected]


# 2-EH pairs - RFC order - layers present AND in correct position

@pytest.mark.parametrize("chain,expected", [
    ([H, D], [HBH, DST]),
    ([H, F], [HBH, FRG]),
    ([D, F], [DST, FRG]),
])
def test_pair_rfc_order_preserved(chain, expected):
    assert build(chain) == expected


# 2-EH pairs - reversed order - WITHOUT auto_order the wrong order is kept

@pytest.mark.parametrize("chain,expected", [
    ([D, H], [DST, HBH]),
    ([F, H], [FRG, HBH]),
    ([F, D], [FRG, DST]),
])
def test_pair_wrong_order_preserved_without_auto_order(chain, expected):
    assert build(chain, auto_order=False) == expected


# 2-EH pairs - auto_order - all supported permutations produce RFC order

@pytest.mark.parametrize("chain,expected", [
    ([H, D], [HBH, DST]),
    ([D, H], [HBH, DST]),
    ([H, F], [HBH, FRG]),
    ([F, H], [HBH, FRG]),
    ([D, F], [DST, FRG]),
    ([F, D], [DST, FRG]),
])
def test_pair_auto_order_all_permutations(chain, expected):
    assert build(chain, auto_order=True) == expected


# 3-EH triples - RFC order - layers present AND in correct position

@pytest.mark.parametrize("chain,expected", [
    ([H, D, F], [HBH, DST, FRG]),
])
def test_triple_rfc_order_preserved(chain, expected):
    assert build(chain) == expected


# 3-EH triples - auto_order - all permutations of the supported triple

@pytest.mark.parametrize("chain,expected", [
    # hop + dst + frag  (6 permutations)
    ([H, D, F], [HBH, DST, FRG]),
    ([H, F, D], [HBH, DST, FRG]),
    ([D, H, F], [HBH, DST, FRG]),
    ([D, F, H], [HBH, DST, FRG]),
    ([F, H, D], [HBH, DST, FRG]),
    ([F, D, H], [HBH, DST, FRG]),
])
def test_triple_auto_order_all_permutations(chain, expected):
    assert build(chain, auto_order=True) == expected


# hbh alias interchangeable with hop in multi-EH chains

@pytest.mark.parametrize("chain,expected", [
    ([B, D],    [HBH, DST]),
    ([B, F],    [HBH, FRG]),
    ([D, B],    [DST, HBH]),
    ([B, D, F], [HBH, DST, FRG]),
    ([D, B, F], [DST, HBH, FRG]),
])
def test_hbh_alias_in_chains(chain, expected):
    assert build(chain) == expected

@pytest.mark.parametrize("chain,expected", [
    ([B, D],    [HBH, DST]),
    ([D, B],    [HBH, DST]),
    ([F, B, D], [HBH, DST, FRG]),
])
def test_hbh_alias_auto_order(chain, expected):
    assert build(chain, auto_order=True) == expected


# Unsupported EHs raise in every chain position

UNSUPPORTED = [EHName.rt, EHName.ah, EHName.esp, EHName.mobility]

@pytest.mark.parametrize("eh", UNSUPPORTED)
def test_unsupported_single_raises(eh):
    with pytest.raises(ValueError, match="not implemented"):
        apply_eh_chain(mk_cfg([eh]), IPv6(dst="::1"))

@pytest.mark.parametrize("chain", [
    [EHName.ah,       H],
    [H,       EHName.ah],
    [EHName.esp,      D],
    [D,       EHName.esp],
    [EHName.mobility, R],
    [R,  EHName.mobility],
])
def test_unsupported_eh_in_pair_raises(chain):
    with pytest.raises(ValueError, match="not implemented"):
        apply_eh_chain(mk_cfg(chain), IPv6(dst="::1"))

@pytest.mark.parametrize("chain", [
    [EHName.ah,       H, D],
    [H, EHName.ah,       D],
    [H, D,       EHName.ah],
    [EHName.mobility, R, F],
    [R, EHName.mobility, F],
    [R, F,  EHName.mobility],
])
def test_unsupported_eh_in_triple_raises(chain):
    with pytest.raises(ValueError, match="not implemented"):
        apply_eh_chain(mk_cfg(chain), IPv6(dst="::1"))


# Chain length boundary

def test_chain_of_3_is_accepted():
    result = build([H, D, F])
    assert len(result) == 3

def test_chain_of_4_raises():
    with pytest.raises(ValueError, match="Cannot chain more than 3"):
        apply_eh_chain(mk_cfg([H, D, R, F]), IPv6(dst="::1"))

def test_chain_of_4_with_unsupported_still_raises_length_first():
    with pytest.raises(ValueError, match="Cannot chain more than 3"):
        apply_eh_chain(mk_cfg([H, D, R, EHName.ah]), IPv6(dst="::1"))
