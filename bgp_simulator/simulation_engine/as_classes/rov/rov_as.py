from .rov_simple_as import ROVSimpleAS

from ..bgp import BGPAS


class ROVAS(ROVSimpleAS, BGPAS):
    """An AS that deploys ROV and has withdrawals, ribs in and out"""

    name: str = "ROV"
