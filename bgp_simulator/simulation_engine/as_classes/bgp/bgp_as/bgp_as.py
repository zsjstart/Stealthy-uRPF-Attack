from typing import List, Optional

from .propagate_funcs import _propagate
from .propagate_funcs import _process_outgoing_ann
from .propagate_funcs import _prev_sent
from .propagate_funcs import _send_anns

from .process_incoming_funcs import process_incoming_anns
from .process_incoming_funcs import _process_incoming_withdrawal
from .process_incoming_funcs import _withdraw_ann_from_neighbors
from .process_incoming_funcs import _select_best_ribs_in

from ..bgp_simple_as import BGPSimpleAS

from ....ann_containers import RIBsIn
from ....ann_containers import RIBsOut
from ....ann_containers import SendQueue

from ....announcement import Announcement as Ann
import sys 
sys.path.append('/home/zhao/Shujie/Routing_traffic/coding/bgpsimulator/bgp_simulator_pkg/bgp_simulator_pkg')

from enums import Relationships


class BGPAS(BGPSimpleAS):

    name = "BGP"

    def __init__(self,
                 *args,
                 _ribs_in: Optional[RIBsIn] = None,
                 _ribs_out: Optional[RIBsOut] = None,
                 _send_q: Optional[SendQueue] = None,
                 **kwargs):
        super(BGPAS, self).__init__(*args, **kwargs)
        self._ribs_in: RIBsIn = _ribs_in if _ribs_in else RIBsIn()
        self._ribs_out: RIBsOut = _ribs_out if _ribs_out else RIBsOut()
        self._send_q: SendQueue = _send_q if _send_q else SendQueue()

    # Propagation functions
    _propagate = _propagate
    _process_outgoing_ann = _process_outgoing_ann
    _prev_sent = _prev_sent  # type: ignore
    _send_anns = _send_anns

    # Must add this func here since it refers to BGPAS
    # Could use super but want to avoid additional func calls
    def _populate_send_q(self,
                         propagate_to: Relationships,
                         send_rels: List[Relationships]) -> None:
        # Process outging ann is oerriden so this just adds to send q
        super(BGPAS, self)._propagate(propagate_to, send_rels)

    # Process incoming funcs
    process_incoming_anns = process_incoming_anns
    _process_incoming_withdrawal = _process_incoming_withdrawal
    _withdraw_ann_from_neighbors = _withdraw_ann_from_neighbors
    _select_best_ribs_in = _select_best_ribs_in

    # Must be here since it referes to BGPAS
    # Could just use super but want to avoid the additional func calls
    # mypy doesn't understand the func definition
    def receive_ann(self,  # type: ignore
                    ann: Ann,
                    accept_withdrawals: bool = True
                    ) -> None:
        super(BGPAS, self).receive_ann(ann, accept_withdrawals=True)

    def __to_yaml_dict__(self):
        """This optional method is called when you call yaml.dump()"""

        as_dict = super(BGPAS, self).__to_yaml_dict__()
        as_dict.update({"_ribs_in": self._ribs_in,
                        "_ribs_out": self._ribs_out,
                        "_send_q": self._send_q})
        return as_dict
