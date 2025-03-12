from __future__ import annotations
from typing import Any, Dict, Optional, TYPE_CHECKING

from ....announcement import Announcement as Ann
from ....ann_containers import RecvQueue
import random
import sys 
sys.path.append('/home/zhao/Shujie/Routing_traffic/coding/bgpsimulator/bgp_simulator_pkg/bgp_simulator_pkg')

from enums import Relationships

if TYPE_CHECKING:
    #from ....simulation_framework import Scenario
    from simulation_framework import Scenario


def receive_ann(self, ann: Ann, accept_withdrawals: bool = False):
    """Function for recieving announcements, adds to recv_q"""

    if ann.withdraw and not accept_withdrawals:
        raise NotImplementedError("Policy can't handle withdrawals")
    self._recv_q.add_ann(ann)


def process_incoming_anns(self,
                          *,
                          from_rel: Relationships,
                          propagation_round: int,
                          scenario: "Scenario",
                          reset_q: bool = True):
    """Process all announcements that were incoming from a specific rel"""

    # For each prefix, get all anns recieved
    
    for prefix, ann_list in self._recv_q.prefix_anns():
        # Get announcement currently in local rib
        current_ann: Ann = self._local_rib.get_ann(prefix)
        
        current_processed: bool = True
        
        ##remove the following code even if it seems mostly correct!
        '''
        # Seeded Ann will never be overriden, so continue
        if getattr(current_ann, "seed_asn", None) is not None:
            continue
        '''
        
        
        # For each announcement that was incoming
        for ann in ann_list:
            # Make sure there are no loops
            # In ROV subclass also check roa validity
            
            
            if self._valid_ann(ann, from_rel): #valid according to the AS cls. 
                
                # Determine if the new ann is better, see gao_rexford.py
                new_ann_better: bool = self._new_ann_better(current_ann,
                                                            current_processed,
                                                            from_rel,
                                                            ann,
                                                            False,
                                                            from_rel)
                
                # If new ann is better, replace the current_ann with it 
                #if self.asn == 401085: print("new ann better: ", current_ann, prefix, ann, new_ann_better)
                if new_ann_better:
                    current_ann = ann
                    current_processed = False
        
        
        
        # This is a new best ann. Process it and add it to the local rib. 
        if current_processed is False: 
            current_ann = self._copy_and_process(current_ann,
                                                 from_rel)
            # Save to local rib
            self._local_rib.add_ann(current_ann)
            

    self._reset_q(reset_q)


def _valid_ann(self,
               ann: Ann,
               recv_relationship: Relationships
               ) -> bool:
    """Determine if an announcement is valid or should be dropped"""

    # BGP Loop Prevention Check
    return not (self.asn in ann.as_path)


def _copy_and_process(self,
                      ann: Ann,
                      recv_relationship: Relationships,
                      overwrite_default_kwargs: Optional[Dict[Any, Any]] = None
                      ) -> Ann:
    """Deep copies ann and modifies attrs

    Prepends AS to AS Path and sets recv_relationship
    """

    kwargs: Dict[str, Any] = {"as_path": (self.asn,) + ann.as_path,
                              "recv_relationship": recv_relationship}

    if overwrite_default_kwargs:
        kwargs.update(overwrite_default_kwargs)
    # Don't use a dict comp here for speed
    return ann.copy(overwrite_default_kwargs=kwargs)


def _reset_q(self, reset_q: bool):
    """Resets the recieve q"""

    if reset_q:
        self._recv_q = RecvQueue()
