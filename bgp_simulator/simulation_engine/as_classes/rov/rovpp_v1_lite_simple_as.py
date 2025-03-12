from typing import Dict, Tuple, TYPE_CHECKING, Optional
from .rov_simple_as import ROVSimpleAS


from enums import Relationships
from ...announcement import Announcement as Ann
from ...rovpp_ann import ROVPPAnn

import sys
sys.path.append(
    '/home/zhao/Shujie/Routing_traffic/coding/bgpsimulator/bgp_simulator_pkg/bgp_simulator_pkg')

if TYPE_CHECKING:
    from simulation_framework import Scenario


class ROVPPV1LiteSimpleAS(ROVSimpleAS):

    name = "ROV++V1 Lite Simple"

    def __init__(self, *args, **kwargs):
        super(ROVPPV1LiteSimpleAS, self).__init__(*args, **kwargs)
        self.temp_holes = dict()

    def _policy_propagate(self, _, ann, *args):
        """Only propagate announcements that aren't blackholes"""

        # Policy handled this ann for propagation (and did nothing)
        return ann.blackhole

    def receive_ann(self, ann: Ann, *args, **kwargs):
        """Ensures that announcments are ROV++ and valid"""

        if not isinstance(ann, ROVPPAnn):
            raise NotImplementedError("Not an ROV++ Announcement")
        return super(ROVPPV1LiteSimpleAS, self).receive_ann(
            ann, *args, **kwargs)

    def process_incoming_anns(self,
                              *,
                              from_rel: Relationships,
                              propagation_round: int,
                              scenario: "Scenario",
                              reset_q: bool = True):
        """Processes all incoming announcements"""

        self.temp_holes: Dict[Ann, Tuple[Ann]] = self._get_ann_to_holes_dict(
            scenario)
        super(ROVPPV1LiteSimpleAS, self).process_incoming_anns(
            from_rel=from_rel,
            propagation_round=propagation_round,
            scenario=scenario,
            reset_q=False)

        self._add_blackholes(self.temp_holes, from_rel, scenario)

        # It's possible that we had a previously valid prefix
        # Then later recieved a subprefix that was invalid
        # So we must recount the holes of each ann in local RIB
        self._recount_holes(propagation_round)

        self._reset_q(reset_q)

    def _recount_holes(self, propagation_round):
        # It's possible that we had a previously valid prefix
        # Then later recieved a subprefix that was invalid
        # Or there was previously an invalid subprefix
        # But later that invalid subprefix was removed
        # So we must recount the holes of each ann in local RIB
        assert propagation_round == 0, "Must recount holes if you plan on this"

    def _reset_q(self, reset_q: bool):
        if reset_q:
            self.temp_holes = dict()
        super(ROVPPV1LiteSimpleAS, self)._reset_q(reset_q)

    def _get_ann_to_holes_dict(self, scenario):
        """Gets announcements to a typle of Ann holes

        Holes are subprefix hijacks
        """

        holes = dict()
      
        for _, ann_list in self._recv_q.prefix_anns():
            for ann in ann_list:
                
                ann_holes = []
                #if self.asn == 401085:
                #    print("Ann: ", ann)
                for subprefix in scenario.ordered_prefix_subprefix_dict[
                        ann.prefix]:

                    for sub_ann in self._recv_q.get_ann_list(subprefix):
                        # Holes are only from same neighbor
                        if (sub_ann.invalid_by_roa
                                and sub_ann.as_path[0] == ann.as_path[0]):
                            ann_holes.append(sub_ann)
                # check all non routed announcements of the same prefix
                for same_prefix_ann in self._recv_q.get_ann_list(ann.prefix):
                    if (same_prefix_ann.invalid_by_roa
                        and not same_prefix_ann.roa_routed
                            and same_prefix_ann.as_path[0] == ann.as_path[0]):
                        ann_holes.append(same_prefix_ann)
                holes[ann] = tuple(ann_holes)
                '''
                if self.asn == 401085:
                    for hole in ann_holes:
                        print('Hole: ', hole)
                '''
        
        return holes

    def _add_blackholes(self, holes, from_rel, scenario):
        """Manipulates local RIB by adding blackholes and dropping invalid"""

        blackholes_to_add = []
        # For each ann in local RIB:
        for _, ann in self._local_rib.prefix_anns():
            # For each hole in ann: (holes are invalid subprefixes)
            if self.asn == 401085:
                print("_local_rib Ann: ", ann, ann.blackhole)
            for unprocessed_hole_ann in ann.holes:
                #if self.asn == 401085:
                #    print("unprocessed_hole_ann: ", unprocessed_hole_ann)

                # If there is not an existing valid ann for that hole subprefix
                existing_local_rib_subprefix_ann = self._local_rib.get_ann(
                    unprocessed_hole_ann.prefix)

                if (existing_local_rib_subprefix_ann is None
                    or (existing_local_rib_subprefix_ann.invalid_by_roa
                        and not existing_local_rib_subprefix_ann.preventive
                        # Without this line
                        # The same local rib Ann will try to create another
                        # blackhole for each from_rel
                        # But we don't want it to recreate
                        # And for single round prop, a future valid ann won't
                        # override the current valid ann due to gao rexford
                        and not existing_local_rib_subprefix_ann.blackhole)):
                    # If another entry exists, remove it
                    if self._local_rib.get_ann(unprocessed_hole_ann.prefix):
                        # Remove current ann and replace with blackhole
                        self._local_rib.remove_ann(unprocessed_hole_ann.prefix)
                    # Create the blackhole

                    blackhole = self._copy_and_process(
                        unprocessed_hole_ann,
                        from_rel,
                        overwrite_default_kwargs={"holes": tuple(),
                                                  "blackhole": True,
                                                  "traceback_end": True})

                    blackholes_to_add.append(blackhole)

        # Must also add announcements that never made it into the local rib
        # Because the professors want to blackhole announcements even if ROV
        # Would have otherwise dropped them
        # For each ann in local RIB:
        for prefix, ann_list in self._recv_q.prefix_anns():
            # Don't go over announcements you've already checked in local rib
            if self._local_rib.get_ann(prefix):
                continue
            for ann in ann_list:
                # Get the anns that aren't routed and add them
                if (not ann.roa_routed
                        and ann.invalid_by_roa
                        and not ann.preventive
                        and not ann.blackhole):
                    # Create the blackhole
                    blackhole = self._copy_and_process(
                        ann,
                        from_rel,
                        overwrite_default_kwargs={"holes": tuple(),
                                                  "blackhole": True,
                                                  "traceback_end": True})

                    blackholes_to_add.append(blackhole)

        '''
        # Hardcoded to blackhole superprefixes that we know exist
        # Professors wanted this change after we finished,
        # not worth the time to add correctly and they okayed this
        if isinstance(scenario, NonRoutedSuperprefixHijack):
            ann = self._local_rib.get_ann("1.0.0.0/8")
            if ann:
                bhole = self._copy_and_process(ann,
                                               from_rel,
                                               overwrite_default_kwargs={
                                                    "prefix": "1.2.0.0/16",
                                                    "holes": [],
                                                    "blackhole": True,
                                                    "traceback_end": True
                                               })
                blackholes_to_add.append(bhole)
            # Add this new prefix to the dict for traceback
            # Keys must also be in order omg
            scenario.ordered_prefix_subprefix_dict = {
                "1.2.0.0/16": [],
                "1.0.0.0/8": ["1.2.0.0/16"],
            }
        '''
        # Do this here to avoid changing dict size
        for blackhole in blackholes_to_add:
            # Add the blackhole
            self._local_rib.add_ann(blackhole)

            # Do nothing - ann should already be a blackhole
            assert ((blackhole.blackhole and blackhole.invalid_by_roa)
                    or not blackhole.invalid_by_roa)

    def _new_rel_better(self,
                        current_ann: Optional[Ann],
                        current_processed: bool,
                        default_current_recv_rel: Relationships,
                        new_ann: Ann,
                        new_processed: bool,
                        default_new_recv_rel: Relationships,
                        ) -> Optional[bool]:
        """Determines if the new ann > current ann by Gao Rexford/relationship

        current_ann: Announcement we are checking against
        current_processed: True if announcement was processed (in local rib)
            This means that the announcement has the current as preprended
                to the AS path, and the proper recv_relationship set
        default_current_recv_rel:: Relationship for if the ann is unprocessed
        new_ann: New announcement
        new_processed: True if announcement was processed (in local rib)
            This means that the announcement has the current AS prepended
                to the AS path, and the proper recv_relationship set
        default_new_recv_rel: Relationship for if the ann is unprocessed
        """

        # mypy says statement is unreachable, but this isn't true for subclasses
        # In other repos
        if current_ann is None:  # type: ignore
            return True
        elif new_ann is None:
            # mypy says statement is unreachable but this isn't true for subclasses
            # In other repos
            return False  # type: ignore
        else:
            
            # Identify safe routes
            if (not self.temp_holes.get(current_ann) and not self.temp_holes.get(new_ann)) or (self.temp_holes.get(current_ann) and self.temp_holes.get(new_ann)):
               
               return super(ROVPPV1LiteSimpleAS, self)._new_rel_better(current_ann, current_processed, default_current_recv_rel, new_ann, new_processed, default_new_recv_rel)
            elif self.temp_holes.get(current_ann) and not self.temp_holes.get(new_ann):
            	return True
            else:
            	return False

        
    def _copy_and_process(self,
                          ann,
                          recv_relationship,
                          overwrite_default_kwargs=None):
        """Deep copies ann and modifies attrs"""

        # for hole in self.temp_holes[ann]:
        # print("Hole: ", ann, hole)

        if overwrite_default_kwargs:  # noqa

            if "holes" not in overwrite_default_kwargs:
                overwrite_default_kwargs["holes"] = self.temp_holes[ann]

        else:

            overwrite_default_kwargs = {"holes": self.temp_holes[ann]}

        return super(ROVPPV1LiteSimpleAS, self)._copy_and_process(
            ann,
            recv_relationship,
            overwrite_default_kwargs=overwrite_default_kwargs)

    def _process_outgoing_ann(self, neighbor, ann, *args, **kwargs):
        no_holes_ann = ann.copy(overwrite_default_kwargs={"holes": ()})
        #if self.asn == 401085:
        #    print("no_holes_ann: ", no_holes_ann)
        super(ROVPPV1LiteSimpleAS, self)._process_outgoing_ann(
            neighbor, no_holes_ann, *args, **kwargs)
