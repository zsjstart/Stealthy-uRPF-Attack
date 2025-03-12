import dataclasses
from typing import Dict, Iterator, Optional

from yamlable import YamlAble, yaml_info

from .ann_container import AnnContainer

from ..announcement import Announcement
import sys 
sys.path.append('/home/zhao/Shujie/Routing_traffic/coding/bgpsimulator/bgp_simulator_pkg/bgp_simulator_pkg')

from enums import Relationships


@yaml_info(yaml_tag="AnnInfo")
@dataclasses.dataclass
class AnnInfo(YamlAble):
    """Dataclass for storing a ribs in Ann info

    These announcements are unprocessed, so we store
    the unprocessed_ann and also the recv_relationship
    (since the recv_relationship on the announcement is
    from the last AS and has not yet been updated)
    """

    unprocessed_ann: Optional[Announcement]
    recv_relationship: Optional[Relationships]


class RIBsIn(AnnContainer):
    """Incomming announcements for a BGP AS

    neighbor: {prefix: (announcement, relationship)}
    """

    __slots__ = ()

    def __init__(self, _info: Optional[Dict[int, Dict[str, AnnInfo]]] = None):
        """Stores _info dict which contains ribs in

        This is passed in so that we can regenerate this class from yaml

        Note that we do not use a defaultdict here because that is not
        yamlable using the yamlable library
        """

        # {neighbor: {prefix: (announcement, relationship)}}
        self._info: Dict[int,
                         Dict[str, AnnInfo]
                         ] = _info if _info is not None else dict()

    def get_unprocessed_ann_recv_rel(self,
                                     neighbor_asn: int,
                                     prefix: str
                                     ) -> Optional[AnnInfo]:
        """Returns AnnInfo for a neighbor ASN and prefix

        We don't use defaultdict here because that's not yamlable
        """

        return self._info.get(neighbor_asn, dict()).get(prefix)

    def add_unprocessed_ann(self,
                            unprocessed_ann: Announcement,
                            recv_relationship: Relationships):
        """Adds an unprocessed ann to ribs in

        We don't use default dict here because it's not yamlable"""

        # Shorten the var name
        ann = unprocessed_ann
        if ann.as_path[0] not in self._info:
            self._info[ann.as_path[0]] = {ann.prefix: AnnInfo(
                unprocessed_ann=unprocessed_ann,
                recv_relationship=recv_relationship)}
        else:
            self._info[ann.as_path[0]][ann.prefix] = AnnInfo(
                unprocessed_ann=unprocessed_ann,
                recv_relationship=recv_relationship)

    def get_ann_infos(self, prefix: str) -> Iterator[AnnInfo]:
        """Returns AnnInfos for a given prefix"""

        default_ann_info: AnnInfo = AnnInfo(unprocessed_ann=None,
                                            recv_relationship=None)
        for prefix_ann_info in self._info.values():
            yield prefix_ann_info.get(prefix, default_ann_info)

    def remove_entry(self, neighbor_asn: int, prefix: str):
        """Removes AnnInfo from RibsIn"""

        del self._info[neighbor_asn][prefix]
