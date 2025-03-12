from itertools import chain
from typing import Any, Dict, Optional, Tuple, Type

from yamlable import YamlAble, yaml_info, yaml_info_decorate
import sys 
sys.path.append('/home/zhao/Shujie/Routing_traffic/coding/bgpsimulator/bgp_simulator_pkg/bgp_simulator_pkg')

from enums import Relationships


_all_slots: Dict[Type["Announcement"], Tuple[str, ...]] = dict()


@yaml_info(yaml_tag="Announcement")
class Announcement(YamlAble):
    """BGP Announcement"""

    # MUST use slots for speed
    # Since anns get copied across 70k ASes
    __slots__ = ("prefix", "timestamp", "as_path", "roa_valid_length",
                 "roa_origin",
                 "recv_relationship", "seed_asn", "withdraw", "traceback_end")

    def __init__(self,
                 *,
                 prefix: str,
                 as_path: Tuple[int, ...],
                 timestamp: int,
                 seed_asn: Optional[int],
                 roa_valid_length: Optional[bool],
                 roa_origin: Optional[int],
                 recv_relationship: Relationships,
                 withdraw: bool = False,
                 traceback_end: bool = False,
                 communities: Tuple[str, ...] = ()):
        self.prefix: str = prefix
        self.as_path: Tuple[int, ...] = as_path
        self.timestamp: int = timestamp
        self.seed_asn: Optional[int] = seed_asn
        self.roa_valid_length: Optional[bool] = roa_valid_length
        self.roa_origin: Optional[int] = roa_origin
        self.recv_relationship: Relationships = recv_relationship
        self.withdraw: bool = withdraw
        self.traceback_end: bool = traceback_end
        self.communities: Tuple[str, ...] = communities

    def __init_subclass__(cls, *args, **kwargs):
        """This method essentially creates a list of all subclasses
        This is allows us to easily assign yaml tags
        """

        super().__init_subclass__(*args, **kwargs)

        yaml_info_decorate(cls, yaml_tag=cls.__name__)

    def __eq__(self, other) -> bool:
        if isinstance(other, Announcement):
            return self._get_vars() == other._get_vars()
        else:
            return NotImplemented

    def prefix_path_attributes_eq(self, ann: Optional["Announcement"]) -> bool:
        """Checks prefix and as path equivalency"""

        if ann is None:
            return False
        elif isinstance(ann, Announcement):
            return (ann.prefix, ann.as_path) == (self.prefix, self.as_path)
        else:
            raise NotImplementedError

    def copy(self,
             overwrite_default_kwargs: Optional[Dict[Any, Any]] = None
             ) -> "Announcement":
        """Creates a new ann with proper sim attrs"""

        kwargs = self._get_vars()
        # Replace seed asn and traceback end every time by default
        #kwargs["seed_asn"] = None
        kwargs["traceback_end"] = False
        if overwrite_default_kwargs:
            kwargs.update(overwrite_default_kwargs)

        return self.__class__(**kwargs)

    @property
    def invalid_by_roa(self) -> bool:
        """Returns True if Ann is invalid by ROA

        False means ann is either valid or unknown
        """

        # Not covered by ROA, unknown
        if self.roa_origin is None:
            return False
        else:
            
            return self.origin != self.roa_origin or not self.roa_valid_length

    @property
    def valid_by_roa(self) -> bool:
        """Returns True if Ann is valid by ROA

        False means ann is either invalid or unknown
        """

        # Need the bool here for mypy, ugh
        return bool(self.origin == self.roa_origin and self.roa_valid_length)

    @property
    def unknown_by_roa(self) -> bool:
        """Returns True if ann is not covered by roa"""

        return not self.invalid_by_roa and not self.valid_by_roa

    @property
    def covered_by_roa(self) -> bool:
        """Returns if an announcement has a roa"""

        return not self.unknown_by_roa

    @property
    def roa_routed(self) -> bool:
        """Returns bool for if announcement is routed according to ROA"""

        return self.roa_origin != 0

    @property
    def origin(self) -> int:
        """Returns the origin of the announcement"""

        return self.as_path[-1]

    def __str__(self) -> str:
        return f"{self.prefix} {self.as_path} {self.recv_relationship}"

    @property
    def all_slots(self) -> Tuple[str, ...]:
        """Returns all slots including of parent classes"""

        global _all_slots
        cls_slots_tpl = _all_slots.get(self.__class__)

        # singleton for speed
        if not cls_slots_tpl:
            # https://stackoverflow.com/a/6720815/8903959
            cls_slots = chain.from_iterable(getattr(cls, '__slots__', [])
                                            for cls in self.__class__.__mro__)
            cls_slots_tpl = tuple(list(cls_slots))
            _all_slots[self.__class__] = cls_slots_tpl
        return cls_slots_tpl

    def _get_vars(self) -> Dict[str, Any]:
        """Returns class as a dict

        (Can't use normal vars due to slots)"""

        return {x: getattr(self, x) for x in self.all_slots}

    def __hash__(self):
        """Hash func. Needed for ROV++"""
        return hash(str(self))

##############
# Yaml funcs #
##############

    def __to_yaml_dict__(self) -> Dict[str, Any]:
        """ This optional method is called when you call yaml.dump()"""

        return self._get_vars()

    @classmethod
    def __from_yaml_dict__(cls: Type["Announcement"],
                           dct: Dict[str, Any],
                           yaml_tag: Any
                           ) -> "Announcement":
        """ This optional method is called when you call yaml.load()"""

        return cls(**dct)
