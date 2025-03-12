from enum import Enum, unique

yamlable_enums = []


# Yaml must have unique keys/values
@unique
class YamlAbleEnum(Enum):

    def __init_subclass__(cls, *args, **kwargs):
        """This method essentially creates a list of all subclasses

        This is used later in the yaml codec
        """

        super().__init_subclass__(*args, **kwargs)
        yamlable_enums.append(cls)

    @classmethod
    def yaml_suffix(cls):
        return cls.__name__

    @staticmethod
    def yamlable_enums():
        return yamlable_enums


class Outcomes(YamlAbleEnum):
    __slots__ = tuple()  # type: ignore

    ATTACKER_SUCCESS: int = 0
    VICTIM_SUCCESS: int = 1
    DISCONNECTED: int = 2
    UNDETERMINED: int = 3


class Relationships(YamlAbleEnum):
    __slots__ = tuple()  # type: ignore

    # Must start at one for the priority
    PROVIDERS: int = 1
    PEERS: int = 2
    # Customers have highest priority
    # Economic incentives first!
    CUSTOMERS: int = 3
    # Origin must always remain
    ORIGIN: int = 4
    # Unknown for external programs like extrapoaltor
    UNKNOWN: int = 5
    LEAKER: int = 6


class ROAValidity(YamlAbleEnum):
    """Possible values for ROA Validity

    Note that we cannot differentiate between
    invalid by origin or max length
    because you could get one that is invalid by origin for one roa
    and invalid by max length for another roa
    """

    __slots__ = tuple()  # type: ignore

    VALID: int = 0
    UNKNOWN: int = 1
    INVALID: int = 2


class Timestamps(YamlAbleEnum):
    """Different timestamps to use"""

    __slots__ = tuple()  # type: ignore

    # Victim is always first
    VICTIM: int = 1645380300
    ATTACKER: int = 1645380381


class Prefixes(YamlAbleEnum):
    """Prefixes to use for attacks

    prefix always belongs to the victim
    """

    __slots__ = tuple()  # type: ignore

    #SUPERPREFIX: str = "1.0.0.0/8"
    # Prefix always belongs to victim
    PREFIX: str = "1.2.0.0/16"
    SUBPREFIX: str = "1.2.3.0/24"


class ASNs(YamlAbleEnum):
    """Default ASNs for various ASNs"""

    __slots__ = tuple()  # type: ignore

    ATTACKER: int = 666
    VICTIM: int = 777


class ASTypes(YamlAbleEnum):
    """AS Types"""

    __slots__ = ()  # type: ignore

    STUBS_OR_MH: str = "stubs_or_mh"
    INPUT_CLIQUE: str = "input_clique"
    # Not stubs, multihomed, or input clique
    ETC: str = "etc"

