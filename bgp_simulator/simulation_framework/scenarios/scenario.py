from simulation_engine import SimulationEngine
from simulation_engine import BGPSimpleAS
from simulation_engine import Announcement
from enums import Relationships
from enums import Outcomes
from abc import ABC, abstractmethod
import random
from ipaddress import ip_network
from ipaddress import IPv4Network
from ipaddress import IPv6Network
from typing import Any, Dict, List, Optional, Set, Tuple, Type, Union
import pickle
from caida_collector_pkg import AS
import sys
from pathlib import Path
from collections import defaultdict

sys.path.append(
    '/home/zhao/Shujie/Routing_traffic/coding/bgpsimulator/bgp_simulator_pkg/bgp_simulator_pkg')

pseudo_base_cls_dict: Dict[Type[AS], Type[AS]] = dict()


class Scenario(ABC):
    """Contains information regarding an attack"""
    '''
    __slots__ = ("AnnCls",
                 "BaseASCls",
                 "AdoptASCls",
                 "num_attackers",
                 "num_victims",
                 "attacker_asns",
                 "victim_asns",
                 "attacker_victim_asns_preset",
                 "non_default_as_cls_dict",
                 "ordered_prefix_subprefix_dict",
                 "announcements",
                 "non_default_as_cls_dict")
    '''

    def __init__(self,
                 # This is the base type of announcement for this class
                 # You can specify a different base ann
                 AnnCls: Type[Announcement] = Announcement,
                 BaseASCls: Type[AS] = BGPSimpleAS,
                 AdoptASCls: Optional[Type[AS]] = None,
                 num_attackers: Optional[int] = 1,
                 num_victims: Optional[int] = 1,
                 attacker_asns: Optional[Set[int]] = None,
                 victim_asns: Optional[Set[int]] = None,
                 pfxs: Optional[Set[str]] = None,
                 # Purely for rebuilding from YAML
                 non_default_as_cls_dict: Optional[Dict[int, Type[AS]]] = None,
                 announcements: Tuple[Announcement, ...] = (),
                 output: Optional[dict] = {},
                 total_anns: Optional[set] = set(),
                 affected_asns: Optional[set] = set(),
                 affected_paths: Optional[set] = set(),
                 affected_prefixes: defaultdict(set) = None,
                 num_no_anns: Optional[int] = 0,
                 
                 ):
        """inits attrs

        non_default_as_cls_dict is a dict of asn: AdoptASCls
        where you do __not__ include any of the BaseASCls,
        since that is the default
        """

        self.AnnCls: Type[Announcement] = AnnCls
        self.BaseASCls: Type[AS] = BaseASCls

        # This is done to fix the following:
        # Scenario 1 has 3 BGP ASes and 1 AdoptCls
        # Scenario 2 has no adopt classes, so 4 BGP
        # Scenario 3 we want to run ROV++, but what were the adopting ASes from
        # scenario 1? We don't know anymore.
        # Instead for scenario 2, we have 3 BGP ASes and 1 Psuedo BGP AS
        # Then scenario 3 will still work as expected
        if AdoptASCls is None:
            # mypy says this is unreachable, which is wrong
            global pseudo_base_cls_dict  # type: ignore
            AdoptASCls = pseudo_base_cls_dict.get(self.BaseASCls)
            if not AdoptASCls:
                name: str = f"Psuedo {self.BaseASCls.name}".replace(" ", "")
                PseudoBaseCls = type(name, (self.BaseASCls,), {"name": name})
                pseudo_base_cls_dict[self.BaseASCls] = PseudoBaseCls
                AdoptASCls = PseudoBaseCls
            self.AdoptASCls: Type[AS] = AdoptASCls
        else:
            self.AdoptASCls = AdoptASCls

        self.num_attackers: int = num_attackers
        self.num_victims: int = num_victims

        self.num_no_anns: int = num_no_anns

        self.affected_asns = affected_asns
        self.affected_paths = affected_paths
        self.affected_prefixes = defaultdict(set)
        self.total_anns = total_anns

        # If we are regenerating from yaml
        self.attacker_asns = attacker_asns if attacker_asns else set()
        #assert (attacker_asns is None or len(attacker_asns) == num_attackers)
        self.victim_asns = victim_asns if victim_asns else set()
        #assert (victim_asns is None or len(victim_asns) == num_victims)

        # simulating benign conflicts:
        #self.pfxs = pfxs
        self.output = output
        self.direct_vulnerable_urpf = defaultdict(set)
        self.indirect_vulnerable_urpf = defaultdict(set)
        
        self.as2_set = defaultdict(set)
        self.as3_set = defaultdict(set)
        self.as666_set = defaultdict(set)
        self.affected_customer_set = defaultdict(set)
        
        
        if (victim_asns, attacker_asns) != (None, None):
            self.attacker_victim_asns_preset: bool = True
        else:
            self.attacker_victim_asns_preset = False

        # Purely for yaml #################################################
        if non_default_as_cls_dict:
            self.non_default_as_cls_dict: Dict[int,
                                               Type[AS]
                                               ] = non_default_as_cls_dict
        if announcements:
            self.announcements: Tuple["Announcement", ...] = announcements
            
        
        self.adopting_asns= []
        
        
       
        
        
        
    @property
    def graph_label(self) -> str:
        """Label that will be used on the graph"""

        if self.AdoptASCls:
            return f"{self.BaseASCls.name} ({self.AdoptASCls.name} adopting)"
        else:
            return f"{self.BaseASCls.name} (None adopting)"

    ##############################################
    # Set Attacker/Victim and Announcement Funcs #
    ##############################################

    def _set_attackers_victims_anns(self,
                                    engine: SimulationEngine,
                                    percent_adoption: float,
                                    prev_scenario: Optional["Scenario"]):
        """Sets attackers, victims. announcements instance vars"""

        # Use the same attacker victim pair that was used previously

        if prev_scenario:
            self.attacker_asns = prev_scenario.attacker_asns
            self.victim_asns = prev_scenario.victim_asns
        # This is the first time, randomly select attacker/victim
        else:
           
            self._set_attackers_victims(engine,
                                        percent_adoption,
                                        prev_scenario)
        # Must call this here due to atk/vic pair being different

        # see its subclasses -> hijack scenarios, we can set up different types of bgp hijacks and route leaks
        self.announcements = self._get_announcements()

        self._get_ordered_prefix_subprefix_dict()  # !!!!

    def _set_attackers_victims(self, *args, **kwargs):
        """Sets attacker victim pair"""

        # Only run if attacker and victims aren't already set
        if not self.attacker_victim_asns_preset:
            self.attacker_asns = self._get_attacker_asns(*args, **kwargs)
            self.victim_asns = self._get_victim_asns(*args, **kwargs)

    def _get_attacker_asns(self, *args, **kwargs) -> Set[int]:
        """Returns attacker ASN at random"""
        # return {46699}
        random.seed()
        possible_attacker_asns = \
            self._get_possible_attacker_asns(*args, **kwargs)
        
        
        # https://stackoverflow.com/a/15837796/8903959
        return set(random.sample(tuple(possible_attacker_asns),
                                 self.num_attackers))
        
    def _get_victim_asns(self, *args, **kwargs) -> Set[int]:
        """Returns victim ASN at random. Attacker can't be victim"""
        # return {139739}
        random.seed()
        possible_vic_asns = self._get_possible_victim_asns(*args, **kwargs)
        
        
        return set(random.sample(
            # https://stackoverflow.com/a/15837796/8903959
            tuple(possible_vic_asns.difference(self.attacker_asns)),
            self.num_victims))
        

    # For this, don't bother making a subclass with stubs_and_mh
    # Since it won't really create another class branch,
    # Since another dev would likely just subclass from the same place

    def _get_possible_attacker_asns(self,
                                    engine: SimulationEngine,
                                    percent_adoption: float,
                                    prev_scenario: Optional["Scenario"]
                                    ) -> Set[int]:
        """Returns possible attacker ASNs, defaulted from stubs_and_mh"""

        #return engine.stub_or_mh_asns | engine.input_clique_asns | engine.etc_asns
        return engine.stub_or_mh_asns

    # For this, don't bother making a subclass with stubs_and_mh
    # Since it won't really create another class branch,
    # Since another dev would likely just subclass from the same place
    def _get_possible_victim_asns(self,
                                  engine: SimulationEngine,
                                  percent_adoption: float,
                                  prev_scenario: Optional["Scenario"]
                                  ) -> Set[int]:
        """Returns possible victim ASNs, defaulted from stubs_and_mh"""

        #return engine.stub_or_mh_asns | engine.input_clique_asns | engine.etc_asns
        return engine.stub_or_mh_asns
        

    @abstractmethod
    def _get_announcements(self):
        """Returns announcements"""
        print('get announcements!')

        raise NotImplementedError

    #######################
    # Adopting ASNs funcs #
    #######################

    def _get_non_default_as_cls_dict(self,
                                     engine: SimulationEngine,
                                     percent_adoption: float,
                                     prev_scenario: Optional["Scenario"]
                                     ) -> Dict[int, Type[AS]]:
        """Returns as class dict

        non_default_as_cls_dict is a dict of asn: AdoptASCls
        where you do __not__ include any of the BaseASCls,
        since that is the default

        By default, we use the previous engine input to maintain static
        adoption across trials
        """

        # By default, use the last engine input to maintain static
        # adoption across the graph
        if prev_scenario:
            non_default_as_cls_dict = dict()
            for asn, OldASCls in prev_scenario.non_default_as_cls_dict.items():
                # If the ASN was of the adopting class of the last scenario,
                if OldASCls == prev_scenario.AdoptASCls:
                    non_default_as_cls_dict[asn] = self.AdoptASCls
                # Otherwise keep the AS class as it was
                # This is useful for things like ROV, etc...
                else:
                    non_default_as_cls_dict[asn] = OldASCls
            return non_default_as_cls_dict
        # Randomly get adopting ases
        else:

            return self._get_adopting_asns_dict(engine, percent_adoption)

    def load_adopting_asns(self):
        asns = []
        with open('/home/zhao/Shujie/Routing_traffic/coding/degree_centrality_0.1.pkl', "rb") as f: #rovista_rov_operators.p
            data = pickle.load(f)
        for asn in data:
            asns.append(int(asn))
        return asns
    
    
        
    def _assess_uRPF_asns(self, engine: SimulationEngine):
        urpf_asns = set()
        with open('/home/zhao/Shujie/Routing_traffic/coding/urpf_present_asn.res', "r") as filehandle:
            filecontents = filehandle.readlines()
            for i, line in enumerate(filecontents):
                fields = line.strip('\n').split(',')
                urpf_asns.add(int(fields[0]))
                
        info = defaultdict(dict)
        
        #f = open('./targeted_uRPF_attacks.dat', 'w')
        
        for i, as_obj in enumerate(engine.as_dict.values()):
            obj = as_obj.__to_yaml_dict__()
            info[as_obj.asn]['providers'] = obj['providers']
            info[as_obj.asn]['customers'] = obj['customers']
            info[as_obj.asn]['peers'] = obj['peers']

        target_uRPF_asns = set()
        for urpf_asn in urpf_asns:
            if urpf_asn not in info:
                continue
            if len(info[urpf_asn]['providers']) == 0:
                continue
            
            as2 = random.sample(info[urpf_asn]['providers'], 1)[0]
            
            if len(info[as2]['providers']) == 0 and len(info[as2]['peers']) == 0:
                continue
            if len(info[as2]['providers']) > 0:
                as3 = random.sample(info[as2]['providers'], 1)[0]
            elif len(info[as2]['peers']) > 0:
                as3 = random.sample(info[as2]['peers'], 1)[0]

            if len(info[as2]['customers']) == 0:
                continue
            as666 = random.sample(info[as2]['customers'], 1)[0]
            target_uRPF_asns.add(urpf_asn)
            #f.write(str(urpf_asn)+','+str(as2)+','+str(as3)+','+str(as666)+'\n')

        print("target uRPF asns: ", len(target_uRPF_asns))
        #f.close()
        return target_uRPF_asns

    def _get_adopting_asns_dict(self,
                                engine: SimulationEngine,
                                percent_adopt: float) -> Dict[int, Type[AS]]:
        """Get adopting ASNs

        By default, to get even adoption, adopt in each of the three
        subcategories
        """
        
        
        #f = open('/home/zhao/Shujie/Routing_traffic/coding/three_types_asns.data', 'w')
        adopting_asns = list()
        subcategories = ("stub_or_mh_asns", "etc_asns", "input_clique_asns")
        for subcategory in subcategories:
            asns = getattr(engine, subcategory)
            
            
            #for asn in asns:
            # 	f.write(str(asn) +','+ subcategory+'\n')
            
            # Remove ASes that are already pre-set
            # Ex: Attacker and victim
            # Ex: ROV Nodes (in certain situations)
            #print(subcategory, len(asns))
            
                 
            possible_adopters = asns.difference(self._preset_asns)
            
            # Get how many ASes should be adopting
            k = int(len(possible_adopters) * percent_adopt)
            # Round for the start and end of the graph
            # (if 0 ASes would be adopting, have 1 as adopt)
            # (If all ASes would be adopting, have all -1 adopt)
            # This feature was chosen by my professors, and is not
            # supported by this simulator
            if percent_adopt == -1:
                k = 1
            elif percent_adopt == 101:
                k -= 1

            # https://stackoverflow.com/a/15837796/8903959
            possible_adopters = tuple(possible_adopters)
            random.seed(1)
            adopting_asns.extend(
                random.sample(possible_adopters, k)
            )  # type: ignore
            

        adopting_asns += self._default_adopters
        assert len(adopting_asns) == len(set(adopting_asns))
        
        #f.close()
        
        
        """
        adopting_asns = list(engine.input_clique_asns)
        random.seed(1)
        possible_adopters = list(engine.etc_asns) #+ list(engine.stub_or_mh_asns)
        adopting_asns.extend(random.sample(possible_adopters, int(len(possible_adopters) * percent_adopt)))
        self.num_adopting_asns = "{:.2f}".format(len(adopting_asns)/len(engine.as_dict))
        """
        
        
        #random.seed(1)
        #adopting_asns = random.sample(engine.stub_or_mh_asns, 19)
        
        
        
        #adopting_asns = self.load_adopting_asns()
        
        #adopting_asns = list()
        
        #self.adopting_asns = adopting_asns + list(engine.input_clique_asns)
        print('Networks adopting asns: ', len(self.adopting_asns))
        
        return {asn: self.AdoptASCls for asn in adopting_asns}

    @property
    def _default_adopters(self) -> Set[int]:
        """By default, victim always adopts"""

        return self.victim_asns

    @property
    def _default_non_adopters(self) -> Set[int]:
        """By default, attacker always does not adopt"""

        return self.attacker_asns

    @property
    def _preset_asns(self) -> Set[int]:
        """ASNs that have a preset adoption policy"""
        # Here filter attacker's providers!
        # Returns the union of default adopters and non adopters
        return self._default_adopters | self._default_non_adopters

    def determine_as_outcome(self,
                             as_obj: AS,
                             ann: Optional[Announcement]
                             ) -> Outcomes:
        """Determines the outcome at an AS

        ann is most_specific_ann is the most specific prefix announcement
        that exists at that AS
        """

        if as_obj.asn in self.attacker_asns:
            return Outcomes.ATTACKER_SUCCESS
        elif as_obj.asn in self.victim_asns:
            return Outcomes.VICTIM_SUCCESS
        # End of traceback
        elif (ann is None
              or len(ann.as_path) == 1
              or ann.recv_relationship == Relationships.ORIGIN
              or ann.traceback_end):
            return Outcomes.DISCONNECTED
        else:
            return Outcomes.UNDETERMINED

    def my_determine_as_outcome(self,
                                as_obj: AS,
                                ann: Optional[Announcement]
                                ) -> Outcomes:
        """Determines the outcome at an AS

        ann is most_specific_ann is the most specific prefix announcement
        that exists at that AS
        """

        if (ann is None
            or len(ann.as_path) == 1
            or ann.recv_relationship == Relationships.ORIGIN
                or ann.traceback_end):
            return Outcomes.DISCONNECTED
        #print('seed_asn', ann.seed_asn, ann.origin)
        if ann.seed_asn in self.attacker_asns:

            return Outcomes.ATTACKER_SUCCESS
        elif ann.seed_asn in self.victim_asns:

            return Outcomes.VICTIM_SUCCESS
        # End of traceback
        else:
            return Outcomes.UNDETERMINED

    #############################
    # Engine Manipulation Funcs #
    #############################

    def setup_engine(self,
                     engine: SimulationEngine,
                     percent_adoption: float,
                     prev_scenario: Optional["Scenario"] = None):
        """Sets up engine input"""

        self._set_attackers_victims_anns(engine,
                                         percent_adoption,
                                         prev_scenario)
        self._set_engine_as_classes(engine, percent_adoption, prev_scenario)
        self._seed_engine_announcements(engine,
                                        percent_adoption,
                                        prev_scenario)
        engine.ready_to_run_round = 0
        

    def _set_engine_as_classes(self,
                               engine: SimulationEngine,
                               percent_adoption: float,
                               prev_scenario: Optional["Scenario"]):
        """Resets Engine ASes and changes their AS class

        We do this here because we already seed from the scenario
        to allow for easy overriding. If scenario controls seeding,
        it doesn't make sense for engine to control resetting either
        and have each do half and half
        """

        # non_default_as_cls_dict is a dict of asn: AdoptASCls
        # where you do __not__ include any of the BaseASCls,
        # since that is the default
        # Only regenerate this if it's not already set (like with YAML)
        self.non_default_as_cls_dict = self._get_non_default_as_cls_dict(
            engine,
            percent_adoption,
            prev_scenario=prev_scenario)

        # Validate that this is only non_default ASes
        # This matters, because later this entire dict may be used for the next
        # scenario

        for asn, ASCls in self.non_default_as_cls_dict.items():
            assert ASCls != self.BaseASCls, "No defaults! See comment above"

        # Done here to save as much time  as possible
        BaseASCls = self.BaseASCls
        # print(len(engine))
        for as_obj in engine:
            # Set the AS class to be the proper type of AS
            as_obj.__class__ = self.non_default_as_cls_dict.get(as_obj.asn,
                                                                BaseASCls)

            # Clears all RIBs, etc
            # Reset base is False to avoid overrides base AS info (peers, etc)
            as_obj.__init__(reset_base=False)

    def _seed_engine_announcements(self, engine: SimulationEngine, *args):
        """Seeds announcement at the proper AS

        Since this is the simulator engine, we should
        never have to worry about overlapping announcements
        """

        for ann in self.announcements:  # including two announcements, one is normal another is malicious
            # Get the AS object to seed at
            if ann.seed_asn not in engine.as_dict:
                continue
            obj_to_seed = engine.as_dict[ann.seed_asn]

            # Ensure we aren't replacing anything
            err = "Seeding conflict"
            assert obj_to_seed._local_rib.get_ann(ann.prefix) is None, err
            # Seed by placing in the local rib
            obj_to_seed._local_rib.add_ann(ann)
            self.total_anns.add(ann)

    def post_propagation_hook(self, *args, **kwargs):
        """Useful hook for post propagation"""

        pass

    ################
    # Helper Funcs #
    ################

    def _get_ordered_prefix_subprefix_dict(self):
        """Saves a dict of prefix to subprefixes

        mypy was having a lot of trouble with this section
        thus the type ignores
        """

        prefixes = set([])
        for ann in self.announcements:

            prefixes.add(ann.prefix)
        # Do this here for speed
        prefixes: List[Union[IPv4Network, IPv6Network]] = [  # type: ignore
            ip_network(x) for x in prefixes]
        # Sort prefixes with most specific prefix first
        # Note that this must be sorted for the traceback to get the
        # most specific prefix first

        prefixes = list(sorted(prefixes,
                               key=lambda x: x.num_addresses))  # type: ignore

        prefix_subprefix_dict = {x: [] for x in prefixes}  # type: ignore

        for outer_prefix, subprefix_list in prefix_subprefix_dict.items():
            for prefix in prefixes:
                if (prefix.subnet_of(outer_prefix)  # type: ignore
                        and prefix != outer_prefix):
                    subprefix_list.append(str(prefix))
        # Get rid of ip_network
        self.ordered_prefix_subprefix_dict: Dict[str, List[str]] = {
            str(k): v for k, v in prefix_subprefix_dict.items()}

    ##############
    # Yaml Funcs #
    ##############

    def __to_yaml_dict__(self) -> Dict[Any, Any]:
        """This optional method is called when you call yaml.dump()"""

        return {"announcements": self.announcements,
                "attacker_asns": self.attacker_asns,
                "victim_asns": self.victim_asns,
                "num_victims": self.num_victims,
                "num_attackers": self.num_attackers,
                "non_default_as_cls_dict":
                    {asn: AS.subclass_to_name_dict[ASCls]
                     for asn, ASCls in self.non_default_as_cls_dict.items()}}

    @classmethod
    def __from_yaml_dict__(cls, dct, yaml_tag):
        """This optional method is called when you call yaml.load()"""

        as_classes = {asn: AS.name_to_subclass_dict[name]
                      for asn, name in dct["non_default_as_cls_dict"].items()}

        return cls(announcements=dct["announcements"],
                   attacker_asns=dct["attacker_asns"],
                   victim_asns=dct["victim_asns"],
                   num_victims=dct["num_victims"],
                   num_attackers=dct["num_attackers"],
                   non_default_as_cls_dict=as_classes)
