from feature_extractor import load_caida_as_org, load_caida_as_rel
import load_pub_data
import pickle
import time
import random
from simulation_engine import ROVSmartAS
from simulation_engine import ROVSimpleAS
from simulation_engine import SimulationEngine
from simulation_engine import BGPSimpleAS
from copy import deepcopy
from itertools import product
import json
from multiprocessing import Pool
from pathlib import Path
from shutil import make_archive
from tempfile import TemporaryDirectory
from typing import Any, Dict, List, Tuple
from collections import defaultdict

from caida_collector_pkg import CaidaCollector

from .scenarios import Scenario
from .scenarios import SubprefixHijack
from .scenarios import RouteLeak, HybridLeak
from .scenarios import PrefixHijack
from .scenarios import BenignConflict
from .scenarios import ValidPrefix, OldValidPrefix
from .subgraphs import Subgraph
from enums import Relationships
import sys
import math


sys.path.append(
    '/home/zhao/Shujie/Routing_traffic/coding/bgpsimulator/bgp_simulator_pkg/bgp_simulator_pkg')

BASEPATH = '/home/zhao/Shujie/Routing_traffic/coding/'
sys.path.append(BASEPATH)

PubData = dict()

PrefixHijack_attacker_asns = {136923, 23198, 56060, 272045, 267354}
BenignConflict_attacker_asns = {52471}  # 52471, 137019, 44243
ValidPrefix_attacker_asns = {7922, 21928, 149555, 14618, 12389}
RouteLeak_attacker_asns = {199599, 265038, 42313, 42910, 269601}
HybridLeak_attacker_asns = {270771, 13101, 265766, 60299, 21277}




def load_benign_info():
    with open("/home/zhao/Shujie/Routing_traffic/coding/bc_info.p", "rb") as f:
        Info = pickle.load(f)
        return Info

def load_hijack_info():
    
    with open("/home/zhao/Shujie/Routing_traffic/coding/hijackspeer_info.p", "rb") as f:
        Info1 = pickle.load(f)
        print(len(Info1))
        return Info1
        
    '''
    with open("/home/zhao/Shujie/Routing_traffic/coding/hijacksdiff_info.p", "rb") as f:
        Info2 = pickle.load(f)
        Info1.update(Info2)
        prefixes = set()
        roa_asns = set()
        for asn in Info1:
        	for timestamp, prefix, roa_asn in Info1[asn]:
        		prefixes.add(prefix)
        		roa_asns.add(roa_asn)
        print(len(prefixes), len(roa_asns))
        return Info1
    '''


class Simulation:
    """Runs simulations for BGP attack/defend scenarios"""

    def __init__(self,
                 # (.05, .1, .2, .3, .4, .5, .6, .8, 1), #for each percent runing num_trials
                 percent_adoptions: Tuple[float, ...] = (
                     0.5,),  # we won't use this parameter

                 save_dict: bool = False,
                 initial_pfxs: list = None,
                 output_path: Path = Path(
                     "/home/zhao/Shujie/Routing_traffic/coding/bgpsimulator/graphs"),
                 subgraphs: Tuple[Subgraph, ...] = tuple([
                     Cls() for Cls in  # type: ignore
                     Subgraph.subclasses if Cls.name]),  # type: ignore
                 num_trials: int = 1,  # default value is one case in a scenario
                 propagation_rounds: int = 1,
                 parse_cpus: int = 1
                 ):
        """Downloads relationship data, runs simulation

        Graphs -> A list of graph classes
        graph_path: Where to store the graphs. Should be a .tar.gz file
        assert_pypy: Ensures you are using pypy if true
        mp_method: Multiprocessing method
        """

        self.percent_adoptions: Tuple[float, ...] = percent_adoptions
        #self.scenarios: Tuple[Scenario, ...] = scenarios
        self.subgraphs: Tuple[Subgraph, ...] = subgraphs
        
        self.propagation_rounds: int = propagation_rounds
        self.output_path: Path = output_path
        self.parse_cpus: int = parse_cpus

        self.save_dict = save_dict
        self.Info: defaultdict(set) = load_benign_info()
        
        self.initial_pfxs = [pfx for pfx in self.Info] # Each ann countains a unique prefix
        
        self.num_anns: int = 100
        self.num_trials: int = math.ceil(len(self.initial_pfxs)/self.num_anns)
        self.output: dict = {}
        self.prefixes = defaultdict(set)
        self.asns = defaultdict(set)
        self.scenarios: Tuple[Scenario, ...] = tuple(
            [BenignConflict(AdoptASCls=ROVSmartAS, attacker_asns={}, victim_asns={}, output={}, Info=self.Info)]
        )  # ROVSmartAS, BenignConflict, PrefixHijack
        #self.save_path: Path = Path("/home/zhao/Shujie/Routing_traffic/coding/bgpsimulator/bc_sim_no_rov.csv")
        self.save_path2: Path = Path("/home/zhao/Shujie/Routing_traffic/coding/bgpsimulator/bc_sim_pfx_ASnum_lov.csv")

        # All scenarios must have a uni que graph label
        labels = [x.graph_label for x in self.scenarios]
        assert len(labels) == len(set(labels)), "Scenario labels not unique"

        # Done here so that the caida files are cached
        # So that multiprocessing doesn't interfere with one another
        CaidaCollector().run()

    def run(self):
        """Runs the simulation and write the data"""

        self._get_data()
        #self._write_data()
        if self.save_dict:
            # with open(BASEPATH+"global_hege_dict.p", "wb") as fp:
            #    pickle.dump(load_pub_data.GlobalHegeDict, fp)
            with open(BASEPATH+"/LocalData/IRR/irr_database.p", "wb") as fp:
                pickle.dump(load_pub_data.IrrDatabase, fp)

    def _write_data(self):
        """Writes subgraphs in graph_dir"""

        # init JSON and temporary directory
        json_data = dict()
        with TemporaryDirectory() as tmp_dir:
            # Write subgraph and add data to the JSON
            for subgraph in self.subgraphs:
                subgraph.write_graphs(Path(tmp_dir))
                json_data[subgraph.name] = subgraph.data
            # Save the JSON
            with (Path(tmp_dir) / "results.json").open("w") as f:
                json.dump(json_data, f, indent=4)

            # Zip the data
            make_archive(self.output_path, "zip", tmp_dir)  # type: ignore
            print(f"\nWrote graphs to {self.output_path}.zip")

    def _get_data(self):
        """Runs trials for graph and aggregates data"""

        # Single process
        if self.parse_cpus == 1:
            # Results are a list of lists of subgraphs
            print('single CPU')
            results = self._get_single_process_results()
        # Multiprocess
        else:
            # Results are a list of lists of subgraphs
            print('multi CPU')
            results = self._get_mp_results(self.parse_cpus)

        # Results is a list of lists of subgraphs
        # This joins all results from all trials
        for result_subgraphs in results:
            for self_subgraph, result_subgraph in zip(self.subgraphs,
                                                      result_subgraphs):
                # Merges the trial subgraph into this subgraph
                self_subgraph.add_trial_info(result_subgraph)


###########################
# Multiprocessing Methods #
###########################

    def _get_chunks(self, parse_cpus: int) -> List[List[Tuple[float, int]]]:
        """Returns chunks of trial inputs based on number of CPUs running

        Not a generator since we need this for multiprocessing

        We also don't multiprocess one by one because the start up cost of
        each process is huge (since each process must generate it's own engine
        ) so we must divy up the work beforehand
        """

        # https://stackoverflow.com/a/34032549/8903959
        percents_trials = [tuple(x) for x in
                           product(self.percent_adoptions,
                                   list(range(self.num_trials)))]
        print(percents_trials)
        # https://stackoverflow.com/a/2136090/8903959
        # mypy can't seem to handle these types?
        return [percents_trials[i::parse_cpus]  # type: ignore
                for i in range(parse_cpus)]

    def _get_single_process_results(self) -> List[Tuple[Subgraph, ...]]:
        """Get all results when using single processing"""

        return [self._run_chunk(x, single_proc=True)
                for x in self._get_chunks(1)]

    def _get_mp_results(self, parse_cpus: int) -> List[Tuple[Subgraph, ...]]:
        """Get results from multiprocessing"""

        # Pool is much faster than ProcessPoolExecutor
        with Pool(parse_cpus) as pool:
            return pool.map(self._run_chunk,  # type: ignore
                            self._get_chunks(parse_cpus))

############################
# Data Aggregation Methods #
############################

    def _run_chunk(self,
                   percent_adopt_trials: List[Tuple[float, int]],
                   # MUST leave as false. _get_mp_results depends on this
                   # This should be fixed and this comment deleted
                   single_proc: bool = False
                   ) -> Tuple[Subgraph, ...]:
        """Runs a chunk of trial inputs"""

        # Engine is not picklable or dillable AT ALL, so do it here
        # (after the multiprocess process has started)
        # Changing recursion depth does nothing
        # Making nothing a reference does nothing
        engine = CaidaCollector(BaseASCls=BGPSimpleAS,
                                GraphCls=SimulationEngine,
                                ).run(tsv_path=None)
        print(len(engine.as_dict))
        
        '''
        engine_as_dict = dict()
        neighbor_dict = defaultdict(set)
        for asn in engine.as_dict:
            engine_as_dict[asn] = 1
            #for neighbor in getattr(engine.as_dict[asn], Relationships.PEERS.name.lower()):
            for neighbor in engine.as_dict[asn].peers:
            	neighbor_dict[asn].add(neighbor.asn)
            for neighbor in engine.as_dict[asn].providers:
            	neighbor_dict[asn].add(neighbor.asn)
            for neighbor in engine.as_dict[asn].customers:
            	neighbor_dict[asn].add(neighbor.asn)
        with open("/home/zhao/Shujie/Routing_traffic/coding/neighbor_dict.p", "wb") as fp:
            pickle.dump(neighbor_dict, fp)
        with open("/home/zhao/Shujie/Routing_traffic/coding/engine_as_dict.p", "wb") as fp:
            pickle.dump(engine_as_dict, fp)
        '''
        
        # Must deepcopy here to have the same behavior between single
        # And multiprocessing
        if single_proc:
            #print('subgraphs: ', self.subgraphs)
            subgraphs = deepcopy(self.subgraphs)
        else:
            subgraphs = self.subgraphs

        prev_scenario = None
        total_anns = 0
        pfxs = deepcopy(self.initial_pfxs)
        for percent_adopt, trial in percent_adopt_trials:
            '''
            if trial % self.num_trials == 0:
                attacker_asns = deepcopy(self.initial_attacker_asns)
                print('attacker: ', attacker_asns, self.initial_attacker_asns)
            '''
            for scenario in self.scenarios:
                if trial != self.num_trials-1:
                	scenario.pfxs = list(pfxs[trial*self.num_anns:(trial+1)*self.num_anns])
                else:
                	scenario.pfxs = list(pfxs[trial*self.num_anns:])
                
                #scenario.attacker_asns = {270771}

                # Deep copy scenario to ensure it's fresh
                # Since certain things like announcements change round to round
                scenario = deepcopy(scenario)

                print(
                    f"{percent_adopt * 100}% {scenario.graph_label}, #{trial}", end="                             " + "\r")
                
                # Change AS Classes, seed announcements before propagation
                scenario.setup_engine(engine, percent_adopt, prev_scenario)

                for propagation_round in range(self.propagation_rounds):
                    # Run the engine
                    engine.run(propagation_round=propagation_round,
                               scenario=scenario)

                    kwargs = {"engine": engine,
                              "percent_adopt": percent_adopt,
                              "trial": trial,
                              "scenario": scenario,
                              "propagation_round": propagation_round}
                    # Save all engine run info
                    # The reason we aggregate info right now, instead of saving
                    # the engine and doing it later, is because doing it all
                    # in RAM is MUCH faster, and speed is important
                    self._aggregate_engine_run_data(subgraphs, **kwargs)

                    # By default, this is a no op
                    scenario.post_propagation_hook(**kwargs)
                    '''
                    for asn in scenario.output:
                        
                    	if asn in self.output:
                    		self.output[asn] = self.output[asn] + scenario.output[asn]
                    		self.asns[asn] = self.asns[asn] | scenario.affected_asns[asn]
                    		
                    	else:
                    		self.output[asn] = scenario.output[asn]
                    		self.asns[asn] = scenario.affected_asns[asn]
                    '''
                    total_anns = total_anns + len(scenario.total_anns)
                    print('The number of anns sent: ', len(scenario.total_anns))
                    for prefix, value in scenario.affected_prefixes.items():
                    	self.prefixes[prefix].update(value) 
                    
        '''           
        with (self.save_path).open("w") as f:
            for asn in self.output:
                f.write(str(asn)+',' + str(self.output[asn])+ ','+str(len(self.asns[asn]))+'\n')
        '''
        with (self.save_path2).open("w") as f:
            for prefix in self.prefixes:
                #f.write(prefix+',' + str(max(self.prefixes[prefix]))+'\n')
                f.write(prefix+',' + str(len(self.prefixes[prefix]))+'\n') 
        #print("Total number of announcements sent: ", total_anns)      
        # Reset scenario for next round of trials
        prev_scenario = None
        return subgraphs

    def _aggregate_engine_run_data(self,
                                   subgraphs: Tuple[Subgraph, ...],
                                   **kwargs):
        """For each subgraph, aggregate data

        Some data aggregation is shared to speed up runs
        For example, traceback might be useful across
        Multiple subgraphs
        """

        shared_data: Dict[Any, Any] = dict()
        for subgraph in subgraphs:
            subgraph.aggregate_engine_run_data(shared_data, **kwargs)
