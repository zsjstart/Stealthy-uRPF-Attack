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
from enums import Prefixes
import multiprocessing
import time
import pandas as pd

sys.path.append(
    '/home/zhao/Shujie/Routing_traffic/coding/bgpsimulator/bgp_simulator_pkg/bgp_simulator_pkg')

BASEPATH = '/home/zhao/Shujie/Routing_traffic/coding/'
sys.path.append(BASEPATH)

PubData = dict()


class Simulation:
    """Runs simulations for BGP attack/defend scenarios"""

    def __init__(self,
                 # for each percent runing num_trials
                 percent_adoptions: Tuple[float, ...] = (1.0,),
                 output_path: Path = Path(
                     "/home/zhao/Shujie/Routing_traffic/coding/bgpsimulator/graphs"),
                 subgraphs: Tuple[Subgraph, ...] = tuple([
                     Cls() for Cls in  # type: ignore
                     Subgraph.subclasses if Cls.name]),  # type: ignore
                 num_trials: int = 1,  # default value is one case in a scenario
                 propagation_rounds: int = 1,
                 parse_cpus: int = 1,
                 # urpf_asns: Optional[set] = set(),
                 ):
        """Downloads relationship data, runs simulation

        Graphs -> A list of graph classes
        graph_path: Where to store the graphs. Should be a .tar.gz file
        assert_pypy: Ensures you are using pypy if true
        mp_method: Multiprocessing method
        """

        self.percent_adoptions: Tuple[float, ...] = percent_adoptions

        self.subgraphs: Tuple[Subgraph, ...] = subgraphs

        self.propagation_rounds: int = propagation_rounds
        self.output_path: Path = output_path
        self.parse_cpus: int = parse_cpus

        self.scenarios: Tuple[Scenario, ...] = tuple(
            [SubprefixHijack(AdoptASCls=BGPSimpleAS,
                             attacker_asns={None}, victim_asns={None})]
        )  # ROVSmartAS, BenignConflict, PrefixHijack

        self.save_path: Path = Path(
            "/home/zhao/Shujie/Routing_traffic/coding/bgpsimulator/stealthy_hijack_sim_uRPF.csv")

        # All scenarios must have a uni que graph label
        labels = [x.graph_label for x in self.scenarios]
        assert len(labels) == len(set(labels)), "Scenario labels not unique"

        # Done here so that the caida files are cached
        # So that multiprocessing doesn't interfere with one another
        CaidaCollector().run()

        '''
        self.urpf_attack_infos = []
        with open('/home/zhao/Shujie/Routing_traffic/coding/targeted_uRPF_attacks.dat', "r") as filehandle:
            filecontents = filehandle.readlines()
            for i, line in enumerate(filecontents):
                if i == 0: continue
                fields = line.strip('\n').split(',')
                urpf_asn,as2,as3,as666 = fields
                self.urpf_attack_infos.append((int(urpf_asn),int(as2),int(as3),int(as666)))
        print(len(self.urpf_attack_infos))

        self.num_trials: int = len(self.urpf_attack_infos)
        '''

        self.urpf_asns: set = self.load_uRPF_asns(self.percent_adoptions[0])

        # self.num_trials: int = len(self.urpf_asns)
        self.num_trials: int = 1

        self.direct_vulnerable_urpf = defaultdict(set)
        self.indirect_vulnerable_urpf = defaultdict(set)

        self.as2_set = defaultdict(set)
        self.as3_set = defaultdict(set)
        self.as2_as3_pair = defaultdict(lambda: defaultdict(set))
        self.num_attacks = dict()
        
        
        self.as666_set = defaultdict(set)
        self.attacks_set = defaultdict(set)
        self.affected_customer_set = defaultdict(set)

    def load_uRPF_asns(self, percent_adopt):

        # Hypothetical simulations
        engine = CaidaCollector(BaseASCls=BGPSimpleAS,
                                GraphCls=SimulationEngine,
                                ).run(tsv_path=None)
        urpf_asns = list()
        subcategories = ("stub_or_mh_asns", "etc_asns", "input_clique_asns")
        for subcategory in subcategories:
            asns = getattr(engine, subcategory)
            '''
            k = int(len(asns) * percent_adopt)
            asns = tuple(asns)
            random.seed(1)
            urpf_asns.extend(random.sample(asns, k))  # type: ignore
            '''
            urpf_asns.extend(asns)

        return urpf_asns

        '''
        # Real-world simulations
        urpf_asns = set()
        with open('/home/zhao/Shujie/Routing_traffic/coding/urpf_present_asn.res', "r") as filehandle:
            filecontents = filehandle.readlines()
            for i, line in enumerate(filecontents):
                fields = line.strip('\n').split(',')
                urpf_asns.add(int(fields[0]))

        return urpf_asns
        '''

    def run_with_timeout(self, func, timeout):
        process = multiprocessing.Process(target=func)
        process.start()
        # Wait for the process to complete or timeout
        process.join(timeout=timeout)
        if process.is_alive():
            print("Process timed out! Terminating...")
            process.terminate()

            return False
        else:
            print("Process completed successfully.")
            return True

    def run(self):
        """Runs the simulation and write the data"""

        self._get_data()
        # self._write_data()

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

    #################################
    # Identify network nodes that are vulnerable to stealthy hijacks without simulations
    #################################

    def _check_vulnerable_asn(self, urpf_asn, info, checked_asn):
        found = False
        for provider in info[checked_asn]['providers']:
            if len(info[provider]['customers']) > 1 and (len(info[provider]['providers']) > 0 or len(info[provider]['peers']) > 0):
                for provider_provider in info[provider]['providers']:
                    if provider_provider in set(info[checked_asn]['providers']) or provider_provider in set(info[checked_asn]['customers']) or provider_provider in set(info[checked_asn]['peers']):
                        continue

                    found = True
                    self.as2_set[urpf_asn].add(provider)
                    self.as3_set[urpf_asn].add(provider_provider)
                    
                    self.as2_as3_pair[urpf_asn][provider].add(provider_provider)
                    

                for provider_peer in info[provider]['peers']:
                    if provider_peer in set(info[checked_asn]['providers']) or provider_peer in set(info[checked_asn]['customers']) or provider_peer in set(info[checked_asn]['peers']):
                        continue
                        
                    found = True
                    self.as2_set[urpf_asn].add(provider)
                    self.as3_set[urpf_asn].add(provider_peer)
                    
                    self.as2_as3_pair[urpf_asn][provider].add(provider_peer)

        return found

    def iterate_checking(self, checked_asn, urpf_asn, info):
        providers = info[checked_asn]['providers']

        if len(providers) == 0:
            return
        if checked_asn != urpf_asn and self._check_vulnerable_asn(urpf_asn, info, checked_asn):
            self.indirect_vulnerable_urpf[urpf_asn] = True
            return

        for provider in providers:
            self.iterate_checking(provider, urpf_asn, info)

    def first_checking(self, urpf_asn, info):
        providers = info[urpf_asn]['providers']

        if len(providers) == 0:
            return
        if self._check_vulnerable_asn(urpf_asn, info, urpf_asn):
            self.direct_vulnerable_urpf[urpf_asn] = True
            return

    def _get_customer_set(self, asn, info, customer_zone):
    	
        for customer in info[asn]['customers']:
            if customer in customer_zone:
                continue
            customer_zone.add(customer)
            self._get_customer_set(customer, info, customer_zone)
            

    def _preprocess(self, engine: SimulationEngine):
        """Gets the outcomes of all ASes"""

        info = defaultdict(dict)
        
        tier1_networks = [174, 209, 286, 701, 1239, 1299, 2828, 2914, 3257, 3320, 3356, 3491, 5511, 6453, 6461, 6762, 6830, 7018, 12956]
        tier1_customers = defaultdict(set)
        tier1_peers = defaultdict(set)
        total_tier1_customers = set()
        
        for i, as_obj in enumerate(engine.as_dict.values()):
            obj = as_obj.__to_yaml_dict__()
            info[as_obj.asn]['providers'] = obj['providers']
            info[as_obj.asn]['customers'] = obj['customers']
            info[as_obj.asn]['peers'] = obj['peers']
            info[as_obj.asn]['obj'] = as_obj
            if as_obj.asn in tier1_networks:
            	
            	tier1_customers[as_obj.asn].update(obj['customers'])
            	tier1_peers[as_obj.asn].update(obj['peers'])
            	total_tier1_customers.update(obj['customers'])
            
            
            #tier1_customers -= set(tier1_networks)
            with open('/home/zhao/Shujie/Routing_traffic/coding/bgpsimulator/stealthy_hijacks_res/urpf_res/tier1_customers.pkl', 'wb') as ifile:
                    pickle.dump(total_tier1_customers, ifile)
            
        N = 0
        for asn in tier1_networks:
        	
        	customers = len(tier1_customers[asn])
        	peers = len(tier1_peers[asn])
        	N += customers * peers
        print("attacks: ", N)
            
          

        urpf_asns = self.urpf_asns

        for urpf_asn in urpf_asns:
            
            if urpf_asn not in info:  # Necessary code
                continue
                
            self.first_checking(urpf_asn, info)
            
            
            if self.direct_vulnerable_urpf.get(urpf_asn):
                n = 0
                for as2 in self.as2_set[urpf_asn]:
                    self.as666_set[urpf_asn].update(info[as2]['customers'])
                    
                    victims = self.as2_as3_pair[urpf_asn].get(as2)
                    attackers = info[as2]['customers']
                    
                    n = n + len(victims) * len(attackers)
                
                print("Num of attacks: ", urpf_asn, n)
                self.num_attacks[urpf_asn] = n
                
                customer_zone = set()
                self._get_customer_set(urpf_asn, info, customer_zone)
                self.affected_customer_set[urpf_asn] = customer_zone
                continue

            
            self.iterate_checking(urpf_asn, urpf_asn, info)

            if self.indirect_vulnerable_urpf.get(urpf_asn):
                n = 0
                for as2 in self.as2_set[urpf_asn]:
                    self.as666_set[urpf_asn].update(info[as2]['customers'])
                    victims = self.as2_as3_pair[urpf_asn].get(as2)
                    attackers = info[as2]['customers']
                    n = n + len(victims) * len(attackers)
                
                print("Num of attacks: ", urpf_asn, n)
                self.num_attacks[urpf_asn] = n
                customer_zone = set()
                self._get_customer_set(urpf_asn, info, customer_zone)
                self.affected_customer_set[urpf_asn] = customer_zone
                
        
        with open('/home/zhao/Shujie/Routing_traffic/coding/bgpsimulator/stealthy_hijacks_res/urpf_res/num_attacks.pkl', 'wb') as ifile:
        	pickle.dump(self.num_attacks, ifile)    
            
            


############################
# Data Aggregation Methods # input clique: 174 209 286 701 1239 1299 2828 2914 3257 3320 3356 3491 5511 6453 6461 6762 6830 7018 12956
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

        
        print('Total number of ASes on the simulator: ', len(engine.as_dict))
        print('Number of stub_or_mh_asns: ', len(engine.stub_or_mh_asns))
        print('Number of input_clique_asns: ', len(engine.input_clique_asns))
        print('Number of etc_asns: ', len(engine.etc_asns))
        

        # Must deepcopy here to have the same behavior between single
        # And multiprocessing
        if single_proc:
            # print('subgraphs: ', self.subgraphs)
            subgraphs = deepcopy(self.subgraphs)
        else:
            subgraphs = self.subgraphs

        prev_scenario = None

        for percent_adopt, trial in percent_adopt_trials:

            for scenario in self.scenarios:
                '''
                # Deep copy scenario to ensure it's fresh
                # Since certain things like announcements change round to round
                scenario = deepcopy(scenario)

                print(
                    f"{percent_adopt * 100}% {scenario.graph_label}, #{trial}", end="                             " + "\r")

                # Change AS Classes, seed announcements before propagation

                # reset the attack asns
                scenario.attacker_asns = set(self.urpf_asns)

                print('Number of urpf asns: ', len(scenario.attacker_asns))

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

                self._preprocess(engine)

                print('URPF asns (direct) vulnerable to stealthy attacks: ', len(
                    self.direct_vulnerable_urpf))
                print('URPF asns (indirect) vulnerable to stealthy attacks: ', len(
                    self.indirect_vulnerable_urpf))

                '''
                with open('/home/zhao/Shujie/Routing_traffic/coding/bgpsimulator/stealthy_hijacks_res/urpf_res/scenario.direct_vulnerable_urpf.pkl', 'wb') as ifile:
                    pickle.dump(self.direct_vulnerable_urpf, ifile)

                with open('/home/zhao/Shujie/Routing_traffic/coding/bgpsimulator/stealthy_hijacks_res/urpf_res/scenario.indirect_vulnerable_urpf.pkl', 'wb') as ifile:
                    pickle.dump(self.indirect_vulnerable_urpf, ifile)

                with open('/home/zhao/Shujie/Routing_traffic/coding/bgpsimulator/stealthy_hijacks_res/urpf_res/scenario.as2_set.pkl', 'wb') as ifile:
                    pickle.dump(self.as2_set, ifile)

                with open('/home/zhao/Shujie/Routing_traffic/coding/bgpsimulator/stealthy_hijacks_res/urpf_res/scenario.as3_set.pkl', 'wb') as ifile:
                    pickle.dump(self.as3_set, ifile)

                with open('/home/zhao/Shujie/Routing_traffic/coding/bgpsimulator/stealthy_hijacks_res/urpf_res/scenario.as666_set.pkl', 'wb') as ifile:
                    pickle.dump(self.as666_set, ifile)

                with open('/home/zhao/Shujie/Routing_traffic/coding/bgpsimulator/stealthy_hijacks_res/urpf_res/scenario.affected_customer_set.pkl', 'wb') as ifile:
                    pickle.dump(self.affected_customer_set, ifile)
                '''
                

        '''         
        with (self.save_path).open("w") as f:
            for asn in self.output:
                f.write(str(asn)+',' + str(self.output[asn])+ ','+str(len(self.asns[asn]))+'\n')
        '''
        # df = pd.DataFrame(csv_data)
        # df.to_csv(self.save_path, index=False)

        # print("Total number of announcements sent: ", total_anns)
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
