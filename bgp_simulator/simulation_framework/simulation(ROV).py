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


from simulation_engine import ROVPPV1LiteSimpleAS
from simulation_engine import ROVPPAnn


sys.path.append(
    '/home/zhao/Shujie/Routing_traffic/coding/bgpsimulator/bgp_simulator_pkg/bgp_simulator_pkg')

BASEPATH = '/home/zhao/Shujie/Routing_traffic/coding/'
sys.path.append(BASEPATH)

PubData = dict()


class Simulation:
    """Runs simulations for BGP attack/defend scenarios"""

    def __init__(self,
                 # (0.05, 0.1, 0.3, 0.5, 0.7, 0.9,) #for each percent runing num_trials
                 scenarios: Tuple[Scenario, ...] = tuple([SubprefixHijack(AdoptASCls=ROVPPV1LiteSimpleAS, AnnCls = ROVPPAnn, attacker_asns={133233}, victim_asns={262693})]),  
                 percent_adoptions: Tuple[float, ...] = (0.1, ), #0.1, 0.3, 0.5, 0.7, 0.9,  
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

        self.subgraphs: Tuple[Subgraph, ...] = subgraphs

        self.propagation_rounds: int = propagation_rounds
        self.output_path: Path = output_path
        self.parse_cpus: int = parse_cpus

        self.scenarios: Tuple[Scenario, ...] = scenarios  # ROVSmartAS, ROVSimpleAS, BenignConflict, PrefixHijack

        self.save_path: Path = None

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
        '''

        self.num_trials: int = num_trials

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

        
        

        # Must deepcopy here to have the same behavior between single
        # And multiprocessing
        if single_proc:
            # print('subgraphs: ', self.subgraphs)
            subgraphs = deepcopy(self.subgraphs)
        else:
            subgraphs = self.subgraphs

        prev_scenario = None

        csv_data = defaultdict(dict)
        for percent_adopt in self.percent_adoptions:
            csv_data[percent_adopt] = {
                'Attacker(asn)': [],
                'Victim(asn)': [],
                'Affected(%)': [],
                'Direct(%)': [],
                'Indirect(%)': [],
            }
        
        rates = []
        for percent_adopt, trial in percent_adopt_trials:

            for scenario in self.scenarios:
                
                infos = {
                'Adopting_asns': [],
                'Attacker_asn': '',
                'Victim_asn': '',
                'Directly_affected': [],
                'Indirectly_affected': [],
                'Vulnerable_paths': [], 
                }
                
                # Deep copy scenario to ensure it's fresh
                # Since certain things like announcements change round to round
                scenario = deepcopy(scenario)

                print(
                    f"{percent_adopt * 100}% {scenario.graph_label}, #{trial}", end="                             " + "\r")

                # Change AS Classes, seed announcements before propagation

                scenario.setup_engine(engine, percent_adopt, prev_scenario)

                print("attacker and victim asns: ",
                      scenario.attacker_asns, scenario.victim_asns)

                # scenario._assess_uRPF_asns(engine)

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
                    csv_data[percent_adopt]['Attacker(asn)'].append(
                        list(scenario.attacker_asns)[0])
                    csv_data[percent_adopt]['Victim(asn)'].append(
                        list(scenario.victim_asns)[0])
                        
                    indirect = 0
                    direct = 0
                    
                    for asn in scenario.output:
                    	if scenario.output[asn] == 'indirect': indirect = indirect + 1
                    	elif scenario.output[asn] == 'direct': direct = direct + 1
                    	
                    csv_data[percent_adopt]['Affected(%)'].append((indirect+direct)/(len(engine.as_dict)))
                    csv_data[percent_adopt]['Direct(%)'].append((direct)/(len(engine.as_dict)))
                    csv_data[percent_adopt]['Indirect(%)'].append((indirect)/(len(engine.as_dict)))
                    
                    print("Num of output: ", len(scenario.output))
                    '''
                    
                    
                    csv_data[percent_adopt]['Attacker(asn)'].append(
                        list(scenario.attacker_asns)[0])
                    csv_data[percent_adopt]['Victim(asn)'].append(
                        list(scenario.victim_asns)[0])
                    csv_data[percent_adopt]['Affected(%)'].append(
                        len(scenario.affected_asns)/(len(engine.as_dict)-scenario.num_no_anns))
                    csv_data[percent_adopt]['Direct(%)'].append(len(scenario.affected_prefixes[Prefixes.SUBPREFIX.value])/(len(engine.as_dict)-scenario.num_no_anns))
                    csv_data[percent_adopt]['Indirect(%)'].append(len(scenario.affected_prefixes[Prefixes.PREFIX.value])/(len(engine.as_dict)-scenario.num_no_anns))

                    print("Proportion of directly affected networks: ", len(scenario.affected_prefixes[Prefixes.SUBPREFIX.value])/(len(engine.as_dict)-scenario.num_no_anns))
                    print("Proportion of indirectly affected networks: ", len(scenario.affected_prefixes[Prefixes.PREFIX.value])/(len(engine.as_dict)-scenario.num_no_anns))
                    print("Number of no announcements: ", scenario.num_no_anns)
                    print('Number of networks deploying ROV: ', len(scenario.adopting_asns))
                    
                    infos['Adopting_asns'] = scenario.adopting_asns
                    infos['Attacker_asn'] = list(scenario.attacker_asns)[0]
                    infos['Victim_asn'] = list(scenario.victim_asns)[0]
                    infos['Directly_affected'] = list(scenario.affected_prefixes[Prefixes.SUBPREFIX.value])
                    infos['Indirectly_affected'] = list(scenario.affected_prefixes[Prefixes.PREFIX.value])
                    infos['Vulnerable_paths'] = list(scenario.affected_paths)
                    
                    with open("/home/zhao/Shujie/Routing_traffic/coding/bgpsimulator/stealthy_hijacks_res/simulation_data/infos("+str(percent_adopt)+"+"+str(trial)+").pkl", "wb") as ifile:
                    	pickle.dump(infos, ifile)
                    
                    

                   

        '''         
        with (self.save_path).open("w") as f:
            for asn in self.output:
                f.write(str(asn)+',' + str(self.output[asn])+ ','+str(len(self.asns[asn]))+'\n')
        '''

        for percent_adopt in self.percent_adoptions:
            df = pd.DataFrame(csv_data[percent_adopt])
            #self.save_path = Path("/home/zhao/Shujie/Routing_traffic/coding/bgpsimulator/stealthy_hijacks_res/degree_centrality_sim/stealthy_hijack_sim_ROV."+str(percent_adopt)+".csv")
            #df.to_csv(self.save_path, index=False)
            
        '''
        self.save_path = Path(
            "/home/zhao/Shujie/Routing_traffic/coding/bgpsimulator/stealthy_hijacks_res/realistic_simulations/stealthy_hijack_sim_rovista_ROV_max_direct_asns.csv")
        with (self.save_path).open("w") as f:
            for asn in scenario.affected_prefixes[Prefixes.SUBPREFIX.value]:
                f.write(str(asn)+'\n')
        '''
        
        '''        
        self.save_path = Path(
            "/home/zhao/Shujie/Routing_traffic/coding/bgpsimulator/stealthy_hijacks_res/various_ROV_deployment_networks/stealthy_hijack_sim_ROV_tier1_max_indirect_paths.csv")
        with (self.save_path).open("w") as f:
            for path in scenario.affected_paths:
                f.write(','.join(map(str, list(path)))+'\n')
        '''
        
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
