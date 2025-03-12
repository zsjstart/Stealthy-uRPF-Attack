from pathlib import Path
import sys
from simulation_framework import SubprefixHijack


sys.path.append('/home/zhao/Shujie/Routing_traffic/coding/bgpsimulator/bgp_simulator_pkg/bgp_simulator_pkg')

from simulation_framework import Simulation
import load_pub_data


def main():
    """Runs the defaults"""

    #Simulation(output_path=Path("/home/zhao/Shujie/Routing_traffic/coding/bgpsimulator/graphs").expanduser()).run()
    #load_pub_data.load_pub_data()
    Simulation().run()
    #Simulation(scenario = tuple([SubprefixHijack(AdoptASCls=ROVPPV1LiteSimpleAS, AnnCls = ROVPPAnn, attacker_asns=None, victim_asns=None)])).run()

if __name__ == "__main__":
    main()
