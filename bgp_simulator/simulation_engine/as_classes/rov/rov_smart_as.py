import sys
sys.path.append(
    '/home/zhao/Shujie/Routing_traffic/coding/bgpsimulator/bgp_simulator_pkg/bgp_simulator_pkg')

BASEPATH = '/home/zhao/Shujie/Routing_traffic/coding/'
sys.path.append(BASEPATH)

from feature_extractor import compute_statistics_for_benign_conflicts, compute_pfx_distance
from load_pub_data import CaidaAsOrg, CaidaAsRelPc, CaidaAsRelCp, CaidaAsRelPp, GlobalHegeDict, LocalHegeDict, IrrDatabase, As2prefixesDict
import multiprocessing
from ..bgp import BGPSimpleAS
from ...announcement import Announcement as Ann
import datetime
import pickle
import os
import numpy as np
from typing import Optional
import time
from copy import deepcopy
import sklearn.tree._classes
import joblib


# need to improve because of low speed!! For example, using multiple threads for feature computation.

roa_as2prefixes_dicts = dict()
as2prefixes_dicts = dict()
pubdata = dict()
output = open('/home/zhao/Shujie/Routing_traffic/coding/bgpsimulator/detection_delay.benign_conflict.res', 'w')


def load_clf():
    clf = None
    with open(BASEPATH+'./dt_classifier.pkl', 'rb') as f:
        clf = pickle.load(f)
    scaler = joblib.load(BASEPATH+'./dt_scaler.gz')
    pubdata['clf'] = clf
    pubdata['scaler'] = scaler
    with open(BASEPATH+'./bc_clf_res.p', 'rb') as f:
        bc_clf_dict = pickle.load(f)
    for pfx in bc_clf_dict:
    	pubdata[pfx] = bc_clf_dict[pfx]


class ROVSmartAS(BGPSimpleAS):
    """An AS that deploys SROV"""

    name: str = "ROVSmartAS"

    def _valid_ann(self, ann: Ann, *args, **kwargs) -> bool:  # type: ignore
        """Returns announcement validity through smart validator
        """
        '''
        providers = CaidaAsRelCp.get(str(ann.seed_asn))
        if str(self.asn) in providers:
        	return True
        '''

        if not super(ROVSmartAS, self)._valid_ann(ann, *args, **kwargs):  # Filtering BGP loop
            return False
        
        if not ann.invalid_by_roa:
            #print('Valid')
            return True
        
        if len(pubdata) == 0:
            load_clf()
        
        clf = pubdata['clf']
        scaler = pubdata['scaler']
        timestamp = ann.timestamp

        start = time.monotonic()
        prefix = ann.prefix
        label = pubdata[prefix]
        
        if label == 1: return True
        else: return False
        
        asID = int(ann.origin)
        vrpID = int(ann.roa_origin)
        origin_matching = 0
        if asID == vrpID:
            origin_matching = 1
        #print(len(CaidaAsOrg), len(CaidaAsRelPc), len(As2prefixesDict), len(LocalHegeDict), len(IrrDatabase))
        OriginMatch, IRR, Parent, SameOrg, PC, Depen = compute_statistics_for_benign_conflicts(
            origin_matching, CaidaAsOrg, CaidaAsRelPc, As2prefixesDict, timestamp, prefix, asID, vrpID, None, LocalHegeDict, IrrDatabase)
        a, b, c, d, e, f = 1, 1, 1.0, 0.2, 0.3, 0.6
        
        confi_score = a*OriginMatch + b*IRR + c*Parent + d*SameOrg + e*PC + f*Depen

        if origin_matching == 1:
            distance = 0.0
        else:
            distance = compute_pfx_distance(
                As2prefixesDict, prefix, asID, None)
        if distance == None:
            distance = 1.0
        
        data = [confi_score, distance]
        X_test = np.array(data).reshape(1, 2)

        X_test = scaler.transform(X_test)
        label = clf.predict(X_test)[0]
        end = time.monotonic()
        output.write(str(end-start)+'\n')
        
        #print(OriginMatch, IRR, Parent, SameOrg, PC, Depen, distance, label)
        if label == 1:
            return True
        
        return False
