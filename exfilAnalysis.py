import pickle
from dbanalysis import *

cookies = pickle.load(open('pickled_data', 'rb'))
for cookie in cookies:
    if len(cookie.exfilOperations) > 0:
        for op_type, op in cookie.exfilOperations:
            if op_type == "sabotage":
                print(cookie.operations[0].actor)
                print("---------")
                print(op.actor)
                print("\n\n")
            