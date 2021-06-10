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

#%% 
hosts = []
for cookie in cookies:
    if cookie.host not in hosts:
        hosts.append(cookie.host)
print(hosts)

#%%
cookie_exfil_list_lens = []

for cookie in cookies:
    cookie_exfil_list_lens.append(len(cookie.exfilOperations))
    if len(cookie.exfilOperations) > 240:
        print(len(cookie.exfilOperations))
        print(cookie.host)
        most_exfil_list = cookie.exfilOperations
non_zero_cookie_exfil_list_lens = [i for i in cookie_exfil_list_lens if i != 0]

#%% 
hasSpyOrSabotage = []
for cookie in cookies:
    if len(cookie.exfilOperations) > 0:
        for op_type, op in cookie.exfilOperations:
            if op_type != "normal":
                if cookie not in hasSpyOrSabotage:
                    hasSpyOrSabotage.append(cookie)
#%%

def checkSameSiteStatusChange(operationsList):
    if len(operationsList) < 2:
        return []
    suspiciousOperations = []
    original_actor = operationsList[0].actor
    original_sameSiteStatus = operationsList[0].sameSiteStatus
    for op in operationsList[1:]:
        if op.sameSiteStatus != original_sameSiteStatus:
            if op.actor != original_actor:
                suspiciousOperations.append((original_sameSiteStatus, op.sameSiteStatus, op.actor))
    return suspiciousOperations

sameSiteExfilCookies = []
for cookie in cookies:
    suspicious_operations = checkSameSiteStatusChange(cookie.operations)
    if len(suspicious_operations) > 0:
        sameSiteExfilCookies.append((cookie, suspicious_operations))
# %%

def checkExpirationChange(operationsList):
    if len(operationsList) < 2:
        return []
    suspiciousOperations = []
    original_actor = operationsList[0].actor
    original_expirationDate = operationsList[0].expirationDate
    for op in operationsList[1:]:
        if op.expirationDate != original_expirationDate:
            if op.actor != original_actor:
                suspiciousOperations.append((original_expirationDate, op.expirationDate, op.actor))
    return suspiciousOperations
 
expirationExfilCookies = []
for cookie in cookies:
    suspicious_operations = checkExpirationChange(cookie.operations)
    if len(suspicious_operations) > 0:
        expirationExfilCookies.append((cookie, suspicious_operations))
       
#%%
def hostOnlyChange(operationsList):
    if len(operationsList) < 2:
        return []
    suspiciousOperations = []
    original_actor = operationsList[0].actor
    original_hostOnly = operationsList[0].hostOnly
    for op in operationsList[1:]:
        if op.hostOnly != original_hostOnly:
            if op.actor != original_actor:
                suspiciousOperations.append((original_hostOnly, op.hostOnly, op.actor))
    return suspiciousOperations

hostOnlyExfilCookies = []
for cookie in cookies:
    suspicious_operations = hostOnlyChange(cookie.operations)
    if len(suspicious_operations) > 0:
        hostOnlyExfilCookies.append((cookie, suspicious_operations))
        