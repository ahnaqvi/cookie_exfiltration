import sqlite3
import pandas as pd
from datetime import datetime
from datetime import timedelta
import time
import json
import copy
import pickle


#TODO: check if each operation exfils cookie in post body or request headers. 
# Exfil requires last change was not made by current actor
#TODO: check if previous actor's cookie is being overwritten or stolen/exfilled
#TODO: check if exfil is hashed/encrypted? Might be hard if nonce based


# for each cookie, build a chain of operations ordered by timestamp
# three ways to set, read or modify a cookie, document.cookie in JAVASCRIPT or 
# thru http header in HTTP_REQUESTS
# or set-cookie in server response header in HTTPS_RESPONSES
# For each cookie, sort the operations by timestamp and break ties by comparison 
# of current value with previous value 
# Then, for each cookie, we'll have a chain of operations like delete, read, 
# change or add sorted by timestamp

startTime = time.perf_counter()

class Cookie: 
    def __init__(self, browserId, name, host):
        self.browserId = browserId
        self.name = name
        #host is the site the cookie was set on
        self.host = host
        # list of operations associated with each cookie
        self.operations = []
        self.exfilOperations = [] # stores 4-tuple in following format: (index number of first operation that added cookie, index number of suspected exfil operation, whether the exfil was friendly or adversarial, the exfil operation such as delete or read)
    def addOperation(self, newOperation): 
        self.operations.append(newOperation)
    def addExfilOperation(self, natureOfOp, suspiciousOp): # natureOfOp is either adversarial, friendly or unclear depending on if original actor is cookie.host or someone else
        self.exfilOperations.append((natureOfOp, suspiciousOp))
    def swap(self, op):
        for index, op in enumerate(self.operations):
            if op.cookieAccessMethod != "httpRequest":
                if op.operation != "read":
                    tempOperation = copy.deepcopy(op)
                    self.operations.pop(index)
                    self.operations.insert(0, tempOperation)
                    self.operations[0].operation = "add"
        
        
    def sortOperations(self):
        for index, op in enumerate(self.operations):
            # add, read, modify or delete
            
            if op.cookieAccessMethod ==  "javaScript" and op.operation == "read" and index == 0:
                self.swap(op) # The first op cant be read. Must be an error from openwpm instrumentation. Swap with first non read op.
            if op.cookieAccessMethod == "httpRequest" and index == 0:
                self.swap(op) # The first op cant be read. Must be an error from openwpm instrumentation. Swap with first non read op.

            if op.cookieAccessMethod ==  "javaScript": # take care of this
                if op.operation == "tbd": # with js cookies, we only need to worry about ops that "write", denoted by "tbd" 
                    if index == 0:
                        op.operation = "add"
                    else: # either op is delete or modify
                        if op.expirationDate >= op.timestamp:
                            op.operation = "delete"
                        else:
                            op.operation = "modify"
                else: # operation is "read", all operation values are same as before
                    if index > 0:
                        op.cookieValue = self.operations[index-1].cookieValue 
                        op.expirationDate = self.operations[index-1].expirationDate
                        op.httpOnly = self.operations[index-1].httpOnly
                        op.sameSiteStatus = self.operations[index-1].sameSiteStatus
                        op.hostOnly = self.operations[index-1].hostOnly
            if op.cookieAccessMethod == "httpRequest":
                if index > 0:
                    op.expirationDate = self.operations[index-1].expirationDate
                    op.httpOnly = self.operations[index-1].httpOnly
                    op.sameSiteStatus = self.operations[index-1].sameSiteStatus
                    op.hostOnly = self.operations[index-1].hostOnly
            if op.cookieAccessMethod == "htppResponse":
                if index == 0:
                    op.operation = "add"
                else: # read, modify or delete
                    if op.expirationDate >= op.timestamp:
                        op.operation = "delete"
                    else: # read or modify
                        if op.cookieValue == self.operations[index-1].cookieValue:
                            op.operation = "read"
                        else:
                            op.operation = "modify"
    
    def identifyExfilOperations(self):
        if len(self.operations) < 2:
            return
        original_actor = removePathFromUrl(removeProtocolFromUrl(self.operations[0].actor))
        for i in range(1, len(self.operations)): # can use pairwise, less readble though
            actor = removePathFromUrl(removeProtocolFromUrl(self.operations[i].actor))
            # previous_actor = removePathFromUrl(removeProtocolFromUrl(self.operations[i-1].actor))
            # if previous_actor != actor:
            #     self.exfilOperations.append(i)
            host = removePathFromUrl(removeProtocolFromUrl(self.host))
            if actor != original_actor:
                if original_actor == host: # They're snooping with the host's permission
                    natureOfOp = "normal"
                    self.addExfilOperation("normal", self.operations[i]) # can be more complicated. What if trackers sabotage each other?
                elif original_actor in actor or actor in original_actor:
                    natureOfOp = "normal" # sharing with subdomains or other company trackers should be normal
                    self.addExfilOperation(natureOfOp, self.operations[i])
                else: # they are stealing from each other
                    if self.operations[i].operation == "read":
                        natureOfOp = "spy"
                    else:
                        natureOfOp = "sabotage"
                    self.addExfilOperation(natureOfOp, self.operations[i])
                    
            
            
class Operation:
    def __init__(self, operation, actor, timestamp, 
    cookieAccessMethod, cookieValue, expirationDate, httpOnly: bool, 
    sameSiteStatus, hostOnly: bool):
        # operation can be modify, delete, read, or add. Actor is the 
        # website doing the operation. 
        # TODO: What is change_cause and record_type in js_cookie table
        self.operation = operation # add, delete, modfify, read 
        # actor is the current site doing the operation
        self.actor = actor # removePath(removeProtocol(actor))
        # timestamp of the operation
        self.timestamp = timestamp
        # cookieAccessMethod is http or javascript
        self.cookieAccessMethod = cookieAccessMethod
        self.cookieValue = cookieValue
        self.expirationDate = expirationDate
        self.httpOnly = httpOnly
        self.sameSiteStatus = sameSiteStatus
        # https://stackoverflow.com/questions/4688736/\
        # difference-between-host-and-domain-in-cookie-parameters-php/4688833
        # Good explanation ^ of host only
        self.hostOnly = hostOnly
        
    def __str__(self):
        str_repr = F'''operation: {self.operation}
        Actor: {self.actor}
        Time stamp: {self.timestamp}
        Cookie Access Method: {self.cookieAccessMethod}
        Cookie Value: {self.cookieValue}
        Expiration: {self.expirationDate}
        '''
        return str_repr
        
    def __repr__(self):
        return self.__str__()

#%%
def loadDb(dbLocation = "/Users/ahnaqvi/Documents/research/\
zubair research/OpenWPM/datadir/crawl-data_mini.sqlite"):
    '''Load db into memory'''
    persistentDb = sqlite3.connect(dbLocation)
    inMemoryDb = sqlite3.connect(':memory:')
    persistentDb.backup(inMemoryDb)
    return inMemoryDb

def removePathFromUrl(url):
    # reverse string. remove everything before and including slash, reverse and return
    reversed_url = url[::-1]
    index = reversed_url.find("/")
    if index == -1:
        return url
    return removePathFromUrl(reversed_url[index + 1:][::-1])

def removeProtocolFromUrl(url):
    if url.startswith("https://"):
        url = url[8:]
    if url.startswith("http://"):
        url = url[7:]
    if url.startswith("."):
        url = url[1:]
    if url.startswith("www."):
        url = url[4:]
    if url.endswith("/"):
        url = url[:-1]
    return url
    

def makeCookies(db):
    '''Make list of cookies'''
    cur = db.cursor()
    cookiesRaw = cur.execute\
    ("select distinct browser_id, name, host from JAVASCRIPT_COOKIES")
    cookiesRaw = list(cookiesRaw)
    cookies = [] 
    for cookieRaw in cookiesRaw:
        # print(cookieRaw)
        # print("")
        cookie = Cookie(browserId=cookieRaw[0], name=cookieRaw[1], 
        host=removePathFromUrl(removeProtocolFromUrl(cookieRaw[2])))
        
        cookies.append(cookie)
    return cookies


def table2frame(cur, tableName):
    query = cur.execute("SELECT * FROM {}".format(tableName))
    cols = [column[0] for column in query.description]
    results = pd.DataFrame.from_records(data = query.fetchall(), columns = cols)
    return results
   
 
def makeJavascriptCookieOperation(actor, value, initial_operation, initial_timestamp, call_stack, cookie):    
    if cookie.name not in value.split(";"): # this cookie was not affected
        return None
    # break value into furhter cookie values, expiry and all other attibutes of operation
    cookieAccessMethod = "javaScript"
    timestamp = (datetime.fromisoformat(initial_timestamp[:-1]) - datetime.utcfromtimestamp(0)).total_seconds()
        
    if initial_operation == "set":  
        httpOnly = False # javascript cannot set httpOnly header
        hostOnly = True
        sameSiteStatus = "no_restriction"
        expirationDate = "session" # ?
        operation = "tbd"
        expirationDate = (datetime(2038, 1, 19, 0, 0) - datetime.utcfromtimestamp(0)).total_seconds() 
        # default expiry date is 2038, infinity essentially     
        if value:
            print(value)
            for i in value.split(";"):
                # print(i.split("=",1))
                if cookie.name in i.split("=",1): # look for name=value
                    # Value can include equal sign
                    cookieValue = i.split("=",1)[1]
                if "domain" in i.lower(): 
                    hostOnly = False
                if "samesite" in i.lower(): 
                    sameSiteStatus = i.split("=",1)[1]
                if "expires" in i:
                    try:
                        expirationDate = datetime.strptime\
                        (i.split("=",1)[1][:(i.split("=",1)[1]).find('GMT')-1], "%a, %d %b %Y %H:%M:%S") 
                        expirationDate = (expirationDate - datetime.utcfromtimestamp(0)).total_seconds()
                        # all times are utc

                    except:
                        try:
                            expirationDate = datetime.strptime\
                            (i.split("=",1)[1][:(i.split("=",1)[1]).find('GMT')-1], "%a, %d-%b-%Y %H:%M:%S")
                            expirationDate = (expirationDate - datetime.utcfromtimestamp(0)).total_seconds()
                        except:
                            expirationDate = datetime.strptime\
                            (i.split("=",1)[1][:(i.split("=",1)[1]).find('GMT')-1], "%a, %d-%b-%y %H:%M:%S")
                            expirationDate = (expirationDate - datetime.utcfromtimestamp(0)).total_seconds()
    else:
        if initial_operation == "get":
            operation = "read"
            
        else:
            operation = "NA (" + initial_operation + ")"
        cookieValue = "tbd" # value is same as previous operation 
                            # we'll set value when operations list is sorted
        expirationDate = "tbd"
        httpOnly = "tbd"
        sameSiteStatus = "tbd"
        hostOnly = "tbd"
    
    if actor == "":
        if call_stack == "":
            actor = "Unknown"
        else:
            start_index = call_stack.find("@")
            end_index = call_stack.find("\n")
            if start_index == -1 or end_index == -1:
                actor = "Unknown"
            else:
                actor = call_stack[start_index+1 : end_index] # use the lcallstack to determine calling script if unavaialbe otehrwise
                
    newOperation = Operation(operation, actor, timestamp, cookieAccessMethod, \
                              cookieValue, expirationDate, httpOnly, sameSiteStatus, hostOnly)
    cookie.operations.append(newOperation)
    return 1 # success


def makeHttpRequestCookieOperation(actor, headers, initial_timestamp, cookie):
    cookieHeaderValue = [ header[1] for header in json.loads(headers) if header[0].lower() == "cookie" ]
    if not cookieHeaderValue or cookie.name not in cookieHeaderValue[0]:
        return None
    operation = "tbd" # everything else is the same as previous operation
                      # We'll know after all the operations are sorted
    timestamp = (datetime.fromisoformat(initial_timestamp[:-1]) - datetime.utcfromtimestamp(0)).total_seconds()
    cookieAccessMethod = "httpRequest"
    # cookieHeaderValue[0] contains the string of all cookies such as "a=23;b=2;d=2"
    for i in cookieHeaderValue[0].split(";"):
        if cookie.name in i:
            cookieValue = i.split("=", 1)[1]
            break

    expirationDate = "tbd"
    httpOnly = "tbd"
    sameSiteStatus = "tbd"
    hostOnly = "tbd"
    operation = "read"
    newOperation = Operation(operation, actor, timestamp, cookieAccessMethod, \
                              cookieValue, expirationDate, httpOnly, sameSiteStatus, hostOnly)
    cookie.operations.append(newOperation)
    return 1
        
        
def makeHttpResponseCookieOperation(actor, headers, initial_timestamp, cookie):
    # there can be multiple set-cookie headers
    # print("Len response headers: ")
    cookieHeaderValues = [ header[1] for header in json.loads(headers) if "set-cookie" in header[0].lower()]
    # if len(cookieHeaderValues) > 0:
        # print(len(cookieHeaderValues))
        # print("")
    for cookieHeaderValue in cookieHeaderValues:
        if (not cookieHeaderValue) or (cookie.name not in cookieHeaderValue):
            continue
        else:
            for i in cookieHeaderValue.split(";"):
                if cookie.name in i.split("=", 1):
                    # print(i)
                    cookieValue = i.split("=", 1)[1]
                if "expire" in i.lower():
                    try:
                        expirationDate = datetime.strptime\
                        (i.split("=",1)[1][:-4], "%a, %d %b %Y %H:%M:%S") 
                        # all times are utc
                        expirationDate = (expirationDate - datetime.utcfromtimestamp(0)).total_seconds()

                    except ValueError:
                        try:
                            expirationDate = datetime.strptime\
                            (i.split("=",1)[1][:(i.split("=",1)[1]).find('GMT')-1], "%a, %d-%b-%Y %H:%M:%S")
                            expirationDate = (expirationDate - datetime.utcfromtimestamp(0)).total_seconds()
                        except ValueError:
                            expirationDate = datetime.strptime\
                            (i.split("=",1)[1][:(i.split("=",1)[1]).find('GMT')-1], "%a, %d-%b-%y %H:%M:%S")
                            expirationDate = (expirationDate - datetime.utcfromtimestamp(0)).total_seconds()
                            
                if "max-age" in i.lower():
                    expirationDate = datetime.utcnow() + timedelta(seconds=int(i.split("=")[1]))
                    expirationDate = (expirationDate - datetime.utcfromtimestamp(0)).total_seconds()

                if "domain=" in i.lower():
                    # https://stackoverflow.com/questions/12387338/what-is-a-host-only-cookie
                    if cookie.host != removeProtocolFromUrl(i.split("=", 1)[1]):
                        hostOnly = False
                        cookie.host = removeProtocolFromUrl(i.split("=", 1)[1])
                    else:
                        hostOnly = True
                if "httponly" == i.lower():
                    httpOnly = True
                if "samesite" in i.lower().split("="):
                    sameSiteStatus = i.split("=")[1]
            if not 'cookieValue' in locals():
                cookieValue = ""
            if not 'expirationDate' in locals():
                expirationDate = (datetime(2038, 1, 19, 0, 0) - datetime.utcfromtimestamp(0)).total_seconds()
            if not 'httpOnly' in locals():
                httpOnly = False
            if not 'hostOnly' in locals():
                hostOnly = True
            if not 'sameSiteStatus' in locals():
                sameSiteStatus = "lax"
            cookieAccessMethod = "httpResponse"
            timestamp = (datetime.fromisoformat(initial_timestamp[:-1]) - datetime.utcfromtimestamp(0)).total_seconds()
            operation = "tbd"
        newOperation = Operation(operation, actor, timestamp, cookieAccessMethod, cookieValue, expirationDate, httpOnly, sameSiteStatus, hostOnly)
        cookie.addOperation(newOperation)
                                    
    
    
def main():
    # make all tables pandas dataframes
    dbLocation = "/Users/ahnaqvi/Documents/research/\
zubair research/OpenWPM/datadir/crawl-data_mini.sqlite"
    db = sqlite3.connect(dbLocation)
    cur = db.cursor()
    javascript_table = table2frame(cur, "JAVASCRIPT")
    javascript_table["document_url"] = javascript_table["document_url"].apply(removeProtocolFromUrl)
    
    httpRequestsTable = table2frame(cur, "HTTP_REQUESTS")
    httpRequestsTable["url"] = httpRequestsTable["url"].apply(removeProtocolFromUrl)
    httpRequestsTable["top_level_url"] = httpRequestsTable["top_level_url"].apply(removeProtocolFromUrl)
    httpRequestsTable["referrer"] = httpRequestsTable["referrer"].apply(removeProtocolFromUrl)
    httpResponsesTable = table2frame(cur, "HTTP_RESPONSES")
    httpResponsesTable["url"] = httpResponsesTable["url"].apply(removeProtocolFromUrl)
    #%%
    
    cookies = makeCookies(db) #Shrink down list for testing. 
    # print(len(cookies))
    
    for cookie in cookies:
        # DETERMINE JAVASCRIPT COOKIES
        # print(time.localtime())
        filteredResultsJavascript = javascript_table[\
                                        (javascript_table.symbol \
                                         == \
                                         "window.document.cookie") \
                                        & (javascript_table.browser_id \
                                           == \
                                          cookie.browserId) \
                                        & ( \
                                           javascript_table.document_url \
                                           == \
                                           cookie.host) ][[ \
                                               "script_url", "value", "operation", "time_stamp", "call_stack" \
                                               ]]
        filteredResultsJavascript = filteredResultsJavascript.drop_duplicates()
        filteredResultsJavascript = filteredResultsJavascript.sort_values('time_stamp')                                                                          
        
        
        # %%-------------------------------------------
        filteredResultsHttpRequests = httpRequestsTable.merge(httpResponsesTable, how="left", on="visit_id")
        filteredResultsHttpRequests = filteredResultsHttpRequests[(filteredResultsHttpRequests.browser_id_x == cookie.browserId) & ( (filteredResultsHttpRequests.referrer == cookie.host) | (filteredResultsHttpRequests.url_y == cookie.host) )]
    
        filteredResultsHttpRequests = filteredResultsHttpRequests[["url_x", "headers_x", "time_stamp_x"]]
        filteredResultsHttpRequests = filteredResultsHttpRequests.drop_duplicates()
        filteredResultsHttpRequests = filteredResultsHttpRequests.sort_values('time_stamp_x')
        
        # -------------------------------------------
        filteredResultsHttpResponses = httpResponsesTable.merge(httpRequestsTable, how="left", on="visit_id")
        filteredResultsHttpResponses = filteredResultsHttpResponses[(filteredResultsHttpResponses.browser_id_x == cookie.browserId) & ( (filteredResultsHttpResponses.referrer == cookie.host) | (filteredResultsHttpResponses.referrer == filteredResultsHttpResponses.url_x) )]
        
        filteredResultsHttpResponses = filteredResultsHttpResponses[["url_y", "headers_x", "time_stamp_x"]]
        filteredResultsHttpResponses = filteredResultsHttpResponses.drop_duplicates()
        filteredResultsHttpResponses = filteredResultsHttpResponses.sort_values("time_stamp_x")
        
            
        # Now, populate javascript cookie operations
        for index, row in filteredResultsJavascript.iterrows():
            makeJavascriptCookieOperation(row[0], row[1], row[2], row[3], row[4], cookie)
        for index, row in filteredResultsHttpRequests.iterrows():
            makeHttpRequestCookieOperation(row[0], row[1], row[2], cookie)
        for index, row in filteredResultsHttpResponses.iterrows():
            makeHttpResponseCookieOperation(row[0], row[1], row[2], cookie)
        cookie.sortOperations()
        cookie.identifyExfilOperations()
    
    
    
    endTime = time.perf_counter()
    m, s = divmod(endTime - startTime, 60)
    print("FINISHED! PICKLING NOW...")
    with open('pickled_data', 'wb') as f:
        pickle.dump(cookies,f)
    print(F"{m} minutes and {s} seconds \n")
    

if __name__ == "__main__":
    main()
    
