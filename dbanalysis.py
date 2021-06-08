import sqlite3
import pandas as pd
from datetime import datetime
from datetime import timedelta
import sys
import time
import json
import copy

# TODO: WHAT TO DO FOR EMPTY ACTORS?

#TODO: check if each operation exfils cookie in post body or request headers. 
# Exfil requires last change was not made by current actor
#TODO: check if previous actor's cookie is being overwritten or stolen/exfilled


# for each cookie, build a chain of operations ordered by timestamp
# three ways to set, read or modify a cookie, document.cookie in JAVASCRIPT or 
# thru http header in HTTP_REQUESTS
# or set-cookie in server response header in HTTPS_RESPONSES
# For each cookie, sort the operations by timestamp and break ties by comparison 
# of current value with previous value 
# Then, for each cookie, we'll have a chain of operations like delete, read, 
# change or add sorted by timestamp

startTime = time.perf_counter()

class Cookie: # TODO: have an exfil actors property
    def __init__(self, browserId, name, host):
        self.browserId = browserId
        self.name = name
        #host is the site the cookie was set on
        self.host = host
        # list of operations associated with each cookie
        self.operations = []
    def addOperation(self, newOperation): 
        self.operations.append(newOperation)
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
            if op.cookieAccessMethod == "httpRequest" and op.cookieAccessMethod == "httpRequest" and index == 0:
                self.swap(op) # The first op cant be read. Must be an error from openwpm instrumentation. Swap with first non read op.

            if op.cookieAccessMethod ==  "javaScript": # take care of this
                if op.operation == "tbd": # with js cookies, we only need to worry about ops that "write" 
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
                    op.operation = self.operations[index-1].operation
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
zubair research/OpenWPM/datadir/crawl-data.sqlite"):
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
        cookie = Cookie(browserId=cookieRaw[0], name=cookieRaw[1], 
        host=removeProtocolFromUrl(cookieRaw[2]))
        cookies.append(cookie)
    return cookies


def table2frame(cur, tableName):
    query = cur.execute("SELECT * FROM {}".format(tableName))
    cols = [column[0] for column in query.description]
    results = pd.DataFrame.from_records(data = query.fetchall(), columns = cols)
    return results
   
 
def makeJavascriptCookieOperation(actor, value, initial_operation, initial_timestamp, cookie):    
    # TODO: change actor, using callstack, to actual script url
    if cookie.name not in value: # this cookie was not affected
        return None
    # break value into furhter cookie values, expiry and all other attibutes of operation
    cookieAccessMethod = "javaScript"
    timestamp = (datetime.fromisoformat(initial_timestamp[:-1]) - datetime.utcfromtimestamp(0)).total_seconds()
        
    if initial_operation == "set":  
        httpOnly = False # javascript cannot set httpOnly header
        hostOnly = True
        sameSiteStatus = "no_restriction"
        expirationDate = "session"
        operation = "tbd"
        expirationDate = (datetime(2038, 1, 19, 0, 0) - datetime.utcfromtimestamp(0)).total_seconds() 
        # default expiry date is 2038, infinity essentially     
        if value:
            for i in value.split(";"):
                if cookie.name in i: # look for name=value. 
                    # Value can include equal sign
                    cookieValue = i.split("=",1)[1]
                if "domain" in i.lower(): 
                    hostOnly = False
                if "samesite" in i.lower(): 
                    sameSiteStatus = i.split("=",1)[1]
                if "expires" in i:
                    try:
                        expirationDate = datetime.strptime\
                        (i.split("=",1)[1][:-4], "%a, %d %b %Y %H:%M:%S") 
                        # all times are utc
                    except:
                        expirationDate = datetime.strptime\
                        (i.split("=",1)[1][:-4], "%a, %d-%b-%Y %H:%M:%S")
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
            cookieValue = i.split("=")[1]
            break

    expirationDate = "tbd"
    httpOnly = "tbd"
    sameSiteStatus = "tbd"
    hostOnly = "tbd"
    newOperation = Operation(operation, actor, timestamp, cookieAccessMethod, \
                              cookieValue, expirationDate, httpOnly, sameSiteStatus, hostOnly)
    cookie.operations.append(newOperation)
    return 1
        
        
def makeHttpResponseCookieOperation(actor, headers, initial_timestamp, cookie):
    # there can be multiple set-cookie headers
    print("Len")
    cookieHeaderValues = [ header[1] for header in json.loads(headers) if "set-cookie" in header[0].lower()]
    
    print(len(cookieHeaderValues))
    print("")
    
    for cookieHeaderValue in cookieHeaderValues:
        print(cookieHeaderValue) # <--------
        print("")
        if (not cookieHeaderValue) or (cookie.name not in cookieHeaderValue):
            continue
        else:
            for i in cookieHeaderValue.split(";"):
                if cookie.name in i:
                    cookieValue = i.split("=")[1]
                if "expire" in i.lower():
                    try:
                        expirationDate = datetime.strptime\
                        (i.split("=",1)[1][:-4], "%a, %d %b %Y %H:%M:%S") 
                        # all times are utc
                    except ValueError:
                        expirationDate = datetime.strptime\
                        (i.split("=",1)[1][:-4], "%a, %d-%b-%Y %H:%M:%S")
                if "max-age" in i.lower():
                    expirationDate = datetime.utcnow() + timedelta(seconds=int(i.split("=")[1]))
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
                                    
    
    

#%% make all tables pandas dataframes
dbLocation = "/Users/ahnaqvi/Documents/research/\
zubair research/OpenWPM/datadir/crawl-data.sqlite"
# db = loadDb()
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

cookies = makeCookies(db)[:1] #Shrink down list for testing. 
# TODO: Remove later

for cookie in cookies:
    # DETERMINE JAVASCRIPT COOKIES
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
                                           "script_url", "value", "operation", "time_stamp" \
                                           ]]
    filteredResultsJavascript = filteredResultsJavascript.drop_duplicates()
    filteredResultsJavascript = filteredResultsJavascript.sort_values('time_stamp')                                                                          
    
    
    # %%-------------------------------------------
    filteredResultsHttpRequests = httpRequestsTable.merge(httpResponsesTable, how="left", on="visit_id")
    filteredResultsHttpRequests = filteredResultsHttpRequests[(filteredResultsHttpRequests.browser_id_x == cookie.browserId) & ( (filteredResultsHttpRequests.referrer == cookie.host) | (filteredResultsHttpRequests.url_y == cookie.host) )]

    filteredResultsHttpRequests = filteredResultsHttpRequests[["url_x", "headers_x", "time_stamp_x"]]
    filteredResultsHttpRequests = filteredResultsHttpRequests.drop_duplicates()
    filteredResultsHttpRequests = filteredResultsHttpRequests.sort_values('time_stamp_x')
    if filteredResultsHttpRequests.size > 0:
        print("httpRequests")
        print(filteredResultsHttpRequests.size)
    # -------------------------------------------
    filteredResultsHttpResponses = httpResponsesTable.merge(httpRequestsTable, how="left", on="visit_id")
    filteredResultsHttpResponses = filteredResultsHttpResponses[(filteredResultsHttpResponses.browser_id_x == cookie.browserId) & ( (filteredResultsHttpResponses.referrer == cookie.host) | (filteredResultsHttpResponses.referrer == filteredResultsHttpResponses.url_x) )]
    
    filteredResultsHttpResponses = filteredResultsHttpResponses[["url_y", "headers_x", "time_stamp_x"]]
    filteredResultsHttpResponses = filteredResultsHttpResponses.drop_duplicates()
    filteredResultsHttpResponses = filteredResultsHttpResponses.sort_values("time_stamp_x")
    if filteredResultsHttpResponses.size > 0:
        print("httpRepsonses")
        print(filteredResultsHttpResponses.size)
        
    # Now, populate javascript cookie operations
    for index, row in filteredResultsJavascript.iterrows():
        makeJavascriptCookieOperation(row[0], row[1], row[2], row[3], cookie)
    for index, row in filteredResultsHttpRequests.iterrows():
        makeHttpRequestCookieOperation(row[0], row[1], row[2], cookie)
    for index, row in filteredResultsHttpResponses.iterrows():
        makeHttpResponseCookieOperation(row[0], row[1], row[2], cookie)
    cookie.sortOperations()



endTime = time.perf_counter()
m, s = divmod(endTime - startTime, 60)
print(F"{m} minutes and {s} seconds \n")