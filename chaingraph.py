## Reference: https://github.com/BusinessOptics/dash_interactive_graphviz/blob/master/usage_highlighting.py 
# This program creates the .json file of graph data
from dbanalysis import cookies
import json

# https://stackoverflow.com/questions/54220246/python-class-objects-appending-to-list

ops = [] # List of list of cookie Operation objects for each cookie
cookieNames = [] # List of cookie names
for i in range(len(cookies)):
    ops.append(cookies[i].operations)
    cookieNames.append(cookies[i].name)
    # print(cookieNames)

cookieOpsTemp = [] # List of list of operations for each cookie 
for cookieNum in ops:
    opNames = [] # List of list of operations for each cookie 
    for operation in cookieNum:
        opNames.append(operation)
            
    cookieOpsTemp.append(opNames)
# print("cookieOpsTemp: ", cookieOpsTemp)



cookieOps = [] # Same as cookieOpsTemp but with cookie name at beginning of each operation list
i = 0
for c in cookieOpsTemp:
    # print("c: ", c)
    c.insert(0, cookieNames[i])
    cookieOps.append(c)
    i = i + 1
# print("cookieOps: ", cookieOps)


cookieList = []
data = {}
data["name"] = "null"
data["children"] = cookieList

for cookie in cookieOps:
    d = {}
    d["name"] = "Cookie: " + cookie[0] # Get cookie name, which is first elem of cookie
    d["parent"] = "null"
    
    
    # dat = {}
    opsList = []
    for i in reversed(range(1,len(cookie))):
        opsList = [{"name": str(cookie[i]),
                      "parent": str(cookie[i-1]), 
                      "children": opsList
                    }]
        
    d["children"] = opsList
    
    cookieList.append(d)
    # print("cookie: ", cookie)

# print("cookieList: ", cookieList)
# print(json.dumps(data, indent=2))

json_object = json.dumps(data, indent=2)
with open("/Users/Alicia/OpenWPM-master/node/dist/data.json", "w") as outfile:
    outfile.write(json_object)

