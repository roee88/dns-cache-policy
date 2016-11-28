import os
import operator

success = {}
timeout_count = 0
failed_count = 0
worked_count = 0
resolvers = {}
common = {"bind": 0, "microsoft": 0, "unbound": 0, "vermicelli": 0, "mikrotik": 0, "raiden": 0, "other_": 0}
okcommon = {"bind": 0, "microsoft": 0, "unbound": 0, "vermicelli": 0, "mikrotik": 0, "raiden": 0, "other_": 0}

def count(d, resolver):
    for k in d.keys():
        if k in resolver.lower():
            d[k] += 1
            return
    d["other_"] += 1
                  
total = 0
for filename in os.listdir("output"):
    if not filename.endswith(".sum"): 
        continue
    total += 1
    with open("output/"+filename, "r") as f:        
        worked = False
        timeout = True
        resolver = ""

        linenum = 0
        for line in f:
            linenum += 1
            try:
                if linenum == 5:
                    resolver = line.split(None, 1)[1]
                    if resolver not in resolvers:
                        resolvers[resolver] = 1
                    else:
                        resolvers[resolver] += 1
                    count(common, resolver)
            except:
                pass

            if "SUCCESS" in line:
                worked = True
                testname = line.split("\t")[0]
                if not testname in success:
                    success[testname] = 0
                success[testname] += 1
                timeout = False
                
            elif "FAILED" in line:
                timeout = False
                
        if worked:
            worked_count += 1
            count(okcommon, resolver)
                
        elif timeout:
            timeout_count += 1
            
        else:
            failed_count += 1
            
            
            
def pretty(l):
   for item in l:
      print '\t' + str(item[0]).rstrip() + '\t' + str(item[1]).rstrip()

def pretty_payloads(l):
   for item in l:
      t = str(item[0]).rstrip().translate(None, "[],").replace("=", " ").split()[0::2]
      t.append(str(item[1]).rstrip())
      print "\t".join(t)

if __name__ == "__main__":
    print "Total:", total
    print "Failed:", failed_count
    print "Worked:", worked_count
    print "Timeout:", timeout_count
    print "Common:", common
    print "Common Worked:", okcommon

    print "Successful payloads:"
    print pretty_payloads(sorted(success.items(), key=operator.itemgetter(1), reverse=True))

    print "Fingerprints:"
    print pretty(sorted(resolvers.items(), key=operator.itemgetter(1), reverse=True))
