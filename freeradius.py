#!/usr/bin/python
import sys
import re
import os

#ADJUST THESE NUMBERS BELOW TO YOUR NEEDS
# The levels correspond to LOGWATCH_DETAIL_LEVEL levels
ERROR_LINE_THRESHOLD = 1
WARNING_LINE_THRESHOLD = 5
INFO_LINE_THRESHOLD = 10

logwatch_level = int(os.getenv("LOGWATCH_DETAIL_LEVEL"))

#Stat tracker
stats = {}
stats["total_auths"] = {}
stats["total_auths"]["fail"] = 0
stats["total_auths"]["pass"] = 0
stats["loginOK"] = {}
stats["loginFail"] = {}
stats["infoLines"] = []
stats["errorLines"] = []
stats["warningLines"] = []

#Setting up the regular expressions
#date, type, and data
line_rgx = re.compile("(?P<date>.*? (?:[0-9]{2}:[0-9]{2}:[0-9]{2}) 20[0-9]{2})\s+:\s+(?P<type>(?:Info|Auth|Error|Warning)):(?:\s+\([0-9]{1,6}\))?\s+(?P<data>.*)")
#username, WAPid, and userMAC
auth_success = re.compile("Login OK:\s+\[(?P<username>.*?)\]\s+\(from client (?P<WAPid>.*?)\s+port\s+[0-9]{0,5}\s+cli\s+(?P<userMAC>[a-zA-Z0-9]{12})")
#username, authInfo, WAPid, tls, and userMAC
auth_fail = re.compile("Login incorrect:?(?:\s+\(.*?\):)?\s+\[(?P<username>.*?)/(?P<authInfo>.*?)\]\s+\(from client\s+(?P<WAPid>.*?)\s+port [0-9]{0,5} (?:via (?P<tls>TLS tunnel)|cli (?P<userMAC>[a-zA-Z0-9]{12}))")

#easier than putting spaces in by hand, and cleaner looking too
s1 = "    "
s2 = 2*s1
s3 = s2 + s1

def count_dupes(inputList):
    '''Accepts a list and returns a dictionary where each key's value is the number of times it occurs'''
    rtrndict = {}
    for item in inputList:
        if rtrndict.has_key(item) is False: rtrndict[item] = 0
        rtrndict[item] += 1
    return rtrndict

    
def check_line(line):
    global stats
    #Now we start to put our regular expressions to work. This first one will filter out any weird stuff we don't want as well as organize whats left
    line_match = line_rgx.match(line)
    if line_match is not None:
        #If we encounter an Info or Error line we just want to save the entire line for viewing since those are usually important.
        #We can adjust what is shown by logwatch verbose level as well, although for now it will always print everything.
        #In the future, only level 10 will print everything. Other levels will print just print the errors
        if line_match.group("type") == "Info": stats["infoLines"].append(line)
        elif line_match.group("type") == "Error": stats["errorLines"].append(line)
        elif line_match.group("type") == "Warning": stats["warningLines"].append(line)
        #Now onto the Auth section.
        elif line_match.group("type") == "Auth":
            #Here we check if its a good or failed auth
            
            #Feed the data from line_match to the auth_success regex to test if its a successful auth.
            asi = auth_success.match(line_match.group("data"))
            if asi is not None:
                #We got a match for a successful authentication. Now we save the info we want to report later.
                #Increment the total number of good auths
                stats["total_auths"]["pass"] += 1
                #Check if we have a key for this WAP station, if not create it
                if stats["loginOK"].has_key(asi.group("WAPid")) is False: stats["loginOK"][asi.group("WAPid")] = {}
                #Check if we already have a key for this username for this WAP station, if not create it
                if stats["loginOK"][asi.group("WAPid")].has_key(asi.group("username")) is False: stats["loginOK"][asi.group("WAPid")][asi.group("username")] = []
                #Now we append the device MAC address to the username's list for this WAP station. This will serve to count the total number of auths per username as well.
                stats["loginOK"][asi.group("WAPid")][asi.group("username")].append(asi.group("userMAC"))
            
            #Feed the data from line_match to the auth_fail regex to test if its a failed auth.
            afi = auth_fail.match(line_match.group("data"))
            if afi is not None:
                #Got a good match for a failed auth. We do almost the same as with the good auth but there is an extra line we have to watch out for.
                #I thought I was going to use the extra line when I started but now Im not sure sure I want people's passwords all over my logwatches so I'm not using it.
                #I will probably remove it in the future however.
                #increment the total number of failed auths
                stats["total_auths"]["fail"] += 1
                #Make sure this isn't the line we don't want.
                if afi.group("tls") is None:
                    #Check if we have a key for this WAP station, if not create it
                    if stats["loginFail"].has_key(afi.group("WAPid")) is False: stats["loginFail"][afi.group("WAPid")] = {}
                    #Check if the key exists for this username and WAP station, if not create it.
                    if stats["loginFail"][afi.group("WAPid")].has_key(afi.group("username")) is False: stats["loginFail"][afi.group("WAPid")][afi.group("username")] = []
                    #Append the mac address to the username's key for this WAPid
                    stats["loginFail"][afi.group("WAPid")][afi.group("username")].append(afi.group("userMAC"))
            
            

def print_infos():
    #Before we print it out we need to gather together some stats
    #total number of successful auths for each username and WAP station
    gauth_usercount = {}
    gauth_wapcount = {}
    
    #We want to count the total number of authentications that took place. To do this we have to count from the ground up
    #Start with successful auths
    #Go by each wap station
    for wapid in stats["loginOK"]:
        #If the wapid isnt in gauth_wapcount yet, create it and set it to zero
        if gauth_wapcount.has_key(wapid) is False: gauth_wapcount[wapid] = 0
        #Now we go by each username
        for usernm in stats["loginOK"][wapid]:
            #each username has a list of devices they have connected from. We need to count up each of those devices
            usr_device_count = len(stats["loginOK"][wapid][usernm])
            #We add the device count to the total and also set each username's key to that value in usercount
            if gauth_usercount.has_key(wapid) is False: gauth_usercount[wapid] = {}
            gauth_usercount[wapid][usernm] = usr_device_count
            gauth_wapcount[wapid] += usr_device_count
    
    bauth_usercount = {}
    bauth_wapcount = {}
    for wapid in stats["loginFail"]:
        if bauth_wapcount.has_key(wapid) is False: bauth_wapcount[wapid] = 0
        #Now we go by each username
        for usernm in stats["loginFail"][wapid]:
            #each username has a list of devices they have connected from. We need to count up each of those devices
            usr_device_count = len(stats["loginFail"][wapid][usernm])
            #We add the device count to the total and also set each username's key to that value in usercount
            if bauth_usercount.has_key(wapid) is False: bauth_usercount[wapid] = {}
            bauth_usercount[wapid][usernm] = usr_device_count
            bauth_wapcount[wapid] += usr_device_count
    
    #Print out successful authentications
    print "Successful Authentications (%s):" % (str(stats["total_auths"]["pass"]))
    for key in stats["loginOK"]:
        print "%s%s (%s):" % (s1, key, str(gauth_wapcount[key]))
        for usernm in stats["loginOK"][key]:
            print "%s%s (%s):" % (s2, usernm, str(gauth_usercount[key][usernm]))
            device_count = count_dupes(stats["loginOK"][key][usernm])
            for devid in device_count:
                #This converts the string of 12 characters into the standard mac form, e.g. AA:BB:CC:DD:EE:FF
                #We do this through string formatting coupled with list comprehension and list slicing.
                fixed = str("%s:%s:%s:%s:%s:%s" % tuple([devid[x:x+2] for x in xrange(0, 12, 2)])).upper()
                print "%s%s - %s Time(s)" % (s3, fixed, str(device_count[devid]))
            print ""
        print ""
    print "\n"
    
    
    #Print out failed authentications
    print "Failed Authentications (%s)" % (str(stats["total_auths"]["fail"]))
    for key in stats["loginFail"]:
        print "%s%s (%s):" % (s1, key, str(bauth_wapcount[key]))
        for usernm in stats["loginFail"][key]:
            print "%s%s (%s):" % (s2, usernm, str(bauth_usercount[key][usernm]))
            device_count = count_dupes(stats["loginFail"][key][usernm])
            for devid in device_count:
                #This converts the string of 12 characters into the standard mac form, e.g. AA:BB:CC:DD:EE:FF
                #We do this through string formatting coupled with list comprehension and list slicing.
                fixed = str("%s:%s:%s:%s:%s:%s" % tuple([devid[x:x+2] for x in xrange(0, 12, 2)])).upper()
                print "%s%s - %s Time(s)" % (s3, fixed, str(device_count[devid]))
            print ""
        print ""
    print "\n"
    
    if logwatch_level >= ERROR_LINE_THRESHOLD:
        #Print out any error lines
        if len(stats["errorLines"]) > 0:
            print "Errors: "
            for line in stats["errorLines"]:
                print "%s%s" % (s1, line)
            print "\n"
    
    if logwatch_level >= WARNING_LINE_THRESHOLD:
        #Print out any warning lines
        if len(stats["warningLines"]) > 0:
            print "Warnings: "
            for line in stats["warningLines"]:
                print "%s%s" % (s1, line)
            print "\n"

    if logwatch_level >= INFO_LINE_THRESHOLD:
        #Print out any info lines
        if len(stats["infoLines"]) > 0:
            print "Info: "
            for line in stats["infoLines"]:
                print "%s%s" % (s1, line)
            
    

if __name__ == '__main__':
    #Take stdin one line at a time
    for line in sys.stdin:
       check_line(line)

    #And now print it out
    print_infos()

