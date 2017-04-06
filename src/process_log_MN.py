#!/usr/bin/env python
# coding: UTF-8
# developed on Python 3.5.2, on Scientific Linux 7.2
#
# Insight Data Coding Challenge
#        
# __author__ = "Masahiro Notani"
# __date__ = "Wed Apr  5 20:10:47 2017"
#
def datetime_to_epoch(t, tfmt): # convert to epoch time from string with format
    import time
    time_t = time.strptime(t, tfmt)
    epoch_time=time.mktime(time_t)
    
    return int(epoch_time)

def epoch_to_datetime(epoch_time): # convert from epoch time to string
    import time
    from datetime import datetime

    return time.ctime(epoch_time)

def log_parser(name, fout1, fout2, fout3, fout4):
    import re
    from operator import itemgetter, attrgetter

    #a. Use dic for Feature 1,2,3. (because list is slow)
    fdic1 = {} #1 hosts.txt
    fdic2 = {} #2 resources.txt
    fdic3 = {} #3 hours.txt
    
    #b. Use 3 sets of list for Feature 4
    blk_host = []   # Candidate of hostname/ip for block list
    blk_n    = []   # Number of login failure
    blk_epoch  = [] # Epoch time (Unix time) of the 1st login failure
    
    # initialize - blocked.txt for Feature 4
    with open(fout4,'w') as fw4:
        fw4.write(' hostname: first access time for the incident\n')
    
    # Event Loop: Begin
    with open(name,'r') as fr:
        line = fr.readline()
        nline=0
        while line:
            sline = re.sub(r'^(\S+) (\S+) (\S+) \[([^\]]+)\] "([^"]+)" ([0-9]{3}) ([0-9]+|-)', r'\1"\2"\3"\4"\5"\6"\7"', line)
            p = re.compile(r'([^"]+)"') #   A char " is Delimiter, instead of ,
            m = p.findall(sline)
            #print(len(m),m) 
            iphost = m[0]   # ip / hostname
            actime = m[3]   # access time
            crequest = m[4] # resource required by client
            cstatus = m[5]  # client status
            csize = m[6]    # object size sent to client
            #print("iphost, access time, status, size=",iphost,actime,cstatus,csize)

            #1 hosts.txt
            if iphost in fdic1:
                n = fdic1[iphost]
                del fdic1[iphost]
                fdic1[iphost] = n + 1  # Access# n++
            else:
                fdic1[iphost] = 1      # append the host

            #2 resources.txt
            rlist = crequest.split()
            resource = rlist[1] # 0='GET' 1='/...jpg' 2='HTTP1.0/...'
            #print('resource=', resource, ' size=',csize)
            if csize.isdigit()==True:
                if resource in fdic2:
                    n = fdic2[resource]
                    del fdic2[resource]
                    fdic2[resource] = n + int(csize)  # Bandwidth += csize
                elif resource != '/':
                    fdic2[resource] = int(csize)      # append the resource

            #3 hours.txt
            tlist = actime.split()
            hour1 = tlist[0] # 0='01/Jul/1995:00:00:01' 1='-0400'
            #print('hour =', hour1[:-6], end='') # '01/Jul/1995:00'
            hour2 = hour1[:-6]
            if hour2 in fdic3:
                n = fdic3[hour2]
                del fdic3[hour2]
                fdic3[hour2] = n + 1  # Access# n++
            else:
                fdic3[hour2] = 1      # append the hour

            #4 blocked.txt    # status=401,HTTP_UNAUTHORIZED
                              # iphost is ready.
            #4-1-1 status
            if cstatus.isdigit()==True:
                status = int(cstatus)
            else:
                print("*abnormal cstatus: ",cstatus)
                status = -1   # no status info? (-)

            #4-1-2 epock time
            tfmt2 = '%d/%b/%Y:%H:%M:%S'   # %b=Jul, Aug, ...
            epoch_time = datetime_to_epoch(tlist[0], tfmt2)
            
            #4-2 release by normal login
            if status<400:
                for i in range(0, len(blk_host)-1):
                    if blk_host[i]==iphost:       # normal login
                        blk_host.pop(i)
                        blk_n.pop(i)
                        blk_epoch.pop(i)

            #4-3 register by login failure
            if status>=400:
                if blk_host.count(iphost)==0: # Append new blk_host
                    blk_host.append(iphost)
                    blk_n.append(int(1))
                    blk_epoch.append(epoch_time)
                else:
                    i = blk_host.index(iphost)
                    blk_n[i] += 1             # Access# n++
                    if blk_n[i] > 2: # There are 3 times of login failure
                        if (epoch_time - blk_epoch[i])>20: # 20 second window
                            blk_host.pop(i)
                            blk_n.pop(i)
                            blk_epoch.pop(i)
                        else:
                            #4 blocked.txt
                            with open(fout4,'a') as fw4:
                                fmt4_msg = '%s: %s\n' % (iphost, epoch_to_datetime(blk_epoch[i]))
                                fw4.write(fmt4_msg)
                            
                            blk_host.pop(i)
                            blk_n.pop(i)
                            blk_epoch.pop(i)

            line = fr.readline()
            nline+=1
            if nline>100000: break #=== stop the loop to limit the number of events ===#
    # Event Loop: End

    #=== Output Files for Feature 1,2,3
    #1 hosts.txt
    #sdic1= sorted(fdic1.items(), key=lambda x:x[0], reverse=True) # sort by key
    sdic1 = sorted(fdic1.items(), key=itemgetter(1), reverse=True) # sort by value
    
    with open(fout1,'w') as fw1:
        fw1.write('#: hostname, # of access\n')
        n1=0
        for k, v in sdic1:
            n1+=1
            #print(k,v)
            fmt1_msg = '%d: %s,%d\n' % (n1, k, v)
            #print(fmt1_msg)
            fw1.write(fmt1_msg)
            if n1>9: break   # Top 10
    
    #2 resources.txt
    sdic2 = sorted(fdic2.items(), key=itemgetter(1), reverse=True) # sort by value
    
    with open(fout2,'w') as fw2:
        fw2.write('#: resource, total bytes\n')
        n2=0
        for k, v in sdic2:
            n2+=1
            #print(k,v)
            fmt2_msg = '%d: %s,%d\n' % (n2, k, v)
            #print(fmt2_msg)
            fw2.write(fmt2_msg)
            if n2>9: break   # Top 10
    
    #3 hours.txt
    sdic3 = sorted(fdic3.items(), key=itemgetter(1), reverse=True) # sort by value
    
    with open(fout3,'w') as fw3:
        fw3.write('#: date:hour, # of access in 60 minutes\n')
        n3=0
        for k, v in sdic3:
            n3+=1
            #print(k,v)
            fmt3_msg = '%d: %s,%d\n' % (n3, k, v)
            #print(fmt3_msg)
            fw3.write(fmt3_msg)
            if n3>9: break   # Top 10

    #4 blocked.txt
    # this file is written in the event loop.

    return name   

# Main Routine: Begin
filename='log.txt'  # Input filename
f1='./log_output/hosts.txt'      # Feature 1: top 10 most active hosts/IP addresses that have accessed the site
f2='./log_output/resources.txt'  # Feature 2: top 10 resources on the site that consume the most bandwidth
f3='./log_output/hours.txt'      # Feature 3: the site’s 10 busiest 60-minute period3
f4='./log_output/blocked.txt'    # Feature 4: hosts of three consecutive failed login attempts over 20 seconds
log_parser(filename,f1,f2,f3,f4)

input("Hit any key to End.") #=== stopper for Python on Windows ===#
# Main Routine: End
