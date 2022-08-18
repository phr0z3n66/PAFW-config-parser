#! /usr/bin/env python
# Palo Alto Configuration File parser
# Copyright (C) 2022 Erik Thompson
#
#
# Palo Alto Configuration File parser is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation, either version 3 of the License, or (at your
# option) any later version.
#
# Palo Alto Configuration File parser is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with Palo Alto Configuration File parser. If not, see <http://www.gnu.org/licenses/>.
#
# For suggestions, feedback or bug reports: Erik Thompson


import xml.etree.ElementTree as ET
import argparse
import csv

parser = argparse.ArgumentParser(description='Parsing security rules from palauto.')
parser.add_argument('-f', action='store',
                    metavar='<configuration-file>',
                    help='path to configuration file  example C:\\\\directory\\\\runningconfig.xml',
                    required=True)
parser.add_argument('-o', action='store',
                    metavar='<output-directory>',
                    help='path to output file  example C:\\\\directory\\\\directory',
                    required=True)

args = parser.parse_args()

CONFIGFILE = vars(args)['f']
OUTPUTDIR = vars(args)['o']
print(CONFIGFILE)
print(OUTPUTDIR)
# parsing variables
#device
hh = ['hostname', 'domain', 'ip-address']
hdata = 'devices/entry/deviceconfig/system/'
cy = ''
# rules - security
l = ['from', 'to', 'source', 'destination', 'source-user', 'category', 'application',
     'service', 'hip-profiles', 'tag']
ll = 'profile-setting/group'
# rules - nat
natvar = ['to', 'from', 'source', 'destination', 'tag', ]
n = ['to', 'from', 'source', 'destination', 'tag']
# url policies
uu = ['alert', 'block', 'allow', 'override']
# security policy groups
ss = ['virus', 'spyware', 'vulnerability', 'url-filtering', 'wildfire-analysis']
# ip address group
agl = ['static', 'tag']
# device log settings
llog = ['transport', 'port', 'server']
# rules log settings
rlog = ['send-syslog/member', 'log-type', 'filter', 'send-to-panorama']

# main xml parser
tree = ET.parse(CONFIGFILE)
root = tree.getroot()
# create filename var
for h in hh:
    cy = cy + root.find(hdata + h).text + '-'
cyy = OUTPUTDIR + cy

fwrulesfile = cyy + 'fwrules.csv'
natrulesfile = cyy + 'NATrules.csv'
ipobjectfile = cyy + 'IP-Objects.csv'
ipgroupfile = cyy + 'IP-GROUP-Objects.csv'
urlpolicies = cyy + 'URL-policies.csv'
secgroupfile = cyy + 'Security-Groups.csv'
certfile = cyy + 'installed-certs.csv'
appgroupfile = cyy + 'application-groups.csv'
loggroupfile = cyy + 'logging-settings-profiles.csv'


def vvalues(a, b):
    if a is None:
        return b
    else:
        return a.text

def wvals(a, b):
    if a is None:
        return b
    else:
        x = ''
        if len(a) == 1:
            for t in a:
                return t.text
        else:
            ii = 0
            while ii < len(a):
                for t in a:
                    ii = ii + 1
                    if ii == len(a):
                        x = x + t.text
                    else:
                        x = x + t.text + '\n'
            return x

#open firewall file
outfw = open(fwrulesfile, 'w', newline='')
csvwriter = csv.writer(outfw)
csvwriter.writerow(
    ['NAME', 'LOG-SETTING', 'ACTION', 'DISABLED', 'SECURITY PROFILE', 'FROM', 'TO', 'SOURCE', 'DESTINATION',
     'SOURCE-USER', 'CATEGORY',
     'APPLICATION', 'SERVICE', 'HIP', 'TAG', 'GROUP TAG', 'description'])

for entry in root.find('.//devices/entry/vsys/entry/rulebase/security/rules'):
    out = []
    out.append(entry.attrib['name'])
    out.append(vvalues(entry.find('log-setting'), '**-NO-LOGGING-**'))
    out.append(entry.find('action').text)
    out.append(vvalues(entry.find('disabled'), 'NA'))

    l = ['from', 'to', 'source', 'destination', 'source-user', 'category', 'application',
         'service', 'hip-profiles', 'tag']
    ll = 'profile-setting/group'

    if entry.find(ll) is None:
        out.append('**NO-SECURITY-PROFILE**')
    else:
        for e in entry.find(ll):
            out.append(e.text)

    for i in l:
        out.append(wvals(entry.find(i), 'NA'))

    out.append(vvalues(entry.find('group-tag'), 'NA'))
    out.append(vvalues(entry.find('description'), 'NA'))
    csvwriter.writerow(out)
# close firewall rules file
outfw.close()


#NAT Rules Code:
#(not complete)

#open NAT rules file
outnat = open(natrulesfile, 'w', newline='')
csvwriternat = csv.writer(outnat)
csvwriternat.writerow(
    ['NAME', 'LOG-SETTING', 'ACTION', 'DISABLED', 'SECURITY PROFILE', 'FROM', 'TO', 'SOURCE', 'DESTINATION',
     'SOURCE-USER', 'CATEGORY',
     'APPLICATION', 'SERVICE', 'HIP', 'TAG', 'GROUP TAG', 'description'])

for entry in root.find('.//devices/entry/vsys/entry/rulebase/nat/rules'):
    natout = []

    natout.append(entry.attrib['name'])
    natout.append(vvalues(entry.find('disabled'), 'NA'))
    for i in n:
        natout.append(wvals(entry.find(i), 'NA'))

    natout.append(vvalues(entry.find('service'), 'NA'))
    natout.append(vvalues(entry.find('group-tag'), 'NA'))
    natout.append(vvalues(entry.find('description'), 'NA'))
    csvwriternat.writerow(natout)
# close nat rules file
outnat.close()

#URL POLICIES CODE:
# log-http-hdr-user-agent
# log-http-hdr-referer
outurl = open(urlpolicies, 'w', newline='')
csvwriterurl = csv.writer(outurl)
csvwriterurl.writerow(['NAME', 'ALERT', 'BLOCK', 'ALLOW', 'OVERRIDE'])

for u in root.find('devices/entry/vsys/entry/profiles/url-filtering'):
    urllist = []
    urllist.append(u.attrib['name'])
    for i in uu:
        urllist.append(wvals(u.find(i), 'None'))

    csvwriterurl.writerow(urllist)
# close url policy file
outurl.close()

#SECURITY GROUP POLICIES CODE:
outsecg = open(secgroupfile, 'w', newline='')
csvwritersecg = csv.writer(outsecg)
csvwritersecg.writerow(['NAME', 'VIRUS', 'SPYWARE', 'VULNERABILITY', 'URL-FILTERING', 'WILDFIRE'])
for s in root.find('devices/entry/vsys/entry/profile-group'):
    secpollist = []
    secpollist.append(s.attrib['name'])
    for i in ss:
        secpollist.append(wvals(s.find(i), 'None'))

    csvwritersecg.writerow(secpollist)
# close security policy group file
outsecg.close()

#IP OBJECTS CODE:
#open IP file
outip = open(ipobjectfile, 'w', newline='')
csvwriterip = csv.writer(outip)
csvwriterip.writerow(
    ['NAME', 'ADDRESS', 'TYPE', 'TAGS'])

for i in root.find('devices/entry/vsys/entry/address'):
    iplist = []
    iplist.append(i.attrib['name'])
    if vvalues(i.find('fqdn'), 'FQDN') == 'FQDN':
        iplist.append(vvalues(i.find('ip-netmask'), 'IP-NETMASK'))
        iplist.append('ip-netmask')
    else:
        iplist.append(vvalues(i.find('fqdn'), 'FQDN'))
        iplist.append('FQDN')

    iplist.append(wvals(i.find('tag'), 'NO-TAG'))
    csvwriterip.writerow(iplist)
# close ip objects file
outip.close()

#IP ADDRESS GROUP CODE:
outipg = open(ipgroupfile, 'w', newline='')
csvwriteripg = csv.writer(outipg)
csvwriteripg.writerow(['NAME', 'static', 'tag'])
for ag in root.find('devices/entry/vsys/entry/address-group'):
    ipgrouplist = []
    ipgrouplist.append(ag.attrib['name'])
    for i in agl:
        ipgrouplist.append(wvals(ag.find(i), 'None'))

    csvwriteripg.writerow(ipgrouplist)
# close ip address group file
outipg.close()

#APP GROUP CODE:
outappg = open(appgroupfile, 'w', newline='')
csvwriterappg = csv.writer(outappg)
csvwriterappg.writerow(['NAME', 'APPS'])
for ap in root.find('devices/entry/vsys/entry/application-group'):
    applist = []
    applist.append(ap.attrib['name'])
    applist.append(wvals(ap.find('members'), 'NA'))
    csvwriterappg.writerow(applist)
# close application group file
outappg.close()

#CERTIFICATE CODE:
outcert = open(certfile, 'w', newline='')
csvwritercert = csv.writer(outcert)
csvwritercert.writerow(['NAME', 'Valid TO DATE'])
for ce in root.find('shared/certificate'):
    certlist = []
    certlist.append(ce.attrib['name'])
    certlist.append(ce.find('not-valid-after').text)
    csvwritercert.writerow(certlist)
# close cert file
outcert.close()
'''
# device log settings
llog = ['transport', 'port', 'server']
# rules log settings
rlog = ['send-syslog/member', 'log-type', 'filter', 'send-to-panorama']
'''
#DEVICE LOG CODE:
outlogs = open(loggroupfile, 'w', newline='')
csvwriterlogs = csv.writer(outlogs)
csvwriterlogs.writerow(['NAME', 'SERVER', 'SERVER', 'SERVER'])
for ls in root.find('shared/log-settings/syslog'):
    logsetlist = []
    logsetlist.append(ls.attrib['name'])
    for i in ls.find('server'):
        sl = i.attrib['name'] + '\n'
        for il in llog:
            sl = sl + i.find(il).text + '\n'
        logsetlist.append(sl)
    csvwriterlogs.writerow(logsetlist)

#RULES LOG PROFILES:
csvwriterlogs.writerow([''])
csvwriterlogs.writerow([''])
csvwriterlogs.writerow([''])
csvwriterlogs.writerow([''])
csvwriterlogs.writerow([''])
csvwriterlogs.writerow(['LOGGING PROFILES'])
csvwriterlogs.writerow(['NAME', 'SERVER', 'SERVER', 'SERVER'])
for ls in root.find('devices/entry/vsys/entry/log-settings/profiles'):
    rlogsetlist = []
    rlogsetlist.append(ls.attrib['name'])
    for i in ls.find('match-list'):
        rl = i.attrib['name'] + '\n'
        for il in rlog:
            rl = rl + vvalues(i.find(il), 'NA')
        rlogsetlist.append(rl)
    csvwriterlogs.writerow(rlogsetlist)
# CLOSE LOGGING FILE
outlogs.close()

print('COMPLETE')
