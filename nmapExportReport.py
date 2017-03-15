#!/usr/bin/env python
# -*- coding: utf-8 -*-

# NmapExportReport
#
# Processes Nmap XML files to generate reports. The main action is to create an CSV
#

# Copyright (C) 2010 Pablo Endres <epablo@pabloendres.com>

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.


import sys
import getopt

#sys.path.append('/usr/lib/python2.5/site-packages')

import sys
from datetime import datetime
import zenmapCore.NmapParser

version = "0.2"
url = "http://www.pabloendres.com/tools"
verbose = False


def usage():
    global version
    print ""
    print "NmapExportReport " + version + "\t"+ url
    print "usage:  NmapExportReport.py [option] <nmap XML file> \n"
    print "     -h, --help      display this help"
    exit()


def main():
    global verbose
    global url
    output_format = None

    try:
        opts, input_filenames = getopt.gnu_getopt(
                sys.argv[1:], "h", ["help"])
    except getopt.GetoptError, e:
        usage_error(e.msg)
    for o, a in opts:
        if o == "-h" or o == "--help":
            usage()
            sys.exit(0)
        # elif o == "-v" or o == "--verbose":
        #     verbose = True

    if len(input_filenames) != 1:
        usage()

    file_to_parse = input_filenames[0]

    np = zenmapCore.NmapParser.NmapParser()
    np.parse_file(file_to_parse)
    print_csv_by_fors(np)

def print_csv_by_fors(np):

    """Print the values that have been found in CSV format to the default output

    :param np: zenmapCore.NmapParser.NmapParser() that already parsed the file
    """

    print "IP,Port,protocol,state,reason,service name,product,version,extra"

    for host in np.hosts:
        for p in host.ports:
            ## Add the IP Address
            resultString = host.ip['addr']
            ## Check for empty fields and skip them
#            print p
            for field in ['portid','protocol','port_state','reason','service_name','service_product', 'service_version', 'service_extrainfo']:
                if field in p:
                    resultString = resultString + "," + p[field]
                else:
                    resultString = resultString + ","
            print resultString

    ## Todo change the dates to something useful and get the stats in here to
    ## Print the date and nmap options at the top
    print "# Nmap report " + np.nmap['nmaprun']['args']
 #           print '{0},{1}'.format(host.ip['addr'],resultString)
#            print '{0},{1},{2},{3},{4},{5},{6},{7},{8}'.format(host.ip['addr'],p['portid'],p['protocol'],p['port_state'],p['reason'],p['service_name'], p['service_product'],p['service_version'],p['service_extrainfo'])


if __name__ == '__main__':
    import sys
    main()



