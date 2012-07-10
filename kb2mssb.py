#!/usr/bin/env python2.7
# Searches current folder for any files containing 'sysinfo' (sysinfo.txt, computer.sysinfo etc)
# Searches current folder for a MS bulletin spreadsheet containing 'BulletinSearch'
#
# Parses the KB values from sysinfo files, matches them with values in the bulletin database
# outputs results to filename.csv
#
# -l will call systeminfo and parse the results for the current machine
# -d will attempt to download a new bulletin file from MS
#
# NB It does not check the date on bulletin files so a folder containing multiple spreadsheets
# may utilize the older version.
#
# http://rewtdance.blogspot.com

from zipfile import ZipFile
import os
import xml.etree.ElementTree as ET
import re
from datetime import date, timedelta
from optparse import OptionParser

namespace = '{http://schemas.openxmlformats.org/spreadsheetml/2006/main}'

def main():
    (options, args) = setOptionParser()
    
    current_dir = os.getcwd()
    dir_list = os.listdir(current_dir)

    bulletin_file_path = None
    sysinfo_paths = []

    if options.download:
        bulletin_file_path = download_bulletins()

    for file in dir_list:
        if not bulletin_file_path:
            if "BulletinSearch" in file:
                bulletin_file_path = "%s\\%s" % (current_dir, file)
                if options.local:
                    break

        if not options.local:
            if "sysinfo" in file:
                if ".csv" not in file:
                    sysinfo_paths.append("%s\\%s" % (current_dir, file))

    if bulletin_file_path:    
        print "[*] Bulletin file found: %s" % (bulletin_file_path)
    else:
        print "[-] No bulletin file found specify -d to attempt download the latest version"
        return

    if not options.local:
        print "[*] Sysinfo file(s) found: %s" % (', '.join(sysinfo_paths))

    with ZipFile(bulletin_file_path, 'r') as bulletin_zip:
        try:
            worksheet = bulletin_zip.open('xl/worksheets/sheet.xml')
        except KeyError:
            worksheet = bulletin_zip.open('xl/worksheets/sheet1.xml')
            
        tree = ET.ElementTree()
        ET.register_namespace('xlsx', namespace)
        tree.parse(worksheet)

    if options.local:
        kbs = parse_systeminfo(run_sysinfo())
        print "[*] Matching Security Bulletin Values"
        found_kbs = find_kbs(kbs, tree)
        output_results(found_kbs, console=True)
    else:
        for sysfile in sysinfo_paths:
            with open(sysfile, 'r') as systeminfo:
                print "[*] Parsing system info: %s" % (sysfile)
                kbs = parse_systeminfo(systeminfo)
                print "[+] Found %i installed KBs" % (len(kbs))

            print "[*] Matching Security Bulletin Values"
            found_kbs = find_kbs(kbs, tree)

            outfile = sysfile + ".csv"
            output_results(found_kbs, path=outfile)
            
def get_cell_value(cell):
    for value in cell.itertext():
        return value

def convert_oa_date(oa_date):
    kb_date = date(1900,1,1)
    delta = timedelta(days=int(oa_date))
    kb_date = kb_date + delta
    return kb_date.isoformat()

def find_kbs(kb_list, tree):
    kb_matches = []

    rows = tree.findall('./{0}sheetData/{0}row'.format(namespace))
    for row in rows:
        if len(kb_list) < 1:
            break
        
        row_number = row.get('r')
        if row_number < 1:
            continue

        cells = row.findall('./{0}c'.format(namespace))
        kb = get_cell_value(cells[7])

        try:
            kb_list.remove(kb)
        except:
            continue

        date = convert_oa_date(get_cell_value(cells[0]))
        mssb = get_cell_value(cells[1])

        severity = get_cell_value(cells[10])
        cves = get_cell_value(cells[14])

        kb_match = dict(kb=kb, date=date, mssb=mssb, severity=severity, cves=cves)
        kb_matches.append(kb_match)

    for kb in kb_list:
        kb_matches.append((dict(kb=kb, date="", mssb="NOT FOUND", severity="", cves="")))
        
    return kb_matches

def parse_systeminfo(systeminfo):
    kbs = []

    kb_regex = re.compile('KB[0-9]+')
    while 1:
        line = systeminfo.readline()
        if not line:
            break

        match = kb_regex.search(line)
        
        if match:
            kb = match.group().lstrip('KB')
            kbs.append(kb)
    return kbs

def setOptionParser():
    usage = "Usage: %prog [options]"
    parser = OptionParser(usage=usage)
    parser.add_option("-l", "--local", dest="local", action="store_true", default=False,
        help="Inspect local systeminfo file (outputs to console)")
    parser.add_option("-d", "--download", dest="download", action="store_true", default=False,
        help="Download the Bulletin Spreadsheet")

    return parser.parse_args()

def output_results(results, path="", console=False):
    if console:
        path = os.getcwd() + "\\local_results.csv"
        print "[*] Results"
        print "KB\tDATE\t\tMSSB\t\tSEVERITY"
        print "-" * 79
        for line in results:
            print "%s\t%s\t%s\t%s" % (line['kb'], line['date'], line['mssb'], line['severity'])

    print "[*] Writing results to %s" % (path)
    with open(path, 'w') as output:
        output.write("KB,Date,MSSB,Severity\n")
        for line in results:
            output.write("%s,%s,%s,%s\n" % (line['kb'], line['date'], line['mssb'], line['severity']))

def download_bulletins():
    import urllib2
    from urlparse import urlparse
    
    local_filename = "%s\\BulletinSearch_download.xlsx" % (os.getcwd())
    url = "http://go.microsoft.com/fwlink/?LinkID=245778"
    
    try:
        print "[*] Attempting to download"
        req = urllib2.urlopen(url)
        remote_filename = urlparse(req.geturl())[2].split('/')[-1]
        local_filename = "%s\\%s" % (os.getcwd(), remote_filename)
        with open(local_filename, 'wb') as download_file:
            download_file.write(req.read())
    except:
        print "[-] Download failed"
        return None

    print "[+] Download successful: %s" % (local_filename)
    return local_filename

def run_sysinfo():
    import subprocess
    import StringIO
    return StringIO.StringIO(subprocess.Popen(["systeminfo"], stdout=subprocess.PIPE).communicate()[0])

if __name__ == "__main__":
    main()