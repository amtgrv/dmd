#
# Copyright (c) 2017, Amit Gaurav
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the project nor the names of its contributors
#       may be used to endorse or promote products derived from this software
#       without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY AMIT GAURAV ``AS IS'' AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL AMIT GAURAV BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

#
# Python utility to get memory allocation reports for a process.
#

import re
import os
import sys
import time
import shutil
import logging
import tempfile
import argparse
import subprocess
from glob import glob
from datetime import datetime
from collections import Counter

fmt_str = '%(message)s'
logging.basicConfig(level=logging.WARN, format=fmt_str)

#
# Define a heap region to collect all allocations under
# that region.
#
class HeapRegion(object):
    def __init__(self, region):
        if len(region) < 4:
            raise RuntimeError('Invalid heap region {}'.format(region))

        self.start_addr = region[0]
        self.end_addr = region[1]
        self.name = region[3]
        self.logfile = 'mem_analyzer/' + self.name + '.log'
        self.binfile = 'mem_analyzer/' + self.name + '.bin'

    def __generate_bin_file(self, analyzer):
        # run gdb to dump the memory addresses in binary
        gdb_ex_cmd = 'dump binary memory ' + self.binfile + ' ' + self.start_addr + ' ' + self.end_addr
        cmd = ['gdb', '--batch', '-ex', gdb_ex_cmd, analyzer.execfile, analyzer.corefile]
        op = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        op.communicate()

    def __generate_gdb_command(self, analyzer):
        gdb_ex_cmd = 'dump binary memory ' + self.binfile + ' ' + self.start_addr + ' ' + self.end_addr
        return gdb_ex_cmd

    def __log_allocations(self, output, analyzer):
        alloc_groups = [group for group in output.split('--') if group]

        with open(self.logfile, 'w') as fp:
            for item in alloc_groups:
                if ':' not in item:
                    continue
                mem_chunk = [entry for entry in re.split('[ :\n]', item) if entry]
                if len(mem_chunk) < 8:
                    continue

                # This searches for "OKEOKEOK" in the core file.
                if (mem_chunk[1] == '4b4f454b4f454b4f' and mem_chunk[3] != '00'):
                    user_size = int(mem_chunk[3], 16)
                    user_pointer = hex(int(self.start_addr, 16) + int(mem_chunk[0], 16) - user_size)
                    user_tag = int(mem_chunk[5], 16)
                    ret_address = '0x' + mem_chunk[7]

                    # HACK: It is assumed that all valid heap address start with 0x7f.
                    if ret_address.startswith('0x7f'):
                        if (analyzer.tag == 0 or analyzer.tag == user_tag):
                            fp.write("{} {} {}\n".format(user_pointer, ret_address, user_size))
            fp.flush()

    def __add_allocations(self, analyzer):
        rows = list()
        cols = list()
        try:
            with open(self.logfile, 'r') as fp:
                rows = [line.rstrip().split(' ', 1) for line in fp]
                cols = [list(col) for col in zip(*rows)]
        except:
            raise RuntimeError("Failed to open file {}".format(self.logfile))

        if len(rows) == 0:
            return

        counters = Counter(cols[1])
        analyzer.addr_counters += counters

    def __extract_allocations(self, analyzer):
        # Hexdump output formatter.
        fmt_str = '1/8 "%08_ax: %02x\n"'
        cmd = ['hexdump', '-v', '-e', fmt_str, self.binfile]
        h_op = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        g_op = subprocess.Popen(['egrep', '-A3', '4b4f454b4f454b4f'],
                                stdin=h_op.stdout,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        g_stdout, g_stderr = g_op.communicate()

        self.__log_allocations(g_stdout, analyzer)

    def fetch_allocations(self, analyzer):
        self.__generate_bin_file(analyzer)

    def fetch_gdb_memory(self, analyzer):
        return self.__generate_gdb_command(analyzer)

    def process_allocations(self, analyzer):
        self.__extract_allocations(analyzer)
        self.__add_allocations(analyzer)

#
# The memory analyzer class.
#
class MemoryAnalyzer(object):
    def __init__(self, execfile, pid, corefile, tag=0, count=20):

        if pid == 0:
            if not os.path.isfile(corefile):
                print "ERROR: Core file [{}] not found".format(corefile)
                exit(1)

        self.pid = pid
        self.corefile = corefile
        self.execfile = execfile

        self.revision = 1
        self.tag = tag
        self.count = count
        self.heap_regions = list()
        self.addr_counters = Counter()
        self.addr_mapping = dict()

    def __get_execfile_from_core(self, corefile):
        if self.execfile:
            return self.execfile

        exec_file = None
        cmd = ['size', corefile]
        op = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = op.communicate()

        match = re.search('invoked as ([^)]+)', stdout)
        if match:
            exec_file = match.group(1)

        return exec_file
        
    def __generate_core_from_pid(self):
        if self.corefile:
            return self.corefile

        gcore_file = os.getcwd() + '/gcore'
        cmd = ['gcore', '-o', gcore_file, str(self.pid)]
        op = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        op.communicate()

        return gcore_file + '.' + str(self.pid)
        
    def __initialize(self):
        if self.pid > 0:
            self.corefile = self.__generate_core_from_pid()

        if (not self.execfile or not os.path.isfile(self.execfile)):
            self.execfile = self.__get_execfile_from_core(self.corefile)

    def start_tracking(self):
        if self.pid <= 0:
            print "ERROR: Invalid PID to start tracking"
            exit(1)

        # Enable memory tracking.
        enable_memcheck = 'set variable g_dmem_track = 1'
        set_tag = 'set variable g_dmem_tag = ' + str(self.tag)
        cmd = ['gdb', '--batch', '-ex', enable_memcheck, '-ex', set_tag, '-p', str(self.pid)]
        op = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        op.communicate()

    def stop_tracking(self):
        if self.pid <= 0:
            print "ERROR: Invalid PID to stop tracking"
            exit(1)

        # Disable memory tracking.
        disable_memcheck = 'set variable g_dmem_track = 2'
        set_tag = 'set variable g_dmem_tag = 0'
        cmd = ['gdb', '--batch', '-ex', disable_memcheck, '-ex', set_tag, '-p', str(self.pid)]
        op = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        op.communicate()

    def __get_heap_regions(self):
        print 'Get all heap regions',
        gdb_ex_cmd = 'info files'
        cmd = ['gdb', '--batch', '-ex', gdb_ex_cmd, self.execfile, self.corefile]
        op = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        g_stdout, g_stderr = op.communicate()
        load_info = [line for line in g_stdout.split('\n') if "is load" in line]

        regions = list()
        for item in load_info:
            regions.append([entry for entry in  re.split('[\t -]', item) if entry])

        print '\t\t\t[ok]'
        return regions

    def get_c_symbols(self, file_name):
        cmd = ['gdb', '--batch', '-x', file_name, self.execfile, self.corefile]
        op = subprocess.Popen(cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        stdout, stderr = op.communicate()

        return stdout

    def __get_allocation_symbols(self):
        counter = 0
        ret_address = list()
        with tempfile.NamedTemporaryFile(delete=False) as temp:
            for addr in self.addr_counters.keys():
                if addr.split()[0].startswith('0x7f'):
                    temp.write('info symbol ' + addr.split()[0] + '\n')
            temp.flush()

            gdb_output = self.get_c_symbols(temp.name).split('\n')
            addr_symbols = [line for line in gdb_output if line][-len(self.addr_counters.keys()):]
            while counter < len(addr_symbols):
                line = addr_symbols[counter]
                if "in section ." in line:
                    ret_address.append(''.join(line.split()[0:3]))
                elif  "No symbol matches" in line:
                    ret_address.append(line.split()[3])
                #else:
                    #print "Error encountered"
                counter = counter + 1

        counter = 0
        for addr in self.addr_counters.keys():
            if addr.split()[0].startswith('0x7f'):
                self.addr_mapping[addr] = ret_address[counter]
                counter = counter + 1

    def __generate_report(self):
        # Print Statistics

        if len(self.addr_counters) == 0:
            print "No active allocations found. Exiting"
            return

        if self.tag != 0:
            print
            print "Allocations from Tag:", self.tag
            print

        header = 'Address' + '\t\t|' + '  Size (Bytes)' + '\t|\t' + 'Count' + '\t|\t' + 'Symbol'
        for i in xrange(len(header)): print('-'),
        print
        print header
        for i in xrange(len(header)): print('-'),
        print

        counter = 0
        for key, value in self.addr_counters.most_common():
            if counter >= self.count:
                break
            key_a = key.split()
            print key_a[0], '\t|\t', key_a[1], '\t|\t', value, '\t|\t', self.addr_mapping[key]
            counter += 1

        for i in xrange(len(header)): print('-'),
        print

    def __fetch_region(self, region):
        hr = HeapRegion(region)
        hr.fetch_allocations(self)

    def __get_region_memory(self, region):
        hr = HeapRegion(region)
        return hr.fetch_gdb_memory(self)

    def __process_region(self, region):
        hr = HeapRegion(region)
        hr.process_allocations(self)

    def __generate_bin_files(self, file):
        # run gdb to dump the memory addresses in binary
        cmd = ['gdb', '--batch', '-x', file, self.execfile, self.corefile]
        op = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        op.communicate()

    def __fetch_regions(self):
        if os.path.isdir('mem_analyzer'):
            shutil.rmtree('mem_analyzer');
        os.mkdir('mem_analyzer')

        with tempfile.NamedTemporaryFile(delete=False) as temp:
            for region in self.heap_regions:
                print("Fetch allocations in {}".format(region[3])),
                temp.write(self.__get_region_memory(region) + '\n')
                print("\t\t[ok]")
            temp.flush()

            # run gdb command to generate bin files
            self.__generate_bin_files(temp.name)


    def __process_regions(self):

        for region in self.heap_regions:
            print("Analyze allocations in {}".format(region[3])),
            self.__process_region(region)
            print("\t\t[ok]")

    def get_allocations(self):

        self.__initialize()

        print '------------ PHASE (1) ---------------'
        print 'Fetching all memory allocations'
        print '--------------------------------------'
        self.heap_regions = self.__get_heap_regions()
        self.__fetch_regions()
        print
        print 'DONE'

        print
        print '------------ PHASE (2) ---------------'
        print 'Analyzing all memory allocations'
        print '--------------------------------------'
        self.__process_regions()
        print
        print 'DONE'

        print
        print '------------ PHASE (3) ---------------'
        print 'Generating Report'
        print '--------------------------------------'
        self.__get_allocation_symbols()
        self.__generate_report()
        print
        print 'DONE'
        
if __name__ == '__main__':
    starttime = datetime.now()

    parser = argparse.ArgumentParser(description='Get active memory allocations')
    parser.add_argument('--execfile', help='Path to the executable file')

    group1 = parser.add_mutually_exclusive_group(required=True)
    group1.add_argument('--pid', type=int, default=0, help='PID of the process')
    group1.add_argument('--corefile', help='Path to the core')

    group2 = parser.add_mutually_exclusive_group(required=True)
    group2.add_argument('--start-tracking', action="store_true", dest='start', help='Start tracking memory allocations')
    group2.add_argument('--stop-tracking', action="store_true", dest='stop', help='End tracking memory allocations')
    group2.add_argument('--generate-report', action="store_true", dest='report', help='Generate allocations report')

    parser.add_argument('--tag', type=int, default=0, help='Tag to define a memory allocation')
    parser.add_argument('--count', type=int, default=20, help='Count of displayed allocations (decreasing order)')
    args = parser.parse_args()

    if (args.start or args.stop):
        if not args.pid:
            print 'ERROR: start-tracking and end-tracking must have PID as argument'
            exit(1)

    mem = MemoryAnalyzer(args.execfile, args.pid, args.corefile, args.tag, args.count)

    if args.report:
        mem.get_allocations()
    elif args.start:
        mem.start_tracking()
    elif args.stop:
        mem.stop_tracking()

    print 'Total time taken: {}'.format(datetime.now() - starttime)
