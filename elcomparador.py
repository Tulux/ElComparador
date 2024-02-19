#!/bin/python3
# Florent DELAHAYE
# https://github.com/Tulux/ElComparador

import os
import stat
import zlib
import threading
import queue
import time
import argparse
import humanize
import logging
import datetime
import enum
import shutil


def crc32(filename):
    with open(filename, 'rb') as fh:
        hash = 0
        while True:
            s = fh.read(65536)
            if not s:
                break
            hash = zlib.crc32(s, hash)
        return "%08X" % (hash & 0xFFFFFFFF)

def print_refresh(msg, prefix_size = 0):
    term_width = shutil.get_terminal_size()[0]
    prefix = msg[:prefix_size]
    suffix_max = term_width - len(prefix)
    if len(msg) >= term_width:
        msg = '...' + msg[-suffix_max+3:]
    else:
        msg = msg[prefix_size:]
    print(f'{prefix}{msg}\033[K', end='\r')

class FileType(enum.Enum):
    DIR = enum.auto()
    CHR = enum.auto()
    BLK = enum.auto()
    REG = enum.auto()
    FIFO = enum.auto()
    LNK = enum.auto()
    SOCK = enum.auto()
    DOOR = enum.auto()
    PORT = enum.auto()
    WHT = enum.auto()

class ComparisonDifference(Exception):
    def __init__(self, differences):            
        self.differences = differences

class Entry:
    def __init__(self, name, stats = None, symlink = None, inaccessible = False):
        self.name = name
        self.symlink = symlink
        self.crc32 = None
        self.inaccessible = inaccessible
        
        if not inaccessible:
            self.filemode = stat.filemode(stats.st_mode)
            self.owner = stats.st_uid
            self.group = stats.st_gid
            self.suid = True if stats.st_mode & stat.S_ISUID else False
            self.guid = True if stats.st_mode & stat.S_ISGID else False
            self.sticky = True if stats.st_mode & stat.S_ISVTX else False
            self.size = stats.st_size
            self.ctime = stats.st_ctime
            self.mtime = stats.st_mtime
            self.atime = stats.st_atime
            self.type = FileType.DIR if stat.S_ISDIR(stats.st_mode) else \
            FileType.REG if stat.S_ISREG(stats.st_mode) else \
            FileType.LNK if stat.S_ISLNK(stats.st_mode) else None
            if self.type is None:
                raise ValueError("Unknown file type")
        else:
            self.filemode = None
            self.owner = None
            self.group = None
            self.suid = None
            self.guid = None
            self.sticky = None
            self.size = None
            self.ctime = None
            self.mtime = None
            self.atime = None
            self.type = None


    def __str__(self):
        ret = "=" * 50 + "\n"
        ret += f"{self.name}\n"
        ret += "Type: "
        match self.type:
            case FileType.DIR:
                ret += "Directory\n"
            case FileType.REG:
                ret += "Regular\n"
            case FileType.LNK:
                ret += f"Symbolic Link, target: {self.symlink}\n"
        if self.inaccessible:
            ret += " [INACCESSIBLE]\n"
        else:
            ret += (f"Mode: {self.filemode}\n"
                    f"Owner: {self.owner}\n"
                    f"Group: {self.group}\n"
                    f"SUID: {self.suid}\n"
                    f"GUID: {self.guid}\n"
                    f"Sticky bit: {self.sticky}\n"
                    f"Creation date: {datetime.datetime.fromtimestamp(self.ctime).strftime('%Y-%m-%dT%H:%M:%S%z')}\n"
                    f"Modification date: {datetime.datetime.fromtimestamp(self.mtime).strftime('%Y-%m-%dT%H:%M:%S%z')}\n"
                    f"Access date: {datetime.datetime.fromtimestamp(self.atime).strftime('%Y-%m-%dT%H:%M:%S%z')}\n")
            ret += f"Size: {humanize.naturalsize(self.size)}\nCRC32: {self.crc32}\n" if self.type == FileType.REG else ""
        return ret

    def __repr__(self):
        return str({'name': self.name,
                    'filemode': self.filemode,
                    'owner': self.owner,
                    'group': self.group,
                    'suid': self.suid,
                    'guid': self.guid,
                    'sticky': self.sticky,
                    'size': self.size,
                    'ctime': self.ctime,
                    'mtime': self.mtime,
                    'atime': self.mtime,
                    'symlink': self.symlink,
                    'crc32': self.crc32,
                    'inaccessible': self.inaccessible,
                    'type': self.type})

    # Return:
    # True, None: Identical objects
    # False, [values]: Same filename but other differences
    # False, []: Different filename
    def compare(self, other, opts):
        if self.name == other.name:
            difference = []
            if self.inaccessible != other.inaccessible:
                difference.append('inaccessible')
            if self.type != other.type:
                difference.append('type')
            if opts['filemode'] and self.filemode != other.filemode:
                difference.append('filemode')
            if opts['owner'] and self.owner != other.owner:
                difference.append('owner')
            if opts['group'] and self.group != other.group:
                difference.append('group')
            if opts['ctime'] and self.ctime != other.ctime:
                difference.append('ctime')
            if opts['atime'] and self.atime != other.atime:
                difference.append('atime')
            if opts['symlink'] and self.symlink != other.symlink:
                difference.append('symlink')
            if self.crc32 != other.crc32:
                difference.append('crc32')
            if self.type == FileType.REG:
                if opts['file-size'] and self.size != other.size:
                    difference.append('size')
                if opts['file-mtime'] and self.mtime != other.mtime:
                    difference.append('mtime')
            if self.type == FileType.DIR:
                if opts['directory-size'] and self.size != other.size:
                    difference.append('size')
                if opts['directory-mtime'] and self.mtime != other.mtime:
                    difference.append('mtime')                

            if not difference:
                return True, None
            else:
                return False, difference
        else:
            return False, []


class FileList:
    def __init__(self, path, excludes):
        self.path = path
        self.flist = []
        self.excludes = [os.path.join(self.path, ex) for ex in excludes]

        self.monit_lock = threading.Lock()
        self.monit_file_count = 0
        self.monit_current_file = 'STARTED'
        self.monit_total_size = 0

    def monitor(self):
        start = time.time()
        while True:
            self.monit_lock.acquire()
            stats_current_file = self.monit_current_file
            self.monit_lock.release()
            if stats_current_file == '':
                break
            elif stats_current_file != 'STARTED':
                current = time.time()
                self.monit_lock.acquire()
                prefix = f'{self.monit_file_count} files ({humanize.naturalsize(self.monit_total_size)} total), {current - start:.0f}s (~{humanize.naturalsize(self.monit_total_size/(current - start))}/s) - '
                print_refresh(prefix + f'{self.monit_current_file}', prefix_size = len(prefix))
                self.monit_lock.release()
            time.sleep(1)

    # Return all files and directories from a given path
    def browse(self, path, excludes, mode, flag_crc32):
        try:
            #for f in sorted(os.scandir(path), key=lambda e: e.name):
            for f in os.scandir(path):
                fullpath = os.path.join(path, f.name)
                if fullpath not in excludes:
                    self.monit_lock.acquire()
                    self.monit_file_count += 1
                    self.monit_current_file = fullpath
                    self.monit_lock.release()
                    try:
                        stats = f.stat(follow_symlinks=False)
                    except OSError as e:
                        if e.errno == 13:
                            logging.info(f'<{fullpath}> exists but cannot be accessed (errno 13)')
                            self.flist.append(Entry(name=f.name, inaccessible=True))
                    else:
                        # Excluding types other than directory, regular and symlink
                        if stat.S_ISDIR(stats.st_mode) or \
                           stat.S_ISREG(stats.st_mode) or \
                           stat.S_ISLNK(stats.st_mode):
                            
                            target = os.readlink(f) if stat.S_ISLNK(stats.st_mode) else None
                            self.flist.append(Entry(name=fullpath.removeprefix(self.path), stats=stats, symlink=target))
                            
                            if flag_crc32 and stat.S_ISREG(stats.st_mode):
                                self.entryCalculateCRC32(self.getEntry(fullpath.removeprefix(self.path)))

                            self.monit_lock.acquire()
                            self.monit_total_size += stats.st_size
                            self.monit_lock.release()
                            if stat.S_ISDIR(stats.st_mode):
                                self.browse(fullpath, excludes, mode, flag_crc32)
        except OSError as e:
            if mode == 'complete':
                logging.info(f'<{path}> cannot be listed')

    def entryCalculateCRC32(self, entry):
        crc = 0
        # stat() may success on some files whereas open() fails (ie: root-owned files)
        try:
            crc = crc32(os.path.join(self.path, entry.name))
        except OSError as e:
            if e.errno == 13:
                # Mark entry as inaccessible
                entry.inaccessible = True
                logging.info(f'<{os.path.join(self.path, entry.name)}> exists but cannot be accessed (errno 13)')
        else:
            entry.crc32 = crc

    def run(self, mode, flag_progress, flag_crc32):
        if flag_progress:
            monit = threading.Thread(target=self.monitor)
            monit.start()

        logging.debug(f'<{self.path}>: starting browsing')
        self.browse(self.path, self.excludes, mode, flag_crc32)
        logging.debug(f'<{self.path}>: finished browsing, waiting for lock')

        self.monit_lock.acquire()
        self.monit_current_file = '' # Stop thread
        self.monit_lock.release()

        logging.debug(f'<{self.path}>: lock released, starting sorting')
        # Sort file list
        tmp_flist = sorted(self.flist, key=lambda e: e.name)
        logging.debug(f'<{self.path}>: finished sorting')

        self.flist = tmp_flist

    def getEntry(self, filename):
        try:
            ret = next(entry for entry in self.flist if entry.name == filename)
        except StopIteration:
            return None
        else:
            return ret

    def __len__(self):
        return len(self.flist)

    def __getitem__(self, k):
        return self.flist[k]

    def __iter__(self):
        return iter(self.flist)

    def __repr__(self):
        return str([i for i in self])

    def __str__(self):
        return "".join([str(i) for i in self.flist])

    # Dichotomic search
    #
    # Return false if entry not found or true if found
    def searchAndCompare(self, entry, comp_opts):
        seek_start = 0
        seek_end = len(self)
        seek_current = int(len(self) / 2)
        last_iteration = False

        while True:
            if entry.name > self[seek_current].name:
                seek_start = seek_current
                seek_current = int(seek_end - ((seek_end - seek_start) / 2))
                if seek_end - seek_start == 1:
                    last_iteration = True
            elif entry.name < self[seek_current].name:
                seek_end = seek_current
                seek_current = int(seek_start + ((seek_end - seek_start) / 2))
                if seek_end - seek_start == 0:
                    last_iteration = True
            elif entry.name == self[seek_current].name:
                break
            if last_iteration:
                return False

        status, differences = self[seek_current].compare(entry, comp_opts)
        if status:
            return True
        else:
            raise ComparisonDifference(differences)

def compareFilelists(src, dst, mode, smart_crc32, parallel, progress, comp_opts):
    logging.debug('Comparison: starting')
    diff_count = 0
    total = len(src)
    current_file = 0

    for s_entry in src:
        current_file += 1
        try:
            if not dst.searchAndCompare(s_entry, comp_opts):
                if mode == 'complete' or mode == 'missing':
                    diff_count += 1
                    print(f'<{s_entry.name}> missing in destination tree')
                continue
        except ComparisonDifference as e:
            if mode == 'complete':
                diff_count += 1
                print(f'<{s_entry.name}> has got differences:')
                for d in e.differences:
                    print(f'\t{d}')
        else:
            if mode == 'complete' or mode == 'corruption':
                if s_entry.type == FileType.REG and smart_crc32:
                    if progress:
                        prefix = f'CRC32 check ({current_file}/{total} - {current_file/total*100:.1f}%) <'
                        message = f'{s_entry.name}>'
                        print_refresh(prefix+message, prefix_size=len(prefix))

                    if parallel:
                        se_crc32 = threading.Thread(target = src.entryCalculateCRC32, args = (src.getEntry(s_entry.name), ))
                        de_crc32 = threading.Thread(target = dst.entryCalculateCRC32, args = (dst.getEntry(s_entry.name), ))
                        se_crc32.start()
                        de_crc32.start()
                        se_crc32.join()
                        de_crc32.join()
                    else:
                        src.entryCalculateCRC32(src.getEntry(s_entry.name))
                        dst.entryCalculateCRC32(dst.getEntry(s_entry.name))
                    # Compare again
                    try:
                        dst.searchAndCompare(s_entry, comp_opts)
                    except ComparisonDifference as e:
                        diff_count += 1
                        print(f'⚠ WARNING: <{s_entry.name}> has similar metadatas but different CRC32, THERE MIGHT BE CORRUPTION ON ONE SIDE')

    # Required to clean line
    if progress:
        print()

    if not diff_count:
        if mode == 'complete':
            print('Trees are identical\033[K')
        if mode == 'corruption':
            print('No corruption detected\033[K')
    logging.debug('Comparison: finished')
    return diff_count


##
#
# Entry point
#
##

# TODO:
# - in corruption mode, do not discover all destination tree since we only need to find same filenames

parser = argparse.ArgumentParser(description='Compare source tree against tree destination, ex: compare a working tree against its backup', formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('src', help='Source tree')
parser.add_argument('dst', help='Destination tree')
parser.add_argument('-m', '--mode', choices=['complete', 'corruption', 'missing'], default='complete', help='Comparison modes:\n'
                        'complete:\t compare files metadatas and search for missing files, best option to show expected differences (ex: comparison against an old backup)\n'
                        'corruption:\t only look for regular files with similar name/size/modification date but different CRC32, best option to show abnormal differences (ex: comparison against a fresh backup)\n'
                        'missing:\t list files missing in destination\n')
parser.add_argument('-e','--excludes', action='append', help='Excluded folders or files from left and right trees', default=[])
parser.add_argument('-p','--progress', help='Show progress (tree discovery only)', action='store_true', default=False)
parser.add_argument('-d', '--debug', help='Enable debug', action='store_true', default=False)
parser.add_argument('-v', '--verbose', action='count', default=0)
parser.add_argument('--dump', help='Dump file trees', action='store_true', default=False)
parser.add_argument('--parallel', help='Run parallel tree discovery, recommended for trees located on different devices', action=argparse.BooleanOptionalAction, default=True)
parser.add_argument('--compare-permissions', help='Compare permissions (only for complete mode)', action=argparse.BooleanOptionalAction, default=True)
parser.add_argument('--compare-owner', help='Compare owner (only for complete mode)', action=argparse.BooleanOptionalAction, default=True)
parser.add_argument('--compare-group', help='Compare group (only for complete mode)', action=argparse.BooleanOptionalAction, default=True)
parser.add_argument('--compare-suid', help='Compare SUID (only for complete mode)', action=argparse.BooleanOptionalAction, default=True)
parser.add_argument('--compare-guid', help='Compare GUID (only for complete mode)', action=argparse.BooleanOptionalAction, default=True)
parser.add_argument('--compare-sticky', help='Compare sticky bit (only for complete mode)', action=argparse.BooleanOptionalAction, default=True)
parser.add_argument('--compare-file-size', help='Compare file size (only for complete mode)', action=argparse.BooleanOptionalAction, default=True)
parser.add_argument('--compare-directory-size', help='Compare directory size (only for complete mode)', action=argparse.BooleanOptionalAction, default=False)
parser.add_argument('--compare-file-mtime', help='Compare file modified time (only for complete mode)', action=argparse.BooleanOptionalAction, default=True)
parser.add_argument('--compare-directory-mtime', help='Compare directory modified time (only for complete mode)', action=argparse.BooleanOptionalAction, default=False)
parser.add_argument('--compare-ctime', help='Compare creation time (only for complete mode)', action=argparse.BooleanOptionalAction, default=False)
parser.add_argument('--compare-atime', help='Compare access time (only for complete mode)', action=argparse.BooleanOptionalAction, default=False)
parser.add_argument('--compare-symlink', help='Compare symlink target (only for complete mode)', action=argparse.BooleanOptionalAction, default=True)
parser.add_argument('--compare-crc32', choices=['never', 'always', 'smart'], default='smart', help='Hash calculation (CRC32) is highly CPU/IO intensive but is the only way to ensure files are bit-for-bit identical. '
                                                                                                '"smart" parameter will run this calculation only for files that have same metadata values (size, modification date, etc.). '
                                                                                                'Note: this option is only for complete mode (defaults to smart). Set to "smart" in corruption mode and to "never" in missing mode')

args = parser.parse_args()

if args.debug:
    logging.basicConfig(level=logging.DEBUG)
else:
    logging.basicConfig(level=logging.INFO)

s = FileList(os.path.join(args.src, '').encode(), [x.encode() for x in args.excludes if args.excludes is not None])
d = FileList(os.path.join(args.dst, '').encode(), [x.encode() for x in args.excludes if args.excludes is not None])

if args.mode == 'complete':
    discover_crc32 = True if args.compare_crc32 == 'always' else False
    comparison_smart_crc32 = True if args.compare_crc32 == 'smart' else False
    comparison_criterias = {'filemode': args.compare_permissions,
                            'owner': args.compare_owner,
                            'group': args.compare_group,
                            'suid': args.compare_suid,
                            'guid': args.compare_guid,
                            'sticky': args.compare_sticky,
                            'file-size': args.compare_file_size,
                            'directory-size': args.compare_directory_size,
                            'file-mtime': args.compare_file_mtime,
                            'directory-mtime': args.compare_directory_mtime,
                            'ctime': args.compare_ctime,
                            'atime': args.compare_atime,
                            'symlink': args.compare_symlink}

elif args.mode == 'corruption':
    # Force smart CRC32 calculation at comparison step
    discover_crc32 = False
    comparison_smart_crc32 = True
    comparison_criterias = {'filemode': False,
                            'owner': False,
                            'group': False,
                            'suid': False,
                            'guid': False,
                            'sticky': False,
                            'file-size': True,
                            'directory-size': False,
                            'file-mtime': True,
                            'directory-mtime': False,
                            'ctime': False,
                            'atime': False,
                            'symlink': False}

elif args.mode == 'missing':
    discover_crc32 = False
    comparison_smart_crc32 = False
    comparison_criterias = {'filemode': False,
                            'owner': False,
                            'group': False,
                            'suid': False,
                            'guid': False,
                            'sticky': False,
                            'file-size': False,
                            'directory-size': False,
                            'file-mtime': False,
                            'directory-mtime': False,
                            'ctime': False,
                            'atime': False,
                            'symlink': False}


if args.parallel:
    th_s = threading.Thread(target = s.run, args = (args.mode, args.progress, discover_crc32, ))
    th_d = threading.Thread(target = d.run, args = (args.mode, args.progress, discover_crc32, ))
    th_s.start()
    th_d.start()
    th_s.join()
    th_d.join()
else:
    s.run(args.mode, args.progress, discover_crc32)
    d.run(args.mode, args.progress, discover_crc32)

if args.mode == 'complete':    print(f"Source tree: {len(s)} entries")
if args.dump:                   print(s)
if args.mode == 'complete':    print(f"Destination tree: {len(d)} entries")
if args.dump:                   print(d)

if compareFilelists(s, d, args.mode, comparison_smart_crc32, args.parallel, args.progress, comparison_criterias):
    exit(1)
else:
    exit(0)