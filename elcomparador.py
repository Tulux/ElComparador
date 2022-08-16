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


def crc32(filename):
    with open(filename, 'rb') as fh:
        hash = 0
        while True:
            s = fh.read(65536)
            if not s:
                break
            hash = zlib.crc32(s, hash)
        return "%08X" % (hash & 0xFFFFFFFF)

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
    def __init__(self, name, stats = None, symlink = None, crc32 = None, inaccessible = False):
        self.name = name
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
        self.symlink = symlink
        self.crc32 = crc32
        self.inaccessible = inaccessible
        self.type = FileType.DIR if stat.S_ISDIR(stats.st_mode) else \
                    FileType.REG if stat.S_ISREG(stats.st_mode) else \
                    FileType.LNK if stat.S_ISLNK(stats.st_mode) else None
        if self.type is None:
            raise ValueError("Unknown file type")

    def __str__(self):
        ret = "=" * 50 + "\n"
        ret += "{}\n".format(self.name.decode())
        ret += "Type: "
        match self.type:
            case FileType.DIR:
                ret += "Directory\n"
            case FileType.REG:
                ret += "Regular\n"
            case FileType.LNK:
                ret += "Symbolic Link, target: {}\n".format(self.symlink.decode())
        if self.inaccessible:
            ret += " [INACCESSIBLE]\n"
        else:
            ret += ("Mode: {}\n"
                    "Owner: {}\n"
                    "Group: {}\n"
                    "SUID: {}\n"
                    "GUID: {}\n"
                    "Sticky bit: {}\n"
                    "Creation date: {}\n"
                    "Modification date: {}\n"
                    "Access date: {}\n").format(self.filemode,
                                           self.owner,
                                           self.group,
                                           self.suid,
                                           self.guid,
                                           self.sticky,
                                           datetime.datetime.fromtimestamp(self.ctime).strftime("%Y-%m-%dT%H:%M:%S%z"),
                                           datetime.datetime.fromtimestamp(self.mtime).strftime("%Y-%m-%dT%H:%M:%S%z"),
                                           datetime.datetime.fromtimestamp(self.atime).strftime("%Y-%m-%dT%H:%M:%S%z"))
            ret += "Size: {}\nCRC32: {}\n".format(humanize.naturalsize(self.size), self.crc32) if self.type == FileType.REG else ""
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
            if opts['crc32'] and self.crc32 != other.crc32:
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
                try:
                    print('{} files ({} total), {:.0f}s (~{}/s) - {}'.format(self.monit_file_count,
                                                                         humanize.naturalsize(self.monit_total_size),
                                                                         current - start,
                                                                         humanize.naturalsize(self.monit_total_size/(current - start)),
                                                                         self.monit_current_file.decode()), end = '\r')
                except UnicodeDecodeError as e:
                    logging.debug(e)
                    logging.debug(self.monit_current_file)
                    exit(0)
                self.monit_lock.release()
            time.sleep(1)

    # Return all files and directories from a given path
    def browse(self, path, excludes, flag_crc32):
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
                            logging.warning('<{}> exists but cannot be accessed: '.format(f.name.decode()))
                            self.flist.append(Entry(name=f.name, inaccessible=True))
                    else:
                        # Excluding types other than directory, regular and symlink
                        if stat.S_ISDIR(stats.st_mode) or \
                           stat.S_ISREG(stats.st_mode) or \
                           stat.S_ISLNK(stats.st_mode):
                            crc = crc32(fullpath) if flag_crc32 and stat.S_ISREG(stats.st_mode) else None
                            target = os.readlink(f) if stat.S_ISLNK(stats.st_mode) else None
                            self.flist.append(Entry(name=fullpath.removeprefix(self.path), stats=stats, symlink=target, crc32=crc))
                            self.monit_lock.acquire()
                            self.monit_total_size += stats.st_size
                            self.monit_lock.release()
                            if stat.S_ISDIR(stats.st_mode):
                                self.browse(fullpath, excludes, flag_crc32)
        except OSError as e:
            logging.warning('<{}> cannot be listed'.format(path.decode()))

    def run(self, flag_progress, flag_crc32):
        if flag_progress:
            monit = threading.Thread(target=self.monitor)
            monit.start()
        self.browse(self.path, self.excludes, flag_crc32)
        self.monit_lock.acquire()
        self.monit_current_file = '' # Stop thread
        self.monit_lock.release()
        # Sort file list
        tmp_flist = sorted(self.flist, key=lambda e: e.name)
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
    def searchandcompare(self, entry, comp_opts):
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
                if seek_end - seek_start == 1 and seek_start != 0:
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

def compare_filelists(left, right, mode, comp_opts):
    if mode == 'ref_right':
        diff_count = 0
        for r_entry in right:
            try:
                if not left.searchandcompare(r_entry, comp_opts):
                    diff_count += 1
                    print('{} missing in left tree'.format(os.path.join(right.path, r_entry.name).decode()))
            except ComparisonDifference as e:
                diff_count += 1
                print('{} has got differences:'.format(os.path.join(right.path, r_entry.name).decode()))
                for d in e.differences:
                    print('\t{}'.format(d))
        if not diff_count:
            print('Trees are identical')
        return diff_count


##
#
# Entry point
#
##

logging.basicConfig(level=logging.INFO)
parser = argparse.ArgumentParser(description='Compare 2 file trees, ex: compare a folder and its backup', formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('left', help='Left tree')
parser.add_argument('right', help='Right tree')
parser.add_argument('-m', '--mode', help='Comparison mode:\n'
                                         '\tref_right:\t make sure any files from right tree exists in left one (default)\n'
                                         '\tref_left:\t make sure any files from left tree exists in right one\n'
                                         '\tfull:\t\t combine ref_right and ref_left', default="ref_right")
parser.add_argument('-e','--excludes', action='append', help='Excluded folders or files from left and right trees', default=[])
parser.add_argument('-p','--progress', help='Show progress', action='store_true', default=False)
parser.add_argument('--parallel', help='Run parallel trees discovery, recommended for trees located on different devices', action=argparse.BooleanOptionalAction, default=True)
parser.add_argument('--compare-permissions', help='Compare permissions', action=argparse.BooleanOptionalAction, default=True)
parser.add_argument('--compare-owner', help='Compare owner', action=argparse.BooleanOptionalAction, default=True)
parser.add_argument('--compare-group', help='Compare group', action=argparse.BooleanOptionalAction, default=True)
parser.add_argument('--compare-suid', help='Compare SUID', action=argparse.BooleanOptionalAction, default=True)
parser.add_argument('--compare-guid', help='Compare GUID', action=argparse.BooleanOptionalAction, default=True)
parser.add_argument('--compare-sticky', help='Compare sticky bit', action=argparse.BooleanOptionalAction, default=True)
parser.add_argument('--compare-file-size', help='Compare file size', action=argparse.BooleanOptionalAction, default=True)
parser.add_argument('--compare-directory-size', help='Compare directory size', action=argparse.BooleanOptionalAction, default=False)
parser.add_argument('--compare-file-mtime', help='Compare file modified time', action=argparse.BooleanOptionalAction, default=True)
parser.add_argument('--compare-directory-mtime', help='Compare directory modified time', action=argparse.BooleanOptionalAction, default=False)
parser.add_argument('--compare-ctime', help='Compare creation time', action=argparse.BooleanOptionalAction, default=False)
parser.add_argument('--compare-atime', help='Compare access time', action=argparse.BooleanOptionalAction, default=False)
parser.add_argument('--compare-symlink', help='Compare symlink target', action=argparse.BooleanOptionalAction, default=True)
parser.add_argument('--compare-crc32', help='Compare crc32', action=argparse.BooleanOptionalAction, default=True)

args = parser.parse_args()

l = FileList(os.path.join(args.left, '').encode(), [x.encode() for x in args.excludes if args.excludes is not None])
r = FileList(os.path.join(args.right, '').encode(), [x.encode() for x in args.excludes if args.excludes is not None])

if args.parallel:
    th_l = threading.Thread(target = l.run, args = (args.progress, args.compare_crc32, ))
    th_r = threading.Thread(target = r.run, args = (args.progress, args.compare_crc32, ))
    th_l.start()
    th_r.start()
    th_l.join()
    th_r.join()
else:
    l.run(args.progress, args.compare_crc32)
    r.run(args.progress, args.compare_crc32)

print("Left tree: {} entries".format(len(l)))
print("Right tree: {} entries".format(len(r)))

compare_filelists(l, r, args.mode, {'filemode': args.compare_permissions,
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
                                           'symlink': args.compare_symlink,
                                           'crc32': args.compare_crc32})
