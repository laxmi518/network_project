import hashlib
import os
import time
import logging

from pylib import disk, pdict

#def file_hash(filename, hash_type_or_func, blocksize=None):
#    if isinstance(hash_type_or_func, basestring):
#        funcs = {
#            "md5":    hashlib.md5,
#            "sha1":   hashlib.sha1,
#            "sha224": hashlib.sha224,
#            "sha256": hashlib.sha256,
#            "sha384": hashlib.sha384,
#            "sha512": hashlib.sha512,
#        }
#        hash_func = funcs[hash_type_or_func]
#    else:
#        hash_func = hash_type_or_func
#
#    blocksize = blocksize or 10*1024
#    h = hash_func()
#    with open(filename, "rb", blocksize) as f:
#        while True:
#            data = f.read(1024)
#            if not data:
#                break
#            h.update(data)
#    return h.hexdigest()
#
#def file_sha1(filename, blocksize=None):
#    return file_hash(filename, "sha1")

def _check_existing_db(db_file):
    # syncing doesn't seem to work in some implementation of dbm or dbhash used by shelve
    # so using pylib.pdict.PersistentDict
    parent = os.path.dirname(db_file)
    shelve_file = os.path.join(parent, "checksums.shelve")
    for old_file in [shelve_file, shelve_file + ".db"]:
        if os.path.exists(old_file):
            os.remove(old_file)

def create_shelve(db_file):
    disk.prepare_path(db_file)
    s = pdict.PersistentDict(db_file, 'c', format='pickle')
    return s

class PartialChecksum:
    def __init__(self, filename, cursor=0):
        h = hashlib.sha1()
        bufsize = 100 * 1024
        self.checksum = ""

        with open(filename, "rb", bufsize) as f:
            while True:
                if cursor > 0 and not self.checksum:
                    to_read = min(cursor - f.tell(), bufsize)
                    if to_read == 0:
                        self.checksum = h.hexdigest()
                        continue
                else:
                    to_read = bufsize
                data = f.read(to_read)
                if not data:
                    self.end_cursor = f.tell()
                    break
                h.update(data)
            self.whole_checksum = h.hexdigest()

    def get_checksum(self):
        return self.checksum

    def get_whole_checksum(self):
        return self.whole_checksum

    def get_end_cursor(self):
        return self.end_cursor

class VersionChecker:
    def __init__(self, db_file, sid, remotefile, mtime=None, old_logs=True):
        # TODO: delete old data to limit size
        _check_existing_db(db_file)
        self.checksums_shelve = create_shelve(db_file)
        self.sid = sid
        self.remotefile = remotefile
        self.mtime = mtime
        self.new_version = None
        self.new_file = False
        self.old_logs = old_logs

    def is_newer_version(self):
        try:
            self.remotefile_props = self.checksums_shelve[self.sid][self.remotefile]
            logging.info("%r is an old file", self.remotefile)
        except KeyError:
            logging.info("%r is a new file", self.remotefile)
            self.new_file = True
            result = True
        else:
            if self.mtime is None:
                result = True
            elif self.mtime == self.remotefile_props["mtime"]:
                result = False
                logging.info("mtime has not changed for %r. so will not be downloaded.", self.remotefile)
            else:
                result = True
                logging.info("mtime changed from %r to %r for %r. so will be downloaded.",
                        self.remotefile_props["mtime"], self.mtime, self.remotefile)
        self.new_version = result
        return result

    def is_older_version(self):
        return not self.is_newer_version()

    def get_old_cursor(self, localfile):
        if self.new_version is None:
            self.is_newer_version()
        if self.new_file:
            partialchecksum = PartialChecksum(localfile)
            _update_checksum_shelve(self.checksums_shelve, self.sid, self.remotefile, localfile,
                    partialchecksum.get_whole_checksum(), partialchecksum.get_end_cursor(), self.mtime)
            if self.old_logs:
                return 0
            else:
                return -1
        if self.new_version is False:
            logging.warning("%r hasn't changed. it will not be indexed.", self.remotefile)
            return -1

        # TODO: check for plain log file. for non-plain files return cursor = 0 immediately
        old_version_cursor = self.remotefile_props["cursor"]
        old_version_checksum = self.remotefile_props["checksum"]

        partialchecksum = PartialChecksum(localfile, old_version_cursor)
        new_end_cursor = partialchecksum.get_end_cursor()
        _update_checksum_shelve(self.checksums_shelve, self.sid, self.remotefile, localfile,
                partialchecksum.get_whole_checksum(), new_end_cursor, self.mtime)

        if partialchecksum.get_checksum() == old_version_checksum:
            if new_end_cursor > old_version_cursor:
                logging.info("%r was appended, so will be indexed from the last cursor=%d", self.remotefile, old_version_cursor)
                return old_version_cursor
            else:
                logging.info("%r has not changed, so will not be forwarded to batch_processor", self.remotefile)
                return -1
        else:
            logging.info("%r was truncated, so will be indexed from the start of the file.", self.remotefile)
            return 0

def _update_checksum_shelve(checksums_shelve, sid, remotefile, localfile, checksum, cursor, mtime):
    remotefiles = checksums_shelve.get(sid)
    if not remotefiles:
        remotefiles = {}

    remotefiles[remotefile] = {
        "checksum": checksum,
        "cursor": cursor,
        "mtime": mtime,
        "filesize": os.path.getsize(localfile),
        "last_fetch": int(time.time()),
    }
    checksums_shelve[sid] = remotefiles
    checksums_shelve.sync()
