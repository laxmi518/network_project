
"""
Supported files:
.gz, .gzip, .bz2, .zip, .tar, .tar.gz, .tar.bz2

Reference: setuptools/archive_util.py
"""

import bz2
import gzip
import logging
import tarfile
import zipfile

from pylib import filetype

BYTES = 1024  # 1 KB
log = logging.getLogger(__name__)


class UnrecognizedFormat(Exception):
    """Couldn't recognize the archive type"""


def file_iterator(fileobj, bufsize):
    """generates file contents by reading bufsize bytes
    """
    while True:
        data = fileobj.read(bufsize)
        if not data:
            break
        yield data


def unpack_plaintext(filename, cursor=0, bytes=BYTES):
    with open(filename, 'rb', bytes) as f:
        f.seek(cursor)
        for data in file_iterator(f, bytes):
            yield data


def unpack_gzip(filename, bytes=BYTES):
    f = gzip.open(filename, 'rb')

    try:
        for data in file_iterator(f, bytes):
            yield data
    except IOError, err:
        if str(err) == "Not a gzipped file":
            raise UnrecognizedFormat("%s is not a gzip file." % (filename))
    finally:
        f.close()


def unpack_bz2(filename, bytes=BYTES):
    f = bz2.BZ2File(filename, 'rb', bytes)

    try:
        for data in file_iterator(f, bytes):
            yield data
    except IOError, err:
        if str(err) == "invalid data stream":
            raise UnrecognizedFormat("%s is not a bz2 file." % (filename))
    finally:
        f.close()


def unpack_zip(filename, bytes=BYTES):
    """Raises ``UnrecognizedFormat`` if `filename` is not a zipfile (as determined
    by ``zipfile.is_zipfile()``).
    """

    if not zipfile.is_zipfile(filename):
        raise UnrecognizedFormat("%s is not a zip file." % (filename))

    z = zipfile.ZipFile(filename)
    try:
        for info in z.infolist():
            name = info.filename

            # don't extract absolute paths or ones with .. in them or dir paths
            if name.startswith('/') or '..' in name or name.endswith('/'):
                continue

            data = z.read(info.filename)
            yield data
    finally:
        z.close()


def unpack_tar(filename, bytes=BYTES, mode='r'):
    """Raises ``UnrecognizedFormat`` if `filename` is not a tarfile (as determined
    by ``tarfile.is_tarfile()``).
    """

    if not tarfile.is_tarfile(filename):
        raise UnrecognizedFormat("%s is not a tar file." % (filename))

    tarobj = tarfile.open(filename, mode, bufsize=bytes)
    try:
        for member in tarobj:
            if member.isfile():
                name = member.name

                # don't extract absolute paths or ones with .. in them
                if name.startswith('/') or '..' in name:
                    continue

                f = tarobj.extractfile(member)
                for data in file_iterator(f, bytes):
                    yield data
                f.close()
    finally:
        tarobj.close()


def unpack(filename, cursor=0, bytes=BYTES):
    type_, subtype = filetype.filetype(filename)

    if type_ == 'text':
        return unpack_plaintext(filename, cursor, bytes)

    elif type_ == 'application':
        if subtype in ['x-gzip']:
            if tarfile.is_tarfile(filename):
                return unpack_tar(filename, bytes, 'r:gz')
            else:
                return unpack_gzip(filename, bytes)

        elif subtype in ['zip']:
            return unpack_zip(filename, bytes)

        elif subtype in ['x-bzip2']:
            if tarfile.is_tarfile(filename):
                return unpack_tar(filename, bytes, 'r:bz2')
            else:
                return unpack_bz2(filename, bytes)

        elif subtype in ['x-tar']:
            return unpack_tar(filename, bytes)

        elif subtype in ['xml']:
            return unpack_plaintext(filename, cursor, bytes)

        elif subtype in ['x-empty']:
            # given file is empty
            return ()

    raise UnrecognizedFormat("%s/%s: %s not supported for unpacking" % (type_, subtype, filename))


if __name__ == '__main__':
    print list(unpack('tests.tar.gz'))
