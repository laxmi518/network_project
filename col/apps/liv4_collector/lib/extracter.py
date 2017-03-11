import tarfile
import os
import shutil
import logging

from pylib import disk

def get_repoinfo(db, repo):
    return db.datatransport.find_one({"repo": repo})

def extract(filepath, db, config, updater):
    repo = config["repo"]
    repoinfo = get_repoinfo(db, repo)
    localdir = repoinfo.get("extracted_dir")
    if localdir:
        logging.warn("file already extracted at %r", localdir)
        return localdir

    logging.warn("extracting %r", filepath)
    updater.update_stat("extracting")
    cwd = os.path.abspath(os.curdir)

    destination = os.path.join(os.path.dirname(filepath), "extracted")
    disk.prepare_path(destination + '/')

    subtype = repoinfo["subtype"]
    if subtype in ["x-gzip"]:
        mode = 'r:gz'
    elif subtype in ["x-bzip2"]:
        mode = 'r:bz2'
    elif subtype in ["x-tar"]:
        mode = 'r:'
    else:
        raise Exception("File %s has mime subtype %s which is not supported. Only 'x-gzip' and 'x-bzip2' supported" %
                (filepath, subtype))

    try:
        tfile = tarfile.open(filepath, mode)
        tfile.extractall(destination)
    except:
        for key in ["downloaded_file", "subtype", "time"]:
            db.datatransport.update({"repo": repo}, {"$unset": {key: 1}})
        db.datatransport.update({"repo": repo}, {"$set": {"status": "Uploaded file is corrupted. Please upload valid file."}})
        os.unlink(filepath)
        shutil.rmtree(destination)
        raise

    db.datatransport.update({"repo": repo}, {"$set": {"extracted_dir": destination}})

    os.chdir(cwd)
    updater.update_stat("extracted")
    return destination
