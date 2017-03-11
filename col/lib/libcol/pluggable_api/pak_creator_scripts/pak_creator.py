
import os
import sys
import zipfile
from beefish import encrypt

PASSWORD = "LoGPo!nT%$^&~#"

def zip_dir(path):
    """
    """
    
    zip = zipfile.ZipFile("%s.zip" % path, "w")
    for root, dirs, files in os.walk(path):
        for file in files:
            zip.write(os.path.join(root, file))
    zip.close()

def main():
    """
    """
    if len(sys.argv) != 2:
        print "Expected APPLICATION folder as input"
        sys.exit(0)
    
    path = sys.argv[1]
    zip_dir(path)
    
    with open("%s.zip" % path) as fh:
        with open("%s.pak" % path, "wb") as out_fh:
            encrypt(fh, out_fh, PASSWORD)

if __name__ == "__main__":
    main()
