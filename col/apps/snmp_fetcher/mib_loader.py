import logging

mib_dir = '/opt/immune/storage/col/snmp_fetcher/mibs'
mib_modules_record = '/opt/immune/storage/col/snmp_fetcher/mib_modules'

def load_mibs():
    loaded_module_count = 0
    logging.warn("Loading MIB Modules for MibLookup...")
    with open(mib_modules_record, 'r') as f:
        for module in f.readlines():
            logging.warn("Loading Module: %s" % module.rstrip())
            loaded_module_count += 1
            yield module.rstrip()
    if not loaded_module_count:
        logging.warn("No modules specified. Mib Modules Not Loaded")
    else:
        logging.warn("Successfully Loaded %s MIB Modules" % loaded_module_count)


