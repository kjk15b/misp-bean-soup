import json
import re
import sys

apt_data = None

try:
    with open('threat-actor.json', 'r') as f:
        apt_data = json.load(f)
except FileNotFoundError:
    print("Couldn't find threat actors...")
    sys.exit(-1)

# GIDS in MITRE that are not tracked here in MISP-Galaxy
# See https://attack.mitre.org/groups/<gid> for context
unaccounted_for_apts = [
    "G1003", "G0123", "G1005", "G0115", "G0133",
    "G0116", "G0114", "G0134", "G1002", "G0137",
    "G0028", "G0073", "G0105", "G0057", "G0132",
    "G1007", "G0090", "G0074", "G0091", "G0092",
    "G0108", "G0142", "G0101", "G1004", "G1006",
    "G0117", "G0094", "G0139", "G0141", "G0103",
    "G0128", "G0135", "G0140", "G0138", "G0042",
    "G1001", "G0093", "G0098", "G0013", "G0121",
    "G0136", "G1009", "G0084", "G0005", "G0126",
    "G0089", "G0124", "G0118", "G0119", "G0120",
    "G0143", "G1008", "G0131", "G0104", "G0122",
    "G0083", "G0099", "G1011", "G0129", "G0102",
    "G0106", "G0112", "G0107", "G0022", "G0130"
]

def dump_apts(apts : dict):
    with open('processed-apts.json', 'w') as f:
        f.write(json.dumps(apts, indent=3))


def process_apts(apts : dict):
    '''
    Cycle APTs from MISP-Galaxy and extract only ones with refs to MITRE ATT&CK
    '''

    # Below are field values seen in the JSON schema
    # Not all fields are populated for every APT, so this is
    # to better flesh out the JSON with default values
    VALUES        = 'values'
    META          = 'meta'
    ATR_CONF      = 'attribution-confidence'         # DEFAULT '0'
    STATE_SPONSOR = 'cfr-suspected-state-sponsor'    # DEFAULT 'Unknown'
    VICTIMS       = 'cfr-suspected-victims'          # DEFAULT []
    TARGET        = 'cfr-target-category'            # DEFAULT []
    INCIDENT      = 'cfr-type-of-incident'           # DEFAULT 'Unknown'
    COUNTRY       = 'country'                        # DEFAULT 'Unknown'
    REFS          = 'refs'                           # DEFAULT []
    ALIAS         = 'synonyms'                       # DEFAULT []
    VALUE         = 'value'
    DESC          = 'description'                    # DEFAULT GID
    GID           = 'gid'                            # DEFAULT GID

    # Processed dictionary holding all APTs associated with threat_actor.refs mitre references
    mitre_apts = {}

    i = 0
    for threat_actor in apts[VALUES]:
        if META in threat_actor.keys(): # check that we have metadata
            if REFS in threat_actor[META].keys(): # Check that we have refs to scan for MITRE references
                group_id = ''
                for ref in threat_actor[META][REFS]:
                    #print('{} : {}'.format(ref, re.search('attack.mitre.org', ref)))
                    if re.search('attack.mitre.org', ref):
                        group_id = re.sub('\/', '', re.sub('https:\/\/attack.mitre.org\/groups\/', '', ref))
                        # Now we need to do some spring cleaning with the metadata to check for fields that don't exist
                        
                        # check for confidence levels
                        if ATR_CONF not in threat_actor[META].keys():
                            threat_actor[META][ATR_CONF] = '0'

                        # check for State Sponsor
                        if STATE_SPONSOR not in threat_actor[META].keys():
                            threat_actor[META][STATE_SPONSOR] = 'Unknown'

                        # check for victims
                        if VICTIMS not in threat_actor[META].keys():
                            threat_actor[META][VICTIMS] = []

                        # check for targets
                        if TARGET not in threat_actor[META].keys():
                            threat_actor[META][TARGET] = []

                        # check for incident(s)
                        if INCIDENT not in threat_actor[META].keys():
                            threat_actor[META][INCIDENT] = 'Unknown'

                        # check for country
                        if COUNTRY not in threat_actor[META].keys():
                            threat_actor[META][COUNTRY] = 'Unknown'

                        # check for aliases
                        if ALIAS not in threat_actor[META].keys():
                            threat_actor[META][ALIAS] = []

                        if DESC not in threat_actor.keys():
                            threat_actor[META][DESC] = ''
                        else:
                            threat_actor[META][DESC] = threat_actor[DESC]
                        threat_actor[META][VALUE] = threat_actor[VALUE]

                        mitre_apts[group_id] = threat_actor[META]
                        mitre_apts[group_id][GID] = group_id
                        
    # Now we need to account for GIDs that MITRE is tracking, but MISP is not
    for unaccounted_apt in unaccounted_for_apts:
        meta = {
            ATR_CONF      : '0', # confidence levels
            STATE_SPONSOR : 'Unknown',
            VICTIMS       : [],
            TARGET        : [],
            INCIDENT      : '',
            COUNTRY       : 'Unknown',
            ALIAS         : [],
            DESC          : '',
            GID           : unaccounted_apt,
            VALUE         : unaccounted_apt
        }
        mitre_apts[unaccounted_apt] = meta
    
    dump_apts(mitre_apts)




if __name__ == '__main__':
    process_apts(apt_data)