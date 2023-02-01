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

    # Processed dictionary holding all APTs associated with threat_actor.refs mitre references
    mitre_apts = {}

    i = 0
    for threat_actor in apts[VALUES]:
        #print(50*"-")
        #print(threat_actor)
        #print(50*"-")
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


                        mitre_apts[group_id] = threat_actor
                        mitre_apts[group_id]['gid'] = group_id
                        
    
    
    dump_apts(mitre_apts)




if __name__ == '__main__':
    process_apts(apt_data)