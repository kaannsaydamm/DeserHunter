import pickle
import yaml
import json

def load_data(data):
    # Safe
    print(json.loads(data))
    
    # Vulnerable: Pickle
    # POTENTIAL RCE
    obj = pickle.load(data)
    
    # Vulnerable: PyYAML
    config = yaml.load(data)
    
    # Safe YAML
    safe_config = yaml.safe_load(data)
