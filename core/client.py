import requests
import urllib3
from requests.auth import HTTPBasicAuth
from .config import Config

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
config=Config()
class WazuhClient:
    """Base client for Wazuh API interactions"""
    
    def __init__(self):
        self.es_url = config.opensearch_url
        self.api_url = config.wazuh_api_url
        self.auth = HTTPBasicAuth(
            config.OPENSEARCH_USERNAME, 
            config.OPENSEARCH_PASSWORD
        )
        self.headers = {'Content-Type': 'application/json'}
    
    def _es_request(self, endpoint, query):
        """Make Elasticsearch request"""
        url = f"{self.es_url}/{endpoint}"
        try:
            response = requests.post(
                url, 
                json=query, 
                auth=self.auth, 
                verify=False,
                headers=self.headers
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            return {"error": str(e)}
    
    def _api_request(self, endpoint, method='GET', data=None):
        """Make Wazuh API request"""
        url = f"{self.api_url}/{endpoint}"
        try:
            if method.upper() == 'GET':
                response = requests.get(url, auth=self.auth, verify=False)
            else:
                response = requests.post(
                    url, 
                    json=data, 
                    auth=self.auth, 
                    verify=False,
                    headers=self.headers
                )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            return {"error": str(e)}
    
    def search_index(self, index, query):
        """Search specific Wazuh index"""
        return self._es_request(f"{index}/_search", query)
    

    