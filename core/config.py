import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    """Configuration management for Wazuh MCP"""
    
    # Elasticsearch/OpenSearch settings
    OPENSEARCH_HOST = os.getenv('WAZUH_HOST')
    OPENSEARCH_PORT = int(os.getenv('WAZUH_PORT'))
    OPENSEARCH_USERNAME = os.getenv('WAZUH_USERNAME')
    OPENSEARCH_PASSWORD = os.getenv('WAZUH_PASSWORD')
    
    # Wazuh API settings
    WAZUH_API_HOST = os.getenv('WAZUH_API_HOST')
    WAZUH_API_PORT = int(os.getenv('WAZUH_API_PORT', 55000))
    
    # General settings
    DEBUG = os.getenv('DEBUG', 'false').lower() == 'true'
    
    @property
    def opensearch_url(self):
        return f"https://{self.OPENSEARCH_HOST}:{self.OPENSEARCH_PORT}"
    
    @property
    def wazuh_api_url(self):
        return f"https://{self.WAZUH_API_HOST}:{self.WAZUH_API_PORT}"

# Global config instance
# config = Config()