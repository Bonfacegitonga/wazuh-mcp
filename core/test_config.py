from config import config
  # assuming your code is in config.py

print("Opensearch settings:")
print("  Host:", config.OPENSEARCH_HOST)
print("  Port:", config.OPENSEARCH_PORT)
print("  Username:", config.OPENSEARCH_USERNAME)
print("  Password:", config.OPENSEARCH_PASSWORD)
print("  URL:", config.opensearch_url)

print("\nWazuh API settings:")
print("  Host:", config.WAZUH_API_HOST)
print("  Port:", config.WAZUH_API_PORT)
print("  URL:", config.wazuh_api_url)

print("\nDebug Mode:", config.DEBUG)
