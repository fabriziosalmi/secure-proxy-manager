#!/bin/bash

set -e # Exit on error

# Download and merge blocklists
download_and_merge_blocklists() {
    local blocklist_type="$1"
    local local_file="$2"
    echo "Merging ${blocklist_type} blocklists into $local_file"

    > "$local_file" # Clear the file

    local sources=$(jq -c ".blocklists.${blocklist_type}.sources[]" /config.yaml)

    if [[ -z "$sources" ]] || [[ "$sources" == "null" ]] ; then
        echo "No sources found for ${blocklist_type} skipping download"
        return
    fi

    local IFS=$'\n'
    for source in $(echo "$sources" | jq -c '.[]'); do
        local source_name=$(echo "$source" | jq -r '.name')
        local source_url=$(echo "$source" | jq -r '.url')
        local source_format=$(echo "$source" | jq -r '.format')
        local temp_file
        temp_file=$(mktemp)
    
       if [[ -z "$source_url" ]] ; then
            echo "Source URL is empty. Skipping download."
            rm "$temp_file"
           continue
      fi
      
        echo "Downloading ${blocklist_type} blocklist '$source_name' from $source_url"
        
        curl -s "$source_url" -o "$temp_file"
        if [ $? -ne 0 ] ; then
            echo "Download failed for ${blocklist_type} blocklist '$source_name' from $source_url"
            rm "$temp_file"
             continue  # Skip to next source
        fi
         if [[ "$source_format" == "hosts" ]]; then
            # Remove comments and extract only domains
            grep -v '^#' "$temp_file" | awk '{print $2}' >> "$local_file"
        elif [[ "$source_format" == "netset" ]]; then
            cat "$temp_file" >> "$local_file"
        else
             echo "unsupported format ${source_format} skipping merging ${source_name}"
        fi

        rm "$temp_file"
    done
    echo "${blocklist_type} blocklist merging finished"
}
# Process config.yaml
CONFIG_YAML="/config.yaml"
if [ ! -f "$CONFIG_YAML" ]; then
  echo "Error: Configuration file '$CONFIG_YAML' not found."
  exit 1
fi
#install yq
DEBIAN_FRONTEND=noninteractive apt install -y jq
# Download and process blocklists from yaml config
download_and_merge_blocklists "dns" "$(jq -r '.blocklists.dns.local_file' "$CONFIG_YAML")"
download_and_merge_blocklists "ip" "$(jq -r '.blocklists.ip.local_file' "$CONFIG_YAML")"

#override config with env variables
set -a # Export all variables as environment variables
if [[ ! -z "$SQUID_PORT" ]]; then export SQUID_PORT=$(echo "$SQUID_PORT" | sed -E 's/[^0-9]+//g'); fi
if [[ ! -z "$SQUID_CACHE_SIZE" ]]; then export SQUID_CACHE_SIZE=$(echo "$SQUID_CACHE_SIZE" | sed -E 's/[^0-9]+//g'); fi

if [[ ! -z "$SQUID_EXTERNAL_DNS_ENABLED" ]]; then export SQUID_EXTERNAL_DNS_ENABLED=$(echo "$SQUID_EXTERNAL_DNS_ENABLED" | sed -E 's/[^a-z]+//ig'); fi
if [[ ! -z "$SQUID_EXTERNAL_DNS_RESOLVERS" ]]; then export SQUID_EXTERNAL_DNS_RESOLVERS=$(echo "$SQUID_EXTERNAL_DNS_RESOLVERS"  | sed -E 's/(,$)|(,,+)/,/g;s/^,|,$//g'); fi

if [[ ! -z "$SQUID_HTTPS_ENABLED" ]]; then export SQUID_HTTPS_ENABLED=$(echo "$SQUID_HTTPS_ENABLED" | sed -E 's/[^a-z]+//ig'); fi
if [[ ! -z "$SQUID_HTTPS_PORT" ]]; then export SQUID_HTTPS_PORT=$(echo "$SQUID_HTTPS_PORT" | sed -E 's/[^0-9]+//g'); fi
if [[ ! -z "$SQUID_HTTPS_SSL_CERT" ]]; then export SQUID_HTTPS_SSL_CERT="$SQUID_HTTPS_SSL_CERT"; fi
if [[ ! -z "$SQUID_HTTPS_SSL_KEY" ]]; then export SQUID_HTTPS_SSL_KEY="$SQUID_HTTPS_SSL_KEY"; fi

if [[ ! -z "$BLOCKLISTS_DNS_ENABLED" ]]; then export BLOCKLISTS_DNS_ENABLED=$(echo "$BLOCKLISTS_DNS_ENABLED" | sed -E 's/[^a-z]+//ig'); fi
if [[ ! -z "$BLOCKLISTS_IP_ENABLED" ]]; then export BLOCKLISTS_IP_ENABLED=$(echo "$BLOCKLISTS_IP_ENABLED" | sed -E 's/[^a-z]+//ig'); fi

if [[ ! -z "$WHITELIST_ENABLED" ]]; then export WHITELIST_ENABLED=$(echo "$WHITELIST_ENABLED" | sed -E 's/[^a-z]+//ig'); fi
if [[ ! -z "$WHITELIST_IPS" ]]; then export WHITELIST_IPS=$(echo "$WHITELIST_IPS"  | sed -E 's/(,$)|(,,+)/,/g;s/^,|,$//g'); fi
if [[ ! -z "$WHITELIST_DOMAIN_ALLOWLIST" ]]; then export WHITELIST_DOMAIN_ALLOWLIST=$(echo "$WHITELIST_DOMAIN_ALLOWLIST" | sed -E 's/(,$)|(,,+)/,/g;s/^,|,$//g'); fi

if [[ ! -z "$NETWORK_ALLOW_DIRECT" ]]; then export NETWORK_ALLOW_DIRECT=$(echo "$NETWORK_ALLOW_DIRECT" | sed -E 's/[^a-z]+//ig'); fi
if [[ ! -z "$AUTHENTICATION_ENABLED" ]]; then export AUTHENTICATION_ENABLED=$(echo "$AUTHENTICATION_ENABLED" | sed -E 's/[^a-z]+//ig'); fi
if [[ ! -z "$AUTHENTICATION_USERS" ]]; then export AUTHENTICATION_USERS="$AUTHENTICATION_USERS"; fi

set +a
# generate the squid config file
# jq needs to be installed in the dockerfile
envsubst < /squid-config/squid.conf.template  > /etc/squid/squid.conf

# Generate user file for authentication
if [[ "$(jq -r '.authentication.enabled' "$CONFIG_YAML")" == "true" ]] ; then
	if [[ ! -z "$AUTHENTICATION_USERS" ]]; then
		 echo "Generating user authentication file using environment variables"
       echo "$AUTHENTICATION_USERS"  | sed 's/,/\n/g'| awk -F: '{print $1":$(openssl passwd -crypt "$2")"}'  > /etc/squid/users
	 else
        echo "Generating user authentication file"
        awk -F: '{print $1":$(openssl passwd -crypt "$2")"}' /config.yaml | awk '/^users:/ {n=1;next} n {print}' | grep -v '^$' > /etc/squid/users
	 fi
fi
echo "Squid configuration generated successfully!"
