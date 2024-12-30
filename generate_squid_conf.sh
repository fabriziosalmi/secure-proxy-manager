#!/bin/bash

set -e # Exit on error

# Download and merge blocklists
download_and_merge_blocklists() {
    local blocklist_type="$1"
    local local_file="$2"
    echo "Merging ${blocklist_type} blocklists into $local_file"
    
    > "$local_file" # Clear the file
    
    while IFS= read -r source; do
        local source_name=$(echo "$source" | jq -r '.name')
        local source_url=$(echo "$source" | jq -r '.url')
        local source_format=$(echo "$source" | jq -r '.format')
        local temp_file
        temp_file=$(mktemp)
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
    done < <(jq -c ".blocklists.${blocklist_type}.sources[]" /config.yaml)
    echo "${blocklist_type} blocklist merging finished"
}

# Process config.yaml
CONFIG_YAML="/config.yaml"
if [ ! -f "$CONFIG_YAML" ]; then
  echo "Error: Configuration file '$CONFIG_YAML' not found."
  exit 1
fi
#install yq
apk --no-cache add jq

# Download and process blocklists from yaml config
download_and_merge_blocklists "dns" "$(jq -r '.blocklists.dns.local_file' "$CONFIG_YAML")"
download_and_merge_blocklists "ip" "$(jq -r '.blocklists.ip.local_file' "$CONFIG_YAML")"


# generate the squid config file
# jq needs to be installed in the dockerfile
envsubst < /squid-config/squid.conf.template  > /etc/squid/squid.conf

# Generate user file for authentication
if [[ "$(jq -r '.authentication.enabled' "$CONFIG_YAML")" == "true" ]] ; then
        echo "Generating user authentication file"
        awk -F: '{print $1":$(openssl passwd -crypt "$2")"}' /config.yaml | awk '/^users:/ {n=1;next} n {print}' | grep -v '^$' > /etc/squid/users
fi
echo "Squid configuration generated successfully!"
