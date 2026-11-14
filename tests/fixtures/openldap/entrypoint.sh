#!/bin/sh
# Start slapd, load the seed once it answers, and stay in the foreground.
set -e
# /run is empty in a container: slapd writes its pid file here.
mkdir -p /var/run/slapd && chown openldap:openldap /var/run/slapd
slapd -h "ldap:///" -u openldap -g openldap
for i in $(seq 1 50); do
  ldapsearch -x -H ldap://localhost -b dc=example,dc=com -s base >/dev/null 2>&1 && break
  sleep 0.2
done
ldapadd -x -H ldap://localhost -D cn=admin,dc=example,dc=com -w admin-pass-123 -f /seed.ldif >/dev/null
echo "openldap ready"
exec tail -f /dev/null
