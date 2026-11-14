# A throwaway OpenLDAP for the proxy login tests (tests/shell/proxy_login_ldap_test.sh).
# Built from the Ubuntu base the proxy uses; never shipped. lldap answers a
# wrong password with a protocol error instead of invalidCredentials (49), so
# Squid's helper reports BH rather than ERR: OpenLDAP behaves as directories
# (OpenLDAP, Active Directory) do.
FROM ubuntu:26.04@sha256:6a06111c3b0a8600feadb270aec771dc239bf407b25625f93f44ab00e11f4d3c
RUN echo "slapd slapd/domain string example.com" | debconf-set-selections \
 && echo "slapd shared/organization string Example" | debconf-set-selections \
 && echo "slapd slapd/password1 password admin-pass-123" | debconf-set-selections \
 && echo "slapd slapd/password2 password admin-pass-123" | debconf-set-selections \
 && apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends slapd ldap-utils \
 && rm -rf /var/lib/apt/lists/*
COPY seed.ldif entrypoint.sh /
RUN chmod 0755 /entrypoint.sh
EXPOSE 389
ENTRYPOINT ["/entrypoint.sh"]
