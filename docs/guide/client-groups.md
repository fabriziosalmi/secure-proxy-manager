# Client groups

A client group is a set of devices, by address or network, that gets extra
restrictions on top of the policy every client gets. A group only tightens:

- **Lists for the group only.** A source of Blocked domains or Blocked IPs can
  be set to apply only to the groups that use it, for example a list of games
  sites for the children's devices.
- **A time window.** The group may browse only on the days and between the
  times you set, within one day (07:00 to 21:00, not 21:00 to 07:00).
- **Allowlist only.** The group may reach only the destinations on the
  default-deny allowlist (Egress), LAN destinations and IP exceptions, whether
  or not default-deny is on for everyone.

The global lists, the DNS sinkhole and every other rule still apply to a
group's members. A device in two groups gets the restrictions of both.

## Setting one up

1. On **Blacklists**, in **Where the entries came from**, turn on **Groups
   only** for each list that should apply to some devices only (Blocked IPs
   and Blocked domains). Its entries stop applying to every client.
2. On **Clients**, under **Client groups**, choose **New group**: a name, the
   members, the lists for the group only, and if you want set hours or only
   the allowlist.

The [API](/api/blacklists#client-groups) does the same.

## Members

A member is an IP address or a network (`10.1.0.5`, `10.1.0.0/24`, IPv6 too).
The proxy matches the address the request comes from, so a member must be an
address the proxy sees: a device behind another NAT or proxy shows that
device's address instead. A member must also be a client the proxy accepts at
all (private ranges, or `GUI_IP_WHITELIST`).

The proxy login has one shared username, so it cannot tell users apart; members
by user name come with the directory login.

## Lists that apply to groups only

Every source of Blocked domains and Blocked IPs has a scope:

| Scope | Enforced by | Applies to |
|---|---|---|
| `global` (the default) | the DNS sinkhole and the proxy | every client |
| `groups` | the proxy only | the members of the groups that use the source |

A `groups` source is not in the DNS sinkhole, which cannot tell clients apart.
The proxy loads each such source once, however many groups use it. An entry
that a global source also lists stays blocked for everyone. Domain exceptions
take a name off a group's list as they do off the global list.

A source a group uses cannot be set back to `global`: take it off the group
first.

## What happens when something is wrong

- A line of the groups' index the proxy cannot read in full stops the
  regeneration: the running configuration stays, and nothing is applied
  weaker than you set it.
- A list a group uses that has no verified copy in the proxy yet denies the
  group's members everything, with the reason `lists_unverified`, until the
  copy is there. Other clients are not affected.
- A group with no members has no rules.

Blocked requests are logged with the reasons `group_list`, `group_time` and
`group_egress`.

## How it reaches the proxy

The backend writes the groups' files with the lists, under `config/groups/`,
and lists each in the lists manifest with its SHA-256. The proxy's watchdog
copies them verified, as it copies the lists, and regenerates `squid.conf`
when the groups change. A change of members or of a list's entries only takes a
reconfigure.
