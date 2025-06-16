# GitHub Issue Response

## ✅ **Great News - This Already Works Perfectly!**

Hi there! Thank you for bringing this up. I'm happy to inform you that **your use case is already fully supported** by the API! The confusion seems to stem from using the generic endpoint when dedicated endpoints exist for your specific needs.

### 🎯 **Solution for Your Domain Blacklist**

Since your example shows domain names (`0123movies.com`, etc.), you should use the **dedicated domain import endpoint**:

```bash
curl -X POST http://localhost:8011/api/domain-blacklist/import \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic $(echo -n admin:admin | base64)" \
  -d '{"url": "https://example.com/blacklist.txt"}'
```

**Your example blacklist.txt file works perfectly as-is:**
```
0123movies.10s.live
0123movies.com
0123movies.is
0123movies.net
0123movies.org
0123movies.st
0123movies4u.com
0123movieshd.com
```

### 🔧 **For IP Blacklists (Answering Your Second Question)**

Yes, there's absolutely an API for importing IP blacklists! Use the dedicated IP import endpoint:

```bash
curl -X POST http://localhost:8011/api/ip-blacklist/import \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic $(echo -n admin:admin | base64)" \
  -d '{"url": "https://example.com/ip-blacklist.txt"}'
```

**Example IP blacklist format:**
```
192.168.1.100
10.0.0.5
172.16.0.1
203.0.113.0/24
# CIDR notation supported
198.51.100.0/24
```

### 🛠️ **How the Smart Parsing Works**

The API automatically handles different formats:

1. **Tries JSON parsing first** (for structured data)
2. **Falls back to plain text** (one entry per line) - **This is what you need!**
3. **Ignores comments** (lines starting with `#`)
4. **Supports wildcards** for domains (`*.example.com`)
5. **Supports CIDR notation** for IPs (`192.168.1.0/24`)

### 📚 **All Available Import Endpoints**

| Endpoint | Purpose | Use Case |
|----------|---------|----------|
| `/api/domain-blacklist/import` | Domain imports | Your example case! |
| `/api/ip-blacklist/import` | IP imports | IP blacklists |
| `/api/blacklists/import` | Generic | Requires `type` parameter |

### 🧪 **Test It Right Now**

You can test this immediately with a simple domain list:

```bash
curl -X POST http://localhost:8011/api/domain-blacklist/import \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic $(echo -n admin:admin | base64)" \
  -d '{
    "content": "test1.com\ntest2.com\n*.malicious.example"
  }'
```

### 📝 **Why This Confusion Happened**

The generic `/api/blacklists/import` endpoint requires a `type` parameter to distinguish between domains and IPs. The dedicated endpoints (`/api/domain-blacklist/import` and `/api/ip-blacklist/import`) are more user-friendly and don't require this parameter.

### 📖 **Updated Documentation**

I've just updated the README with clearer examples and better documentation of these endpoints. You can now find comprehensive examples for both domain and IP imports.

### 🎉 **Bottom Line**

Your plain text file format is **perfectly supported** - you just need to use the correct endpoint:
- **Domains**: `/api/domain-blacklist/import`  
- **IPs**: `/api/ip-blacklist/import`

The system has been working with plain text files since day one. No changes needed to your files or workflow! 🚀

---

Let me know if you need any clarification or run into any issues testing this out!
