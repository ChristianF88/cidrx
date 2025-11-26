# cidrx Configuration Examples

This directory contains example configuration files for the cidrx threat detection system.

## Overview

cidrx uses various filtering mechanisms to identify and block malicious traffic:

1. **IP-based filtering** - Whitelist/blacklist specific IP addresses and CIDR ranges
2. **User-Agent filtering** - Whitelist/blacklist based on User-Agent patterns
3. **Clustering analysis** - Detect threat patterns through IP clustering
4. **Jail system** - Persistent ban management

## File Structure

```
config_examples/
├── README.md           # This file
├── whitelist.txt       # IP addresses/CIDRs to never ban
├── blacklist.txt       # IP addresses/CIDRs to always ban
├── ua_whitelist.txt    # User-Agent patterns that whitelist IPs
└── ua_blacklist.txt    # User-Agent patterns that blacklist IPs
```

## Configuration Files

### whitelist.txt
Contains IP addresses and CIDR ranges that should **never** be banned:
- Internal networks (192.168.0.0/16, 10.0.0.0/8)
- Essential services (DNS servers, CDNs)
- Monitoring and health check services
- Known legitimate sources

### blacklist.txt
Contains IP addresses and CIDR ranges that should **always** be banned:
- Known malicious networks
- Spam and bot networks
- Tor exit nodes (if desired)
- Geolocation-based blocks
- Custom manual blocks

### ua_whitelist.txt
Contains User-Agent substring patterns that **whitelist** the source IP:
- Search engine crawlers (Googlebot, Bingbot)
- SEO and analysis tools (AhrefsBot, SemrushBot)
- Monitoring services (UptimeRobot, Pingdom)
- Internal tools and services
- Legitimate security scanners

### ua_blacklist.txt
Contains User-Agent substring patterns that **blacklist** the source IP:
- Security testing tools (sqlmap, nmap, nikto)
- Web scraping frameworks (scrapy, selenium)
- Command line tools (curl, wget)
- Attack tools and frameworks
- Brute force and dictionary tools

## Usage

### In Configuration File
Reference these files in your `cidrx.toml` configuration:

```toml
[global]
whitelist = "config_examples/whitelist.txt"
blacklist = "config_examples/blacklist.txt"
userAgentWhitelist = "config_examples/ua_whitelist.txt"
userAgentBlacklist = "config_examples/ua_blacklist.txt"
```

### File Format
All files use the same format:
- One entry per line
- Comments start with `#`
- Empty lines are ignored
- Whitespace is trimmed

#### IP Files Format (whitelist.txt, blacklist.txt)
```
# Comment
192.168.1.0/24    # Internal network
10.0.0.1          # Specific IP
```

#### User-Agent Files Format (ua_whitelist.txt, ua_blacklist.txt)
```
# Comment
Googlebot         # Matches any UA containing "Googlebot"
scanner           # Matches any UA containing "scanner"
```

## Processing Order

cidrx processes filtering in this order:

1. **Parse log entries** using configured log format
2. **Apply time and regex filters** from trie configuration
3. **Check User-Agent whitelist** - exclude matching IPs from analysis
4. **Check User-Agent blacklist** - mark matching IPs for immediate banning
5. **Perform clustering analysis** on remaining IPs
6. **Apply IP whitelist** - remove whitelisted IPs from jail candidates
7. **Update jail file** with new detections
8. **Generate ban file** with active bans + IP blacklist

## Customization

### For Your Environment
1. **Review and modify** the example entries
2. **Add your specific networks** to whitelist.txt
3. **Add known threats** to blacklist.txt
4. **Customize User-Agent patterns** for your application
5. **Test thoroughly** before production deployment

### Best Practices
1. **Start conservative** - use restrictive patterns initially
2. **Monitor false positives** - adjust patterns based on results
3. **Regular updates** - keep threat intelligence current
4. **Document changes** - maintain notes about custom entries
5. **Backup configurations** - version control your customizations

## Security Considerations

### Whitelist Security
- Keep whitelist minimal and specific
- Regularly review for outdated entries
- Monitor for abuse of whitelisted ranges
- Use specific CIDRs rather than broad ranges

### Blacklist Security
- Verify entries before adding to blacklist
- Consider impact on legitimate traffic
- Use threat intelligence sources
- Monitor for false positives

### User-Agent Security
- Use specific patterns to avoid false positives
- Some patterns may match legitimate tools
- Consider your application's legitimate traffic
- Balance security with usability

## Troubleshooting

### Common Issues
1. **File not found** - Check file paths and permissions
2. **Invalid CIDR format** - Verify CIDR syntax (e.g., 192.168.1.0/24)
3. **Regex errors** - Test User-Agent patterns with sample data
4. **Performance issues** - Consider file size and pattern complexity

### Debugging Tips
1. **Check log output** for parsing errors
2. **Test with small datasets** first
3. **Use plain text output** for debugging
4. **Validate file formats** manually
5. **Monitor system resources** during operation

## Examples

### Basic Setup
Minimal configuration for testing:
```toml
[global]
whitelist = "config_examples/whitelist.txt"
blacklist = "config_examples/blacklist.txt"
```

### Advanced Setup
Full configuration with User-Agent filtering:
```toml
[global]
whitelist = "config_examples/whitelist.txt"
blacklist = "config_examples/blacklist.txt"
userAgentWhitelist = "config_examples/ua_whitelist.txt"
userAgentBlacklist = "config_examples/ua_blacklist.txt"
```

### Production Deployment
1. Copy example files to your deployment location
2. Customize entries for your environment
3. Test with non-production data
4. Monitor for false positives
5. Deploy gradually with monitoring

## Support

For questions and issues:
1. Check the main cidrx documentation
2. Review log output for error messages
3. Test configurations with sample data
4. Validate file formats and permissions
5. Monitor system resources during operation