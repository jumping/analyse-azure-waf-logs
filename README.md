#Analyse Azure WAF Logs

The script in this repository, aggregates the triggered rules from a directory of Azure WAF logs.
It reports the total count of each triggered rule and the number of rules triggered by each client IP address.

##Usage

```bash
python3 analyse-waf-logs /path/to/waf/logs
```

##Sample Output

The following sample shows the type of output produced by running the script.

```bash
rule id, description, count
920320, Missing User Agent Header, 101
920300, Request Missing an Accept Header, 89

client ip, count
X.X.X.X, 1012
X.X.X.X, 320
```
