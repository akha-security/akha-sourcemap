#!/usr/bin/env python3
"""
akha-sourcemap - JS Source Map Downloader and Information Exposure Scanner
Downloads .js.map files from a single URL or a URL list,
extracts source files, and scans for sensitive data exposure.

Usage:
  python sourcemap_scanner.py -u https://example.com/app.js
  python sourcemap_scanner.py -f urls.txt
  python sourcemap_scanner.py -u https://example.com/app.js -o report.txt
  python sourcemap_scanner.py -u https://example.com/app.js --save-sources

Author: akha-security
"""

import os
import sys
import re
import json
import math
import time
import argparse
import requests
import urllib3
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from collections import defaultdict
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SCAN_PATTERNS = {
    "AWS Access Key ID": r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
    "AWS Secret Access Key": r"(?i)(aws_secret_access_key|aws_secret|AWS_SECRET)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
    "AWS Session Token": r"(?i)(aws_session_token|AWS_SESSION_TOKEN)\s*[=:]\s*['\"]?FQoGZXIvYXdz[A-Za-z0-9/+=]{40,}['\"]?",
    "AWS Account ID": r"(?i)(aws_account_id|AWS_ACCOUNT)\s*[=:]\s*['\"]?\d{12}['\"]?",
    "AWS ARN": r"arn:aws:[a-zA-Z0-9\-]+:[a-z0-9\-]*:\d{12}:[a-zA-Z0-9\-_/:.]+",
    "AWS S3 Bucket URL": r"(?i)(?:https?://)?[a-zA-Z0-9.\-]+\.s3[.\-](?:amazonaws\.com|[a-z\-]+-\d\.amazonaws\.com)[^\s'\"]*",
    "AWS Cognito Pool ID": r"(?i)(us|eu|ap|sa|ca|me|af)\-[a-z]+\-\d:[0-9a-f]{8}\-[0-9a-f]{4}\-[0-9a-f]{4}\-[0-9a-f]{4}\-[0-9a-f]{12}",
    "Google Cloud API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Google OAuth Token": r"ya29\.[0-9A-Za-z\-_]+",
    "Google OAuth Refresh Token": r"1//[0-9A-Za-z\-_]{20,}",
    "Google OAuth Client ID": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
    "Google OAuth Client Secret": r"(?i)(client_secret|google_secret)\s*[=:]\s*['\"]?GOCSPX\-[A-Za-z0-9\-_]{28}['\"]?",
    "Google Firebase URL": r"https://[a-zA-Z0-9\-]+\.firebaseio\.com",
    "Google Firebase Config": r"(?i)(apiKey|authDomain|databaseURL|projectId|storageBucket|messagingSenderId|appId|measurementId)\s*:\s*['\"][^'\"]+['\"]",
    "GCP Service Account": r"[a-zA-Z0-9\-]+@[a-zA-Z0-9\-]+\.iam\.gserviceaccount\.com",
    "Azure Storage Key": r"(?i)(AccountKey|azure_storage_key|AZURE_KEY)\s*[=:]\s*['\"]?[A-Za-z0-9+/=]{44,}['\"]?",
    "Azure Client Secret": r"(?i)(azure_client_secret|AZURE_CLIENT_SECRET)\s*[=:]\s*['\"][A-Za-z0-9\-._~]{24,}['\"]",
    "Azure Connection String": r"(?i)DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]+;?",
    "Azure SAS Token": r"(?i)[?&](?:sv|sig|se|sp|spr|st)=[^&\s'\"]+(?:&(?:sv|sig|se|sp|spr|st)=[^&\s'\"]+)+",
    "Azure Subscription ID": r"(?i)(subscription_id|AZURE_SUBSCRIPTION)\s*[=:]\s*['\"]?[0-9a-f]{8}\-[0-9a-f]{4}\-[0-9a-f]{4}\-[0-9a-f]{4}\-[0-9a-f]{12}['\"]?",
    "Azure AD Tenant": r"(?i)https://login\.microsoftonline\.com/[0-9a-f]{8}\-[0-9a-f]{4}\-[0-9a-f]{4}\-[0-9a-f]{4}\-[0-9a-f]{12}",
    "DigitalOcean Token": r"(?i)(do_token|digitalocean|DIGITALOCEAN_ACCESS_TOKEN)\s*[=:]\s*['\"]?[a-f0-9]{64}['\"]?",
    "Cloudflare API Key": r"(?i)(cloudflare|CF_API_KEY|CF_API_TOKEN)\s*[=:]\s*['\"]?[A-Za-z0-9\-_]{37,}['\"]?",
    "Alibaba Cloud AccessKey": r"(?i)LTAI[A-Za-z0-9]{12,20}",
    "IBM Cloud API Key": r"(?i)(ibm_cloud_api_key|IBMCLOUD_API_KEY)\s*[=:]\s*['\"]?[A-Za-z0-9\-_]{20,60}['\"]?",
    "Oracle Cloud OCID": r"ocid1\.[a-z0-9.\-_]+",
    "GitHub Token (Classic)": r"ghp_[A-Za-z0-9_]{36,}",
    "GitHub Token (Fine-grained)": r"github_pat_[A-Za-z0-9_]{22,}",
    "GitHub OAuth": r"gho_[A-Za-z0-9_]{36,}",
    "GitHub App Token": r"(?:ghu|ghs|ghr)_[A-Za-z0-9_]{36,}",
    "GitLab Token": r"glpat\-[A-Za-z0-9\-_]{20,}",
    "GitLab Runner Token": r"GR1348941[A-Za-z0-9\-_]{20,}",
    "Bitbucket App Password": r"(?i)bitbucket.*['\"][A-Za-z0-9]{20,}['\"]",
    "Slack Bot Token": r"xoxb\-[0-9]{10,}\-[0-9]{10,}\-[A-Za-z0-9]{24,}",
    "Slack User Token": r"xoxp\-[0-9]{10,}\-[0-9]{10,}\-[0-9]{10,}\-[a-f0-9]{32}",
    "Slack Webhook": r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24}",
    "Slack App Token": r"xapp\-[0-9]\-[A-Z0-9]{11}\-[0-9]{13}\-[a-f0-9]{64}",
    "Stripe Secret Key": r"sk_(test|live)_[0-9a-zA-Z]{24,}",
    "Stripe Publishable Key": r"pk_(test|live)_[0-9a-zA-Z]{24,}",
    "Stripe Webhook Secret": r"whsec_[A-Za-z0-9]{32,}",
    "PayPal Client ID": r"(?i)(paypal_client_id|PAYPAL_CLIENT)\s*[=:]\s*['\"]?A[A-Za-z0-9\-_]{30,}['\"]?",
    "Square Access Token": r"sq0atp\-[A-Za-z0-9\-_]{22}",
    "Square OAuth Secret": r"sq0csp\-[A-Za-z0-9\-_]{43}",
    "Twilio Account SID": r"AC[0-9a-fA-F]{32}",
    "Twilio Auth Token": r"(?i)(twilio_auth_token|TWILIO_TOKEN)\s*[=:]\s*['\"]?[0-9a-f]{32}['\"]?",
    "SendGrid API Key": r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}",
    "Mailgun API Key": r"key\-[0-9a-zA-Z]{32}",
    "Mailchimp API Key": r"[0-9a-f]{32}\-us\d{1,2}",
    "Telegram Bot Token": r"\b\d{8,10}:[A-Za-z0-9_\-]{35}\b",
    "Discord Bot Token": r"(?i)(discord_token|DISCORD_BOT)\s*[=:]\s*['\"]?[A-Za-z0-9.\-_]{50,}['\"]?",
    "Discord Webhook": r"https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+",
    "Shopify Token": r"shpat_[a-fA-F0-9]{32}",
    "Shopify Shared Secret": r"shpss_[a-fA-F0-9]{32}",
    "NPM Access Token": r"npm_[A-Za-z0-9]{36}",
    "PyPI API Token": r"pypi\-[A-Za-z0-9]{150,}",
    "Sentry DSN": r"https://[a-f0-9]{32}@(?:o\d+\.)?(?:sentry\.io|[a-zA-Z0-9.\-]+)/\d+",
    "Datadog API Key": r"(?i)(datadog|DD_API_KEY)\s*[=:]\s*['\"]?[a-f0-9]{32}['\"]?",
    "Algolia API Key": r"(?i)(algolia|ALGOLIA_API_KEY)\s*[=:]\s*['\"]?[a-f0-9]{32}['\"]?",
    "New Relic Key": r"NRAK\-[A-Z0-9]{27}",
    "Mapbox Token": r"(?:pk|sk)\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]{20,}",
    "OpenAI API Key": r"sk\-proj\-[A-Za-z0-9_\-]{20,}",
    "OpenAI Legacy Key": r"\bsk-[A-Za-z0-9]{48}\b",
    "Anthropic API Key": r"sk\-ant\-[A-Za-z0-9\-_]{20,}",
    "Notion Integration Secret": r"secret_[A-Za-z0-9]{40,}",
    "Linear API Key": r"lin_api_[A-Za-z0-9]{30,}",
    "Airtable API Key": r"\bkey[A-Za-z0-9]{14}\b",
    "Postman API Key": r"PMAK-[0-9a-f]{24}-[0-9a-f]{34}",
    "Contentful CMA Token": r"CFPAT-[A-Za-z0-9]{30,}",
    "Sendinblue API Key": r"xkeysib-[A-Za-z0-9\-]{40,}",

    "JSON Web Token (JWT)": r"eyJ[A-Za-z0-9\-_=]+\.eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_.+/=]*",
    "Bearer Token": r"(?i)bearer\s+[a-zA-Z0-9\-_.~+/]{10,}=*",
    "Refresh Token Assignment": r"(?i)(refresh_token|REFRESH_TOKEN)\s*[=:]\s*['\"][A-Za-z0-9\-_.]{16,}['\"]",
    "JWT Secret Assignment": r"(?i)(jwt_secret|JWT_SECRET|jwt_signing_key|JWT_SIGNING_KEY|signing_secret)\s*[=:]\s*['\"][^'\"]{12,}['\"]",
    "CSRF Token Assignment": r"(?i)(csrf_token|xsrf_token|XSRF_TOKEN)\s*[=:]\s*['\"][A-Za-z0-9\-_]{10,}['\"]",
    "Okta API Token": r"\b00[a-zA-Z0-9]{18,}\b",
    "Auth0 Client Secret": r"(?i)(auth0_client_secret|AUTH0_CLIENT_SECRET)\s*[=:]\s*['\"][A-Za-z0-9\-_]{16,}['\"]",
    "Basic Auth Header": r"(?i)basic\s+[A-Za-z0-9+/]{20,}={0,2}",
    "OAuth Client Credentials": r"(?i)(client_id|client_secret|oauth_token|oauth_secret)\s*[=:]\s*['\"][^'\"]{8,}['\"]",
    "Session Cookie": r"(?i)(session_id|sessionid|PHPSESSID|JSESSIONID|connect\.sid|_session)\s*[=:]\s*['\"][^'\"]{8,}['\"]",
    "Private Key Block": r"-{5}BEGIN\s+(?:RSA |EC |PGP |DSA |OPENSSH |ENCRYPTED )?PRIVATE\s+KEY-{5}[\s\S]{32,}?-{5}END\s+(?:RSA |EC |PGP |DSA |OPENSSH |ENCRYPTED )?PRIVATE\s+KEY-{5}",
    "Certificate Block": r"-{5}BEGIN\s+CERTIFICATE-{5}[\s\S]{32,}?-{5}END\s+CERTIFICATE-{5}",
    "SSH Key Fingerprint": r"SHA256:[A-Za-z0-9+/=]{43}",

    "Password Assignment": r"(?i)(?<![a-z_])(password|passwd|pwd|user_pass|admin_pass|db_pass|root_pass|mysql_pass)\s*[=:]\s*['\"](?!password['\"]|\s*['\"])[^'\"]{4,}['\"]",
    "Secret/Token Assignment": r"(?i)(secret|token|api_?key|auth_?token|access_?key|client_?secret|app_?secret|private_?key|encryption_?key|signing_?key)\s*[=:]\s*['\"][^'\"]{8,}['\"]",
    "Authorization Header Hardcoded": r"(?i)(authorization|x-api-key|x-auth-token|x-access-token|x-csrf-token)\s*[=:]\s*['\"][^'\"]+['\"]",
    "API Key in Query Parameter": r"(?i)[?&](?:api[_-]?key|access[_-]?token|auth[_-]?token)=[A-Za-z0-9\-_]{10,}",
    "Hardcoded Salt": r"(?i)(salt|pepper)\s*[=:]\s*['\"][A-Za-z0-9\-_=+/]{8,}['\"]",
    "Credential JSON Blob": r"(?i)\{\s*['\"](?:username|user|email)['\"]\s*:\s*['\"][^'\"]+['\"]\s*,\s*['\"](?:password|pass|secret|token)['\"]\s*:\s*['\"][^'\"]{4,}['\"]\s*\}",
    "Generic High Entropy String": r"(?i)(SECRET|PRIVATE|CREDENTIAL|ACCESS_KEY|MASTER_KEY|ENCRYPTION)\s*[=:]\s*['\"][A-Za-z0-9+/=\-_]{20,}['\"]",
    "Env Variable Leak": r"(?i)process\.env\.(SECRET|TOKEN|API_?KEY|PASSWORD|CREDENTIAL|AUTH_TOKEN|PRIVATE_KEY|MASTER_KEY|ENCRYPTION_KEY)[A-Z_]*",
    "Config Credential Leak": r"(?i)(config|settings|conf|cfg)\.(secret|password|token|key|credential|auth)\s*[=:]\s*['\"][^'\"]+['\"]",
    "Hardcoded Credentials in URL": r"(?i)https?://[a-zA-Z0-9_%]+:[a-zA-Z0-9_%!@#$^&*]+@[a-zA-Z0-9.\-]+(?::\d+)?(?:/|$)",

    "Database Connection String": r"(?i)(mongodb(?:\+srv)?|postgres(?:ql)?|mysql|mariadb|redis|mssql|sqlite|cockroachdb|couchdb|cassandra|neo4j|dynamodb):\/\/[^\s'\"]+",
    "DB Credentials": r"(?i)(DB_PASS|DB_PASSWORD|DATABASE_URL|DB_URL|DB_CONNECTION|REDIS_URL|MONGO_URI)\s*[=:]\s*['\"]?[^\s'\"]+['\"]?",
    "JDBC Connection": r"jdbc:[a-z]+://[^\s'\"]+",
    "LDAP Connection": r"ldaps?://[^\s'\"]+",
    "AMQP/RabbitMQ URL": r"amqps?://[^\s'\"]+",
    "Elasticsearch URL": r"(?i)https?://[^/]*(?:elastic(?:search)?|kibana)[^/]*(?::\d+)(?:/[^\s'\"]*)?",
    "Redis Password Assignment": r"(?i)(redis_password|REDIS_PASSWORD|requirepass)\s*[=:]\s*['\"][^'\"]{6,}['\"]",
    "Elasticsearch API Key Header": r"(?i)ApiKey\s+[A-Za-z0-9+/=]{20,}",
    "Kafka SASL JAAS Config": r"(?i)sasl\.jaas\.config\s*[=:]\s*['\"][^'\"]{20,}['\"]",
    "Supabase URL": r"https://[a-z0-9\-]+\.supabase\.co",
    "Supabase Service Role Key": r"(?i)(supabase_service_role|SUPABASE_SERVICE_ROLE)\s*[=:]\s*['\"][A-Za-z0-9\-_.=]{30,}['\"]",

    "Internal IP Address": r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
    "IPv6 Address": r"(?i)\b(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}\b",
    "Internal/Staging/Dev URL": r"(?i)https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|staging|stage|dev|test|uat|internal|admin|debug|qa|preprod|sandbox)[.\-:][^\s'\"]*",
    "Admin/Dashboard Panel URL": r"(?i)https?://[^\s'\"]*(?:/admin|/dashboard|/panel|/manage|/backoffice|/cms|/control|/internal)[^\s'\"]*",
    "Kubernetes Service DNS": r"\b[a-z0-9\-]+\.svc(?:\.cluster\.local)?\b",
    "Internal Hostname": r"(?i)\b(?:ip-|srv-|db-|redis-|kafka-|internal|intranet)[a-z0-9\-]*\.(?:local|lan|internal|corp)\b",
    "RFC1918 URL": r"(?i)https?://(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)\d{1,3}\.\d{1,3}(?::\d+)?(?:/[^\s'\"]*)?",
    "Common Service Port": r"(?i)(?:port|PORT)\s*[=:]\s*['\"]?\b(3306|5432|1433|27017|6379|9200|11211|8080|8443|9090|5672|15672|2181|9092|4369)\b",
    "FTP/WebSocket/SFTP URL": r"(?:ftp|wss?|sftp|ssh)://[^\s'\"]+",

    "REST API Path Pattern": r"""(?i)['\"]\/(?:api|v[0-9]+|rest|graphql|gql|internal|private|admin|auth|oauth|user|account|payment|order|webhook|callback|ws|socket)\/[a-zA-Z0-9/_\-{}:]+['\"]""",
    "GraphQL Endpoint": r"(?i)['\"](?:https?://[^\s'\"]+)?/graphql['\"]",
    "GraphQL Introspection Query": r"(?i)__schema|__type\s*\(",
    "GraphQL Query/Mutation": r"(?i)(?:query|mutation|subscription)\s+\w+\s*(?:\([^)]*\))?\s*\{",
    "Swagger/OpenAPI URL": r"(?i)['\"](?:https?://[^\s'\"]*)?/(?:swagger|openapi|api-docs|api/docs|redoc)[^\s'\"]*['\"]",
    "Admin/Auth Endpoint Path": r"""(?i)['\"]/(?:admin|auth|oauth|login|token|session|internal|private)[a-zA-Z0-9/_\-{}:]*['\"]""",
    "Potential IDOR Endpoint": r"""(?i)['\"]/(?:api|v\d+)/[a-zA-Z0-9/_\-]*(?:user|users|account|order|invoice|profile)/(?:\{)?(?:id|userId|accountId|orderId)(?:\})?['\"]""",
    "CORS Allow Origin Wildcard": r"""(?i)(?:Access-Control-Allow-Origin|allowedOrigins?|cors_origin)\s*[=:]\s*['\"]?\*['\"]?""",
    "Server-Side Request (SSRF Risk)": r"(?i)(?:fetch|axios|http\.get|request|urllib|curl|wget)\s*\(\s*['\"]?(?:https?://|//)",
    "File Path Disclosure": r"(?i)['\"](?:\/etc\/|\/var\/|\/usr\/|\/home\/|\/root\/|C:\\\\|\/tmp\/|\/opt\/|\/proc\/)[^\s'\"]+['\"]",
    "Upload/File Endpoint": r"(?i)['\"](?:https?://[^\s'\"]*)?/(?:upload|file|media|attachment|document|image|asset|static|resource)s?/[^\s'\"]*['\"]",

    "Email Address": r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
    "Phone Number (International)": r"(?i)(?:phone|tel|mobile|fax|gsm|telefon|cep)\s*[=:,]\s*['\"]?\+?\d{1,4}[\s\-]?\(?\d{1,4}\)?[\s\-]?\d{3,4}[\s\-]?\d{4}['\"]?",
    "Credit Card Number (Visa/MC)": r"(?i)(?:card|kredi|credit|cc|pan)[_\s=:]*['\"]?\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b",
    "CVV/CVC Code": r"(?i)(?:cvv|cvc|security_code)\s*[=:,]\s*['\"]?\d{3,4}['\"]?",
    "Date of Birth": r"(?i)(?:date_of_birth|dob|birthdate|dogum_tarihi)\s*[=:,]\s*['\"]?(?:\d{4}-\d{2}-\d{2}|\d{2}[./-]\d{2}[./-]\d{4})['\"]?",
    "Passport Number": r"(?i)(?:passport|pasaport)\s*[=:,]\s*['\"]?[A-Z0-9]{6,9}['\"]?",
    "Address Field Leak": r"(?i)(?:address|adres|street|city|postal_code|zip_code)\s*[=:]\s*['\"][^'\"]{6,}['\"]",
    "SSN (Social Security)": r"(?i)(?:ssn|social.?security|soc.?sec)\s*[=:,]\s*['\"]?\d{3}\-\d{2}\-\d{4}['\"]?",
    "IBAN Number": r"\b(?:TR|DE|GB|FR|IT|ES|NL|BE|AT|CH|SE|NO|DK|FI|PT|IE|PL|CZ|HU|RO|BG|HR|SK|SI|LT|LV|EE|LU|MT|CY|GR)\d{2}\s?(?:[A-Z0-9]{4}\s?){3,8}[A-Z0-9]{0,4}\b",
    "Turkish ID Number (National ID)": r"(?i)(?:tc|kimlik|identity|tckn|tckimlik)\s*[=:,]\s*['\"]?[1-9]\d{10}['\"]?",
    "Hardcoded User/Admin Name": r"(?i)(admin_user|admin_name|root_user|superuser|master_user)\s*[=:]\s*['\"][^'\"]+['\"]",
    "eval() Usage": r"\beval\s*\(",
    "Function Constructor": r"\bnew\s+Function\s*\(",
    "setTimeout/setInterval with String": r"(?i)(setTimeout|setInterval)\s*\(\s*['\"]",
    "innerHTML Assignment": r"\.innerHTML\s*=",
    "outerHTML Assignment": r"\.outerHTML\s*=",
    "insertAdjacentHTML": r"\.insertAdjacentHTML\s*\(",
    "document.write Usage": r"\bdocument\.write(?:ln)?\s*\(",
    "DOM XSS Sink (jQuery)": r"(?i)\$\(['\"].*['\"].*\)\.(html|append|prepend|after|before|replaceWith)\s*\(",
    "Unsafe postMessage": r"\.postMessage\s*\([^)]*\*",
    "URL Redirect (Open Redirect)": r"(?i)(?:window\.location|location\.href|location\.assign|location\.replace)\s*=\s*[^'\";\n]*(?:url|redirect|return_to|next|callback|goto|dest|target|redir|return|forward)",
    "child_process Exec Usage": r"(?i)child_process\.(?:exec|execSync|spawn|spawnSync)\s*\(",
    "Command Injection Concatenation": r"(?i)(?:exec|execSync|spawn|spawnSync)\s*\([^)]*(?:\+|template|string).*?(?:req\.|params\.|query\.|body\.|input|user)",
    "Prototype Pollution Sink": r"(?i)(?:Object\.assign|lodash\.merge|merge|extend|set)\s*\([^)]*(?:req\.|params\.|query\.|body\.)",
    "Insecure CORS Credentials": r"(?i)(?:Access-Control-Allow-Credentials|allowCredentials|credentials)\s*[=:]\s*['\"]?(?:true|1)['\"]?",
    "Unsafe YAML Load": r"(?i)(?:yaml\.load|jsyaml\.load)\s*\(",
    "Hardcoded SQL Query": r"(?i)(SELECT\s+.{1,80}\s+FROM|INSERT\s+INTO|UPDATE\s+.{1,60}\s+SET|DELETE\s+FROM|DROP\s+TABLE|ALTER\s+TABLE|CREATE\s+TABLE|UNION\s+SELECT)\s+\w+",
    "SQL String Concatenation": r"(?i)(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\s+.*?\+\s*(?:req\.|params\.|query\.|body\.|input|user)",
    "NoSQL Injection Pattern": r"(?i)\{\s*['\"]?\$(?:gt|gte|lt|lte|ne|in|nin|regex|where|exists|elemMatch)['\"]?\s*:",
    "Template Literal in Query": r"(?i)(?:SELECT|INSERT|UPDATE|DELETE)\s+(?:FROM|INTO|SET|\*).*`\$\{",
    "Dynamic File Include": r"(?i)(?:require|import|include|readFile|readFileSync|createReadStream)\s*\(\s*(?:req\.|params\.|query\.|body\.|input|user|variable)",
    "Arbitrary File Read": r"(?i)(?:fs\.readFile(?:Sync)?|fs\.createReadStream)\s*\([^)]*(?:\+|concat|template)",
    "Path Traversal Input": r"(?i)(?:path\.join|path\.resolve)\s*\([^)]*(?:req\.|params\.|query\.|body\.|input|user)",
    "Weak Hash Algorithm (MD5/SHA1)": r"(?i)(?:createHash|hashlib|MessageDigest|digest)\s*\(\s*['\"](?:md5|sha1|sha-1|md4|md2)['\"]",
    "Hardcoded IV/Nonce": r"(?i)(?:iv|nonce|initialization_vector)\s*[=:]\s*['\"][A-Fa-f0-9]{16,}['\"]",
    "Hardcoded Encryption Key": r"(?i)(?:encrypt(?:ion)?_key|cipher_key|aes_key|des_key|crypto_key)\s*[=:]\s*['\"][^'\"]{8,}['\"]",
    "Insecure Random": r"(?i)Math\.random\s*\(\s*\).*(?:token|secret|password|key|salt|nonce|iv|hash|session|csrf|otp|code|pin)",
    "Disabled SSL Verification": r"(?i)(?:rejectUnauthorized|verify_ssl|VERIFY_SSL|SSL_VERIFY|NODE_TLS_REJECT_UNAUTHORIZED)\s*[=:]\s*(?:false|0|['\"]0['\"])",
    "Debugger Statement": r"(?<!\.)\bdebugger\b(?!\s*[=:])",
    "Console Credentials Leak": r"(?i)console\.(log|debug|info|warn|error)\s*\([^)]*?(password|secret|token|credential|apiKey|api_key)[^)]*?\)",
    "Commented-Out Code Block": r"(?i)//\s*(password|secret|token|api_key|private_key|access_key)\s*[=:]",
    "TODO/FIXME/HACK Comment": r"(?i)(?://|/\*|#)\s*\b(TODO|FIXME|XXX|HACK|BUG|SECURITY|VULNERABILITY|UNSAFE|INSECURE)\b:?\s*.{0,100}",
    "Debug Mode Enabled": r"(?i)(debug|DEBUG|Debug)\s*[=:]\s*(?:true|1|['\"]true['\"]|['\"]1['\"]|['\"]yes['\"])",
    "Verbose Error Disclosure": r"(?i)(stack_trace|stackTrace|full_error|error_detail|detailed_error|show_errors|display_errors)\s*[=:]\s*(?:true|1)",
    "Test/Mock Credentials": r"(?i)(test_password|test_token|test_key|mock_secret|fake_api_key|dummy_pass|sample_token)\s*[=:]\s*['\"][^'\"]+['\"]",

    "Docker Registry URL": r"(?i)(?:docker\.io|gcr\.io|ecr\.[a-z\-]+\.amazonaws\.com|azurecr\.io|registry\.[a-z]+)/[a-zA-Z0-9.\-_/]+",
    "Kubernetes Config": r"(?i)(KUBECONFIG|KUBE_TOKEN|KUBE_CA|K8S_AUTH|KUBERNETES_SERVICE)\s*[=:]\s*['\"]?[^\s'\"]+['\"]?",
    "Terraform State": r"(?i)terraform\.(tfstate|tfvars|backend)",
    "Vault Token/Addr": r"(?i)(VAULT_TOKEN|VAULT_ADDR|VAULT_SECRET)\s*[=:]\s*['\"]?[^\s'\"]+['\"]?",
    "AWS Metadata Endpoint": r"http://169\.254\.169\.254/latest/meta-data/[^\s'\"]*",
    "GCP Metadata Endpoint": r"http://metadata\.google\.internal/[^\s'\"]*",
    "Azure Metadata Endpoint": r"http://169\.254\.169\.254/metadata/[^\s'\"]*",
    "Docker Socket Reference": r"/var/run/docker\.sock",
    "Kubeconfig File Path": r"(?i)(?:/home/[^\s'\"]+/.kube/config|C:\\\\Users\\\\[^\\\\]+\\\\\.kube\\\\config)",
    "CI/CD Token": r"(?i)(CIRCLE_TOKEN|TRAVIS_TOKEN|JENKINS_TOKEN|GITLAB_CI_TOKEN|GITHUB_TOKEN|CI_JOB_TOKEN|BITBUCKET_TOKEN|CODEBUILD_TOKEN)\s*[=:]\s*['\"]?[^\s'\"]+['\"]?",
    "Environment File Reference": r"(?i)(?:require|readFile|load|parse|dotenv|config)\s*\(?\s*['\"](?:\.env|\.env\.local|\.env\.production|\.env\.staging|\.env\.development)['\"]\)?",
    "Hostname/Server Name Leak": r"(?i)(hostname|server_name|SERVER_NAME|HOST_NAME)\s*[=:]\s*['\"][a-zA-Z0-9.\-]+['\"]",
    "Webhook URL (Generic)": r"(?i)https?://[^\s'\"]*(?:webhook|hook|notify|callback|ping|trigger)[^\s'\"]*",
}
SKIP_IN_NODE_MODULES = {
    "TODO/FIXME/HACK Comment",
    "Debugger Statement",
    "innerHTML Assignment",
    "outerHTML Assignment",
    "insertAdjacentHTML",
    "document.write Usage",
    "eval() Usage",
    "Function Constructor",
    "setTimeout/setInterval with String",
    "Commented-Out Code Block",
    "Debug Mode Enabled",
    "Verbose Error Disclosure",
    "DOM XSS Sink (jQuery)",
    "Unsafe postMessage",
    "GraphQL Query/Mutation",
    "Insecure Random",
    "Weak Hash Algorithm (MD5/SHA1)",
    "Console Credentials Leak",
    "Template Literal in Query",
}
FALSE_POSITIVE_FILTERS = {
    "Email Address": [
        r"@babel",
        r"@types",
        r"@angular",
        r"@vue",
        r"@react",
        r"@next",
        r"@emotion",
        r"@mui",
        r"@reduxjs",
        r"@testing-library",
        r"@charset",
        r"@keyframes",
        r"@media",
        r"@import",
        r"@font-face",
        r"@supports",
        r"@namespace",
        r"@rollup",
        r"@eslint",
        r"@prettier",
        r"@webpack",
        r"@sentry",
        r"@firebase",
        r"@microsoft",
        r"@google",
        r"@aws",
        r"@azure",
        r"@customer-service",
        r"@discovery",
        r"\.png$",
        r"\.jpg$",
        r"\.svg$",
        r"\.gif$",
        r"\.woff",
        r"\.css$",
        r"example\.com",
        r"test\.com",
        r"sample\.com",
        r"localhost",
        r"placeholder",
        r"your-email",
        r"email@domain",
        r"noreply",
        r"no-reply",
        r"user@",
        r"name@",
        r"@example",
        r"spdx\.org",
        r"github\.com",
        r"npmjs\.(org|com)",
    ],
    "Internal IP Address": [
        r"\b0\.0\.0\.0\b",
        r"\b127\.0\.0\.1\b",
        r"sourceMappingURL",
        r"rgba?\(",
        r"hsla?\(",
    ],
    "Internal/Staging/Dev URL": [
        r"developer\.mozilla",
        r"developer\.android",
        r"developers\.google",
        r"developer\.apple",
        r"devtools",
        r"devextreme",
        r"test-utils",
        r"testing-library",
        r"testcafe",
    ],
    "Phone Number (International)": [
        r"['\"]?\d{13,}['\"]?",
        r"Date\(",
        r"timestamp",
        r"\.getTime",
        r"parseInt",
        r"parseFloat",
        r"\b(width|height|size|length|count|index|offset|margin|padding|border|radius|opacity|duration|delay|timeout|interval|position|zIndex|z-index)\b",
    ],
    "TODO/FIXME/HACK Comment": [],
    "innerHTML Assignment": [],
    "Debugger Statement": [
        r"(?i)debugger.*(?:false|disable|off|no)",
    ],
    "REST API Path Pattern": [
        r"/api/v\d+/docs",
        r"swagger",
    ],
    "Debug Mode Enabled": [
        r"(?i)//\s*debug",
        r"isDebug.*false",
    ],
    "Bearer Token": [
        r"Bearer\s+['\"]?$",
        r"Bearer\s+\$\{",
        r"Bearer\s*['\"]\s*['\"]\s*$",
        r"Bearer\s*['\"]\s*$",
        r"['\"]Bearer ['\"]\s*\+",
        r"['\"]Bearer ['\"]\s*$",
    ],
    "Authorization Header Hardcoded": [
        r"Authorization\s*=\s*['\"]Authorization['\"]\s*$",
        r"['\"]Bearer\s*['\"]\s*$",
        r"['\"]Bearer\s+['\"]\s*$",
        r"concat\(",
        r"\$\{",
        r"\+\s*(?:token|access|auth)",
    ],
    "Elasticsearch URL": [
        r"elastic.*\.js",
        r"elastic.*\.ts",
        r"docs\.elastic",
    ],
    "Secret/Token Assignment": [
        r"\btype\s*[=:]\s*['\"](?:password|token|secret)['\"]\b",
        r"input.*type.*token",
        r"TOKEN_TYPE",
        r"token_type",
        r"access_token.*response",
        r"localStorage.*token",
        r"getItem.*token",
        r"setItem.*token",
        r"removeItem.*token",
        r"\bplaceholder\b",
        r"\blabel\b",
        r"\bname\s*=\s*['\"](?:token|secret|key)['\"]\b",
        r"SECRET_DO_NOT_PASS",
        r"REACT_PROP_TYPES",
        r"DO_NOT_USE",
        r"WILL_BE_FIRED",
        r"token\s*=\s*['\"]%",
        r"no-api-key",
        r"your.?api.?key",
        r"api[_-]?key\s*[=:]\s*['\"]\s*['\"]\s*$",
    ],
    "OAuth Client Credentials": [
        r"\bclient_id\s*[=:]\s*['\"]client_id['\"]\b",
        r"\bclient_secret\s*[=:]\s*['\"]client_secret['\"]\b",
        r"\boauth_token\s*[=:]\s*['\"]oauth_token['\"]\b",
        r"response\.client_id",
        r"params\.client_id",
        r"query\.client_id",
    ],
    "Google Firebase Config": [
        r"\bprojectId\s*:\s*['\"]projectId['\"]\b",
        r"\bauthDomain\s*:\s*['\"]authDomain['\"]\b",
        r"\b(?:get|set|has|check).*(?:apiKey|projectId|authDomain)\b",
        r"(?:required|missing|invalid).*(?:apiKey|projectId)\b",
        r"options\.apiKey",
        r"config\.apiKey",
        r"\bvalidat",
    ],
    "Hardcoded Credentials in URL": [
        r"\$\{",
        r"\{\{",
        r"\+\s*(?:user|pass|host|port)",
        r"<[^>]*>",
        r"@\$\{",
    ],
    "Server-Side Request (SSRF Risk)": [
        r"fetch\s*\(\s*['\"]https?://(?:cdn|fonts|apis?|www)\.(?:google|googleapis|microsoft|cloudflare|jsdelivr|unpkg)",
        r"fetch\s*\(\s*['\"]https?://[a-z]+\.gstatic\.com",
    ],
    "Webhook URL (Generic)": [
        r"react-?hook",
        r"use[A-Z].*hook",
        r"webhook.*doc",
        r"docs.*webhook",
    ],
}

class Colors:
    """Terminal colors (ANSI)"""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
SEVERITY = {
    "CRITICAL": (Colors.BG_RED + Colors.WHITE, "[CRIT]"),
    "HIGH":     (Colors.RED,                    "[HIGH]"),
    "MEDIUM":   (Colors.YELLOW,                 "[MED]"),
    "LOW":      (Colors.BLUE,                   "[LOW]"),
    "INFO":     (Colors.DIM,                    "[INFO]"),
}

PATTERN_SEVERITY = {
    "AWS Access Key ID": "CRITICAL",
    "AWS Secret Access Key": "CRITICAL",
    "Private Key Block": "CRITICAL",
    "Certificate Block": "CRITICAL",
    "Database Connection String": "CRITICAL",
    "JDBC Connection": "CRITICAL",
    "LDAP Connection": "CRITICAL",
    "AMQP/RabbitMQ URL": "CRITICAL",
    "Password Assignment": "CRITICAL",
    "DB Credentials": "CRITICAL",
    "Hardcoded Credentials in URL": "CRITICAL",
    "Azure Connection String": "CRITICAL",
    "Vault Token/Addr": "CRITICAL",
    "Hardcoded Encryption Key": "CRITICAL",
    "Generic High Entropy String": "CRITICAL",
    "Test/Mock Credentials": "CRITICAL",
    "AWS Account ID": "HIGH",
    "AWS ARN": "HIGH",
    "AWS S3 Bucket URL": "HIGH",
    "AWS Cognito Pool ID": "HIGH",
    "Google Cloud API Key": "HIGH",
    "Google OAuth Token": "HIGH",
    "Google OAuth Refresh Token": "HIGH",
    "Google OAuth Client ID": "HIGH",
    "Google OAuth Client Secret": "HIGH",
    "Google Firebase URL": "HIGH",
    "Google Firebase Config": "HIGH",
    "GCP Service Account": "HIGH",
    "Azure Storage Key": "HIGH",
    "Azure Client Secret": "HIGH",
    "Azure SAS Token": "HIGH",
    "Azure Subscription ID": "HIGH",
    "Azure AD Tenant": "HIGH",
    "DigitalOcean Token": "HIGH",
    "Cloudflare API Key": "HIGH",
    "Alibaba Cloud AccessKey": "HIGH",
    "IBM Cloud API Key": "HIGH",
    "Oracle Cloud OCID": "MEDIUM",
    "GitHub Token (Classic)": "HIGH",
    "GitHub Token (Fine-grained)": "HIGH",
    "GitHub OAuth": "HIGH",
    "GitHub App Token": "HIGH",
    "GitLab Token": "HIGH",
    "GitLab Runner Token": "HIGH",
    "Bitbucket App Password": "HIGH",
    "Slack Bot Token": "HIGH",
    "Slack User Token": "HIGH",
    "Slack Webhook": "HIGH",
    "Slack App Token": "HIGH",
    "Stripe Secret Key": "HIGH",
    "Stripe Publishable Key": "HIGH",
    "Stripe Webhook Secret": "HIGH",
    "PayPal Client ID": "HIGH",
    "Square Access Token": "HIGH",
    "Square OAuth Secret": "HIGH",
    "Twilio Account SID": "HIGH",
    "Twilio Auth Token": "HIGH",
    "SendGrid API Key": "HIGH",
    "Mailgun API Key": "HIGH",
    "Mailchimp API Key": "HIGH",
    "Telegram Bot Token": "HIGH",
    "Discord Bot Token": "HIGH",
    "Discord Webhook": "HIGH",
    "Shopify Token": "HIGH",
    "Shopify Shared Secret": "HIGH",
    "NPM Access Token": "HIGH",
    "PyPI API Token": "HIGH",
    "Sentry DSN": "HIGH",
    "Datadog API Key": "HIGH",
    "Algolia API Key": "HIGH",
    "New Relic Key": "HIGH",
    "Mapbox Token": "HIGH",
    "OpenAI API Key": "HIGH",
    "OpenAI Legacy Key": "HIGH",
    "Anthropic API Key": "HIGH",
    "Notion Integration Secret": "HIGH",
    "Linear API Key": "HIGH",
    "Airtable API Key": "HIGH",
    "Postman API Key": "HIGH",
    "Contentful CMA Token": "HIGH",
    "Sendinblue API Key": "HIGH",
    "JSON Web Token (JWT)": "HIGH",
    "Bearer Token": "HIGH",
    "Refresh Token Assignment": "HIGH",
    "JWT Secret Assignment": "HIGH",
    "CSRF Token Assignment": "MEDIUM",
    "Okta API Token": "HIGH",
    "Auth0 Client Secret": "HIGH",
    "Basic Auth Header": "HIGH",
    "OAuth Client Credentials": "HIGH",
    "Session Cookie": "HIGH",
    "SSH Key Fingerprint": "HIGH",
    "Redis Password Assignment": "HIGH",
    "Elasticsearch API Key Header": "HIGH",
    "Kafka SASL JAAS Config": "HIGH",
    "Supabase Service Role Key": "HIGH",
    "Secret/Token Assignment": "HIGH",
    "Authorization Header Hardcoded": "HIGH",
    "API Key in Query Parameter": "HIGH",
    "Hardcoded Salt": "MEDIUM",
    "Credential JSON Blob": "HIGH",
    "Config Credential Leak": "HIGH",
    "Env Variable Leak": "HIGH",
    "CI/CD Token": "HIGH",
    "Kubernetes Config": "HIGH",
    "Console Credentials Leak": "HIGH",
    "Internal IP Address": "MEDIUM",
    "Internal/Staging/Dev URL": "MEDIUM",
    "Admin/Dashboard Panel URL": "MEDIUM",
    "Hardcoded SQL Query": "MEDIUM",
    "SQL String Concatenation": "MEDIUM",
    "NoSQL Injection Pattern": "MEDIUM",
    "Template Literal in Query": "MEDIUM",
    "eval() Usage": "MEDIUM",
    "Function Constructor": "MEDIUM",
    "setTimeout/setInterval with String": "MEDIUM",
    "Dynamic File Include": "MEDIUM",
    "Arbitrary File Read": "MEDIUM",
    "Path Traversal Input": "MEDIUM",
    "FTP/WebSocket/SFTP URL": "MEDIUM",
    "Supabase URL": "MEDIUM",
    "RFC1918 URL": "MEDIUM",
    "Common Service Port": "MEDIUM",
    "Elasticsearch URL": "MEDIUM",
    "CORS Allow Origin Wildcard": "MEDIUM",
    "Server-Side Request (SSRF Risk)": "MEDIUM",
    "URL Redirect (Open Redirect)": "MEDIUM",
    "Unsafe postMessage": "MEDIUM",
    "Weak Hash Algorithm (MD5/SHA1)": "MEDIUM",
    "Hardcoded IV/Nonce": "MEDIUM",
    "Insecure Random": "MEDIUM",
    "Disabled SSL Verification": "MEDIUM",
    "Credit Card Number (Visa/MC)": "MEDIUM",
    "CVV/CVC Code": "CRITICAL",
    "Date of Birth": "MEDIUM",
    "Passport Number": "MEDIUM",
    "Address Field Leak": "LOW",
    "child_process Exec Usage": "MEDIUM",
    "Command Injection Concatenation": "HIGH",
    "Prototype Pollution Sink": "MEDIUM",
    "Insecure CORS Credentials": "MEDIUM",
    "Unsafe YAML Load": "MEDIUM",
    "AWS Metadata Endpoint": "MEDIUM",
    "GCP Metadata Endpoint": "MEDIUM",
    "Azure Metadata Endpoint": "MEDIUM",
    "Docker Socket Reference": "HIGH",
    "Kubeconfig File Path": "HIGH",
    "SSN (Social Security)": "MEDIUM",
    "IBAN Number": "MEDIUM",
    "Docker Registry URL": "MEDIUM",
    "Terraform State": "MEDIUM",
    "Debug Mode Enabled": "MEDIUM",
    "Verbose Error Disclosure": "MEDIUM",
    "File Path Disclosure": "MEDIUM",
    "Kubernetes Service DNS": "LOW",
    "Internal Hostname": "LOW",
    "GraphQL Endpoint": "MEDIUM",
    "GraphQL Introspection Query": "MEDIUM",
    "GraphQL Query/Mutation": "MEDIUM",
    "Swagger/OpenAPI URL": "MEDIUM",
    "Admin/Auth Endpoint Path": "LOW",
    "Potential IDOR Endpoint": "MEDIUM",
    "Webhook URL (Generic)": "MEDIUM",
    "REST API Path Pattern": "LOW",
    "Upload/File Endpoint": "LOW",
    "Email Address": "LOW",
    "Phone Number (International)": "LOW",
    "Turkish ID Number (National ID)": "LOW",
    "IPv6 Address": "LOW",
    "Hardcoded User/Admin Name": "LOW",
    "innerHTML Assignment": "LOW",
    "outerHTML Assignment": "LOW",
    "insertAdjacentHTML": "LOW",
    "document.write Usage": "LOW",
    "DOM XSS Sink (jQuery)": "LOW",
    "Debugger Statement": "LOW",
    "Commented-Out Code Block": "LOW",
    "Hostname/Server Name Leak": "LOW",
    "Environment File Reference": "LOW",
    "TODO/FIXME/HACK Comment": "INFO",
}


def banner():
    print(f"""{Colors.GREEN}
    ============================================================
        {Colors.BOLD}akha-sourcemap{Colors.RESET}{Colors.GREEN} - JS Source Map Exposure Scanner

        URL -> Download -> Extract Sources -> Scan -> Report
    ============================================================{Colors.RESET}
    """)


def sanitize_path(base_dir, source_path):
    """Sanitize source paths and prevent directory traversal."""
    prefixes = ['webpack:///', 'webpack://', 'meteor:///', 'source:///', 'ng:///']
    for prefix in prefixes:
        if source_path.startswith(prefix):
            source_path = source_path[len(prefix):]
            break
    parsed = urlparse(source_path)
    if parsed.scheme:
        source_path = parsed.netloc + parsed.path
    source_path = source_path.split('?')[0]
    invalid_chars = '<>:"|?*\x00'
    for ch in invalid_chars:
        source_path = source_path.replace(ch, '_')
    source_path = os.path.normpath(source_path)
    parts = [p for p in source_path.split(os.sep) if p not in ('..', '.', '', '/')]
    if not parts:
        parts = ['unknown_source.js']
    parts = [p[:200] for p in parts]
    return os.path.join(base_dir, *parts)


def download_sourcemap(url):
    """Download a .js.map file from the given URL and return parsed JSON."""
    url = url.strip()
    if not url:
        return None, None

    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'https://' + url
    parsed = urlparse(url)
    if not parsed.path.endswith('.map'):
        map_url = url + '.map'
    else:
        map_url = url

    print(f"  {Colors.CYAN}[*] Downloading: {map_url}{Colors.RESET}")

    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 akha-sourcemap/2.0',
            'Accept': '*/*',
        }
        resp = requests.get(map_url, headers=headers, timeout=15, verify=False)

        if resp.status_code == 200:
            try:
                data = resp.json()
            except json.JSONDecodeError:
                content = resp.text
                smu_match = re.search(r'(?:\/\/|\/\*)\s*[#@]\s*sourceMappingURL\s*=\s*([^\s*]+)', content)
                if smu_match:
                    smu_url = smu_match.group(1)
                    if not smu_url.startswith('http'):
                        smu_url = urljoin(url, smu_url)
                    print(f"  {Colors.CYAN}[*] sourceMappingURL found, following: {smu_url}{Colors.RESET}")
                    return download_sourcemap(smu_url)
                print(f"  {Colors.RED}[-] Failed: Not valid JSON/source map{Colors.RESET}")
                return None, map_url

            if 'sources' in data:
                sources_count = len(data.get('sources', []))
                contents_count = len(data.get('sourcesContent', []))
                print(f"  {Colors.GREEN}[+] Success! {sources_count} source files, {contents_count} content entries found{Colors.RESET}")
                return data, map_url
            else:
                print(f"  {Colors.RED}[-] Failed: 'sources' array not found{Colors.RESET}")
                return None, map_url

        elif resp.status_code == 404:
            if map_url != url:
                print(f"  {Colors.YELLOW}[!] .map URL not found (404), trying original URL...{Colors.RESET}")
                resp2 = requests.get(url, headers=headers, timeout=15, verify=False)
                if resp2.status_code == 200:
                    smu_match = re.search(r'(?:\/\/|\/\*)\s*[#@]\s*sourceMappingURL\s*=\s*([^\s*]+)', resp2.text)
                    if smu_match:
                        smu_url = smu_match.group(1)
                        if not smu_url.startswith('http'):
                            smu_url = urljoin(url, smu_url)
                        print(f"  {Colors.CYAN}[*] sourceMappingURL found: {smu_url}{Colors.RESET}")
                        return download_sourcemap(smu_url)
            print(f"  {Colors.RED}[-] Not found: HTTP 404{Colors.RESET}")
            return None, map_url
        else:
            print(f"  {Colors.RED}[-] Failed: HTTP {resp.status_code}{Colors.RESET}")
            return None, map_url

    except requests.exceptions.RequestException as e:
        print(f"  {Colors.RED}[-] Connection error: {e}{Colors.RESET}")
        return None, map_url


def extract_sources(data):
    """Extract source file names and content from source map data."""
    sources = data.get('sources', [])
    contents = data.get('sourcesContent', [])
    file_contents = {}

    for i, source in enumerate(sources):
        if i < len(contents) and contents[i] is not None:
            file_contents[source] = contents[i]
        else:
            file_contents[source] = None  # No content, file name only.

    return file_contents


def fill_missing_sources(data, map_url, file_contents, timeout=12):
    """
    If sourcesContent is missing, try downloading from sourceRoot/sources references.
    This step reduces false negatives (sourcesContent can be empty in production maps).
    """
    if not map_url:
        return 0, sum(1 for v in file_contents.values() if v is None)

    source_root = data.get('sourceRoot') or ''
    fetched = 0
    attempted = 0
    missing_keys = [k for k, v in file_contents.items() if v is None]

    if not missing_keys:
        return 0, 0

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 akha-sourcemap/2.0',
        'Accept': '*/*',
    }

    for source_path in missing_keys:
        candidates = []
        src = source_path.strip()

        if src.startswith('http://') or src.startswith('https://'):
            candidates.append(src)

        if source_root:
            root = source_root.rstrip('/') + '/'
            candidates.append(urljoin(map_url, root + src.lstrip('/')))

        candidates.append(urljoin(map_url, src))
        seen = set()
        unique_candidates = []
        for c in candidates:
            if c not in seen:
                seen.add(c)
                unique_candidates.append(c)

        for candidate_url in unique_candidates:
            attempted += 1
            try:
                resp = requests.get(candidate_url, headers=headers, timeout=timeout, verify=False)
                if resp.status_code != 200:
                    continue
                content_type = (resp.headers.get('Content-Type') or '').lower()
                if any(x in content_type for x in ('image/', 'font/', 'octet-stream', 'application/zip')):
                    continue

                body = resp.text
                if not body or len(body) < 4:
                    continue

                file_contents[source_path] = body
                fetched += 1
                break
            except requests.exceptions.RequestException:
                continue

    still_missing = sum(1 for v in file_contents.values() if v is None)
    if attempted > 0:
        print(f"  {Colors.CYAN}[*] Missing source completion: {fetched} fetched, {still_missing} still missing ({attempted} attempts){Colors.RESET}")
    return fetched, still_missing


def is_false_positive(pattern_name, match_text):
    """Run false-positive checks."""
    filters = FALSE_POSITIVE_FILTERS.get(pattern_name, [])
    for fp_pattern in filters:
        if re.search(fp_pattern, match_text, re.IGNORECASE):
            return True
    return False


def calculate_entropy(s):
    """Calculate Shannon entropy. High entropy often indicates a real secret."""
    if not s:
        return 0.0
    entropy = 0.0
    length = len(s)
    freq = defaultdict(int)
    for c in s:
        freq[c] += 1
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


CONFIDENCE_LABELS = [
    (85, "VERY_HIGH"),
    (70, "HIGH"),
    (50, "MEDIUM"),
    (0, "LOW"),
]


def severity_weight(pattern_name):
    sev = PATTERN_SEVERITY.get(pattern_name, "INFO")
    return {
        "CRITICAL": 100,
        "HIGH": 75,
        "MEDIUM": 50,
        "LOW": 25,
        "INFO": 10,
    }.get(sev, 10)


def confidence_label(score):
    for threshold, label in CONFIDENCE_LABELS:
        if score >= threshold:
            return label
    return "LOW"


def score_finding(pattern_name, matched_text, context):
    """Generate a 0-100 confidence score for a finding."""
    score = severity_weight(pattern_name) - 10
    reasons = []
    text = matched_text or ""
    lower_text = text.lower()

    if len(text) >= 24:
        score += 6
        reasons.append("long_and_specific_value")

    ent = calculate_entropy(text)
    if ent >= 4.2:
        score += 12
        reasons.append("high_entropy")
    elif ent >= 3.6:
        score += 6
        reasons.append("medium_entropy")

    strict_secret_patterns = {
        "AWS Access Key ID", "Google Cloud API Key", "GitHub Token (Classic)",
        "GitHub Token (Fine-grained)", "GitLab Token", "SendGrid API Key",
        "Slack Webhook", "Private Key Block", "Certificate Block",
        "Stripe Secret Key", "NPM Access Token", "PyPI API Token",
    }
    if pattern_name in strict_secret_patterns:
        score += 10
        reasons.append("strict_signature_pattern")

    placeholder_words = [
        "example", "sample", "placeholder", "changeme", "your_", "your-",
        "dummy", "test", "token_here", "api_key_here",
    ]
    if any(w in lower_text for w in placeholder_words):
        score -= 20
        reasons.append("placeholder_suspicion")

    if re.search(r"\b(?:todo|fixme|mock|fake)\b", (context or ""), re.IGNORECASE):
        score -= 10
        reasons.append("development_context")

    score = max(0, min(100, score))
    return score, confidence_label(score), reasons


def build_priority_risks(findings, top_n=20):
    """Prioritize likely real risks by severity and confidence."""
    ranked = []
    seen = set()

    for pattern_name, items in findings.items():
        for item in items:
            dedup = (item.get('file'), item.get('line'), pattern_name, item.get('match', '')[:80])
            if dedup in seen:
                continue
            seen.add(dedup)

            verify = item.get('verification') or {}
            verify_state = verify.get('classification', 'UNVERIFIED')
            verify_bonus = 0
            if verify_state == 'VERIFIED_OPEN':
                verify_bonus = 25
            elif verify_state in {'VERIFIED_LIVE_PROTECTED', 'VERIFIED_REDIRECT'}:
                verify_bonus = 10

            risk_score = int(
                severity_weight(pattern_name) * 0.9 +
                item.get('confidence_score', 0) * 0.9 +
                verify_bonus
            )

            ranked.append({
                'pattern': pattern_name,
                'severity': PATTERN_SEVERITY.get(pattern_name, 'INFO'),
                'confidence_score': item.get('confidence_score', 0),
                'confidence_label': item.get('confidence_label', 'LOW'),
                'risk_score': min(100, risk_score),
                'file': item.get('file', ''),
                'line': item.get('line', 0),
                'context': item.get('context', ''),
                'verification': verify_state,
                'verified_url': verify.get('url', ''),
                'status_code': verify.get('status_code'),
            })

    ranked.sort(key=lambda x: (x['risk_score'], x['confidence_score']), reverse=True)
    return ranked[:top_n]


def extract_candidate_url(raw_value, base_url):
    """Try to extract a URL/path from a match and return an absolute URL."""
    if not raw_value:
        return None

    v = raw_value.strip().strip("'\"")
    if not v:
        return None
    if v.startswith('/') and " " in v:
        v = v.split()[0]

    if v.startswith('http://') or v.startswith('https://'):
        return v
    if v.startswith('/'):
        return urljoin(base_url, v)
    return None


def verify_findings_passive(findings, base_url, timeout=8, max_targets=40):
    """
    Passive verification: check endpoint liveness via unauthenticated GET requests.
    Does not attempt exploits and does not send payloads.
    """
    target_patterns = {
        "REST API Path Pattern",
        "GraphQL Endpoint",
        "Swagger/OpenAPI URL",
        "Admin/Dashboard Panel URL",
        "Upload/File Endpoint",
        "Webhook URL (Generic)",
    }

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) akha-sourcemap/2.0 PassiveVerify',
        'Accept': '*/*',
    }

    url_to_items = defaultdict(list)
    for pattern_name, items in findings.items():
        if pattern_name not in target_patterns:
            continue
        for item in items:
            candidate = extract_candidate_url(item.get('match', ''), base_url)
            if not candidate:
                candidate = extract_candidate_url(item.get('context', ''), base_url)
            if candidate:
                url_to_items[candidate].append(item)

    targets = list(url_to_items.keys())[:max_targets]
    if not targets:
        return {
            'requested': 0,
            'verified_open': 0,
            'verified_live_protected': 0,
            'verified_redirect': 0,
            'unverified': 0,
            'errors': 0,
        }

    summary = {
        'requested': 0,
        'verified_open': 0,
        'verified_live_protected': 0,
        'verified_redirect': 0,
        'unverified': 0,
        'errors': 0,
    }

    for target in targets:
        summary['requested'] += 1
        info = {
            'url': target,
            'status_code': None,
            'classification': 'UNVERIFIED',
            'content_type': '',
        }
        try:
            resp = requests.get(target, headers=headers, timeout=timeout, verify=False, allow_redirects=True)
            info['status_code'] = resp.status_code
            info['content_type'] = (resp.headers.get('Content-Type') or '')[:80]

            if 200 <= resp.status_code < 300:
                info['classification'] = 'VERIFIED_OPEN'
                summary['verified_open'] += 1
            elif resp.status_code in (401, 403):
                info['classification'] = 'VERIFIED_LIVE_PROTECTED'
                summary['verified_live_protected'] += 1
            elif resp.status_code in (301, 302, 307, 308):
                info['classification'] = 'VERIFIED_REDIRECT'
                summary['verified_redirect'] += 1
            else:
                summary['unverified'] += 1
        except requests.exceptions.RequestException:
            summary['errors'] += 1

        for item in url_to_items[target]:
            item['verification'] = info

    return summary


def split_minified_line(line, max_chunk=2000):
    """
    Split minified (single-line, very long) code into logical chunks.
    Split on semicolons, commas, and curly braces.
    """
    if len(line) <= max_chunk:
        return [(0, line)]

    chunks = []
    delimiters = re.compile(r'[;,{}]')
    start = 0
    current_pos = 0

    for match in delimiters.finditer(line):
        current_pos = match.end()
        if current_pos - start >= max_chunk:
            chunks.append((start, line[start:current_pos]))
            start = current_pos
    if start < len(line):
        chunks.append((start, line[start:]))

    return chunks if chunks else [(0, line)]


def _scan_line(check_line, filepath, line_num, char_offset,
               compiled_patterns, entropy_check_patterns,
               findings, seen_matches):
    """Scan a single line/chunk with all patterns."""
    is_in_node_modules = 'node_modules' in filepath
    for pattern_name, regex in compiled_patterns.items():
        if is_in_node_modules and pattern_name in SKIP_IN_NODE_MODULES:
            continue
        matches = regex.finditer(check_line)
        for match in matches:
            matched_text = match.group(0)
            dedup_key = (filepath, pattern_name, matched_text[:100])
            if dedup_key in seen_matches:
                continue
            seen_matches.add(dedup_key)
            if is_false_positive(pattern_name, matched_text):
                continue
            if pattern_name in entropy_check_patterns:
                value_match = re.search(r"""[=:]\s*['"]([^'"]+)['"]""", matched_text)
                if value_match:
                    value = value_match.group(1)
                    ent = calculate_entropy(value)
                    if ent < 2.0 and len(value) < 30:
                        continue
                    placeholder_words = [
                        'changeme', 'replace', 'your_', 'your-', 'xxx', 'yyy',
                        'placeholder', 'example', 'sample', 'dummy', 'change_me',
                        'insert', 'enter_', 'fill_in', 'CHANGE', 'REPLACE', 'YOUR_',
                        '<your', '{your', '${', '#{', '{{',
                    ]
                    if any(pw in value.lower() for pw in placeholder_words):
                        continue
            abs_start = char_offset + match.start()
            ctx_start = max(0, match.start() - 60)
            ctx_end = min(len(check_line), match.end() + 60)
            context = check_line[ctx_start:ctx_end].strip()
            conf_score, conf_label, conf_reasons = score_finding(pattern_name, matched_text, context)

            findings[pattern_name].append({
                'file': filepath,
                'line': line_num,
                'match': matched_text[:250],
                'context': context[:400],
              'confidence_score': conf_score,
              'confidence_label': conf_label,
              'confidence_reasons': conf_reasons,
            })
def scan_content(file_contents):
    """
    Scan all source files and detect sensitive data exposure.
    Smart-split minified code, apply entropy analysis, and filter duplicates.
    """
    findings = defaultdict(list)
    total_scanned = 0
    compiled_patterns = {}
    seen_matches = set()
    for name, pattern in SCAN_PATTERNS.items():
        try:
            compiled_patterns[name] = re.compile(pattern, re.IGNORECASE)
        except re.error as e:
            print(f"  {Colors.YELLOW}[!] Regex compile error ({name}): {e}{Colors.RESET}")

    entropy_check_patterns = {
        "Secret/Token Assignment", "Password Assignment", "Generic High Entropy String",
        "Config Credential Leak", "OAuth Client Credentials", "Hardcoded Encryption Key",
        "Authorization Header Hardcoded", "Test/Mock Credentials",
    }

    total_patterns = len(compiled_patterns)
    multiline_patterns = {"Private Key Block", "Certificate Block"}
    total_files = sum(1 for v in file_contents.values() if v is not None)
    print(f"  {Colors.CYAN}[*] {total_files} files, scanning with {total_patterns} patterns...{Colors.RESET}")

    file_idx = 0
    for filepath, content in file_contents.items():
        if content is None:
            continue
        total_scanned += 1
        file_idx += 1

        if file_idx % 50 == 0 or file_idx == total_files:
            print(f"  {Colors.DIM}  [{file_idx}/{total_files}] files scanned...{Colors.RESET}", end='\r')

        lines = content.split('\n')

        for line_num, line in enumerate(lines, 1):
            line_len = len(line)

            if line_len < 4:
                continue

            if line_len > 1000:
                chunks = split_minified_line(line, max_chunk=2000)
                for chunk_offset, chunk in chunks:
                    _scan_line(
                        chunk, filepath, line_num, chunk_offset,
                        compiled_patterns, entropy_check_patterns,
                        findings, seen_matches
                    )
            else:
                _scan_line(
                    line, filepath, line_num, 0,
                    compiled_patterns, entropy_check_patterns,
                    findings, seen_matches
                )
        for pattern_name in multiline_patterns:
            regex = compiled_patterns.get(pattern_name)
            if not regex:
                continue
            for match in regex.finditer(content):
                matched_text = match.group(0)
                dedup_key = (filepath, pattern_name, matched_text[:100])
                if dedup_key in seen_matches:
                    continue
                seen_matches.add(dedup_key)

                start_idx = match.start()
                line_num = content.count('\n', 0, start_idx) + 1
                ctx_start = max(0, start_idx - 60)
                ctx_end = min(len(content), match.end() + 60)
                context = content[ctx_start:ctx_end].replace('\n', ' ').strip()
                conf_score, conf_label, conf_reasons = score_finding(pattern_name, matched_text, context)

                findings[pattern_name].append({
                    'file': filepath,
                    'line': line_num,
                    'match': matched_text[:250],
                    'context': context[:400],
                    'confidence_score': conf_score,
                    'confidence_label': conf_label,
                    'confidence_reasons': conf_reasons,
                })

    print(f"  {Colors.GREEN}[+] Scan complete. {total_scanned} files processed.{Colors.RESET}          ")
    return findings, total_scanned


def extract_domains(file_contents):
    """Extract unique domain names from source files."""
    domain_regex = re.compile(r'(?:https?|ftp)://(?:www\.)?([a-zA-Z0-9.\-]+(?:\.[a-zA-Z]{2,6}))', re.IGNORECASE)
    domains = set()
    for content in file_contents.values():
        if content is None:
            continue
        for match in domain_regex.finditer(content):
            domain = match.group(1).lower()
            skip_domains = {'w3.org', 'schema.org', 'xmlns.com', 'purl.org'}
            if domain not in skip_domains:
                domains.add(domain)
    return sorted(domains)


def print_findings(findings, url, verify_summary=None):
    """Print findings to terminal in a formatted view."""
    if not findings:
        print(f"\n  {Colors.GREEN}[OK] No sensitive data exposure found!{Colors.RESET}")
        return
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

    total_findings = sum(len(v) for v in findings.values())
    severity_counts = defaultdict(int)
    confidence_counts = defaultdict(int)
    for pattern_name, items in findings.items():
        sev = PATTERN_SEVERITY.get(pattern_name, "INFO")
        severity_counts[sev] += len(items)
        for item in items:
            confidence_counts[item.get('confidence_label', 'LOW')] += 1

    top_risks = build_priority_risks(findings, top_n=12)

    print(f"\n{'=' * 70}")
    print(f"  {Colors.BOLD}SCAN RESULTS{Colors.RESET}")
    print(f"  URL: {Colors.CYAN}{url}{Colors.RESET}")
    print(f"  Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'=' * 70}")
    print(f"\n  {Colors.BOLD}SUMMARY:{Colors.RESET} Total {Colors.YELLOW}{total_findings}{Colors.RESET} findings")
    for sev_name in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if severity_counts[sev_name] > 0:
            color, icon = SEVERITY[sev_name]
            print(f"    {icon} {color}{sev_name}: {severity_counts[sev_name]}{Colors.RESET}")

    if any(confidence_counts.values()):
        print(
            f"  {Colors.BOLD}CONFIDENCE:{Colors.RESET} "
            f"VERY_HIGH={confidence_counts['VERY_HIGH']}, "
            f"HIGH={confidence_counts['HIGH']}, "
            f"MEDIUM={confidence_counts['MEDIUM']}, "
            f"LOW={confidence_counts['LOW']}"
        )

    if verify_summary is not None:
        print(
            f"  {Colors.BOLD}VERIFY (passive):{Colors.RESET} "
            f"attempt={verify_summary.get('requested', 0)}, "
            f"open={verify_summary.get('verified_open', 0)}, "
            f"protected={verify_summary.get('verified_live_protected', 0)}, "
            f"redirect={verify_summary.get('verified_redirect', 0)}, "
            f"errors={verify_summary.get('errors', 0)}"
        )

    print(f"\n{'-' * 70}")
    sorted_patterns = sorted(
        findings.items(),
        key=lambda x: severity_order.get(PATTERN_SEVERITY.get(x[0], "INFO"), 4)
    )

    for pattern_name, items in sorted_patterns:
        sev = PATTERN_SEVERITY.get(pattern_name, "INFO")
        color, icon = SEVERITY[sev]

        print(f"\n  {icon} {color}{Colors.BOLD}[{sev}] {pattern_name}{Colors.RESET} ({len(items)} finding)")
        print(f"  {'-' * 50}")
        file_groups = defaultdict(list)
        for item in items:
            file_groups[item['file']].append(item)

        for filepath, file_items in file_groups.items():
            print(f"    {Colors.CYAN}[FILE] {filepath}{Colors.RESET}")
            shown = file_items[:5]
            for item in shown:
                conf = item.get('confidence_label', 'LOW')
                score = item.get('confidence_score', 0)
                verify = (item.get('verification') or {}).get('classification')
                verify_note = f" | verify={verify}" if verify else ""
                print(
                    f"      {Colors.DIM}Line {item['line']:>5}:{Colors.RESET} "
                    f"[{conf}:{score}] {item['context']}{verify_note}"
                )
            if len(file_items) > 5:
                print(f"      {Colors.DIM}... and {len(file_items) - 5} more findings{Colors.RESET}")

    if top_risks:
        print(f"\n  {Colors.BOLD}PRIORITY RISK LIST (Top {len(top_risks)}):{Colors.RESET}")
        for idx, risk in enumerate(top_risks, 1):
            verify = ""
            if risk['verification'] != 'UNVERIFIED':
                verify = f" verify={risk['verification']}"
            print(
                f"    {idx:>2}. [{risk['severity']}] [{risk['confidence_label']}:{risk['confidence_score']}] "
                f"risk={risk['risk_score']} | {risk['pattern']} | {risk['file']}:{risk['line']}{verify}"
            )

    print(f"\n{'=' * 70}\n")


def generate_report(findings, domains, url, total_sources, total_scanned, output_file=None, verify_summary=None):
    """Write the report to file (if -o is provided)."""
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

    lines = []
    lines.append("=" * 70)
    lines.append("  SOURCEMAP SCANNER - EXPOSURE REPORT")
    lines.append("=" * 70)
    lines.append(f"  URL         : {url}")
    lines.append(f"  Date       : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"  Source Files: {total_sources} (with content: {total_scanned})")
    lines.append("=" * 70)

    total_findings = sum(len(v) for v in findings.values())
    severity_counts = defaultdict(int)
    confidence_counts = defaultdict(int)
    for pattern_name, items in findings.items():
        sev = PATTERN_SEVERITY.get(pattern_name, "INFO")
        severity_counts[sev] += len(items)
        for item in items:
            confidence_counts[item.get('confidence_label', 'LOW')] += 1

    top_risks = build_priority_risks(findings, top_n=20)

    lines.append(f"\n  SUMMARY: Total {total_findings} findings")
    for sev_name in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if severity_counts[sev_name] > 0:
            lines.append(f"    [{sev_name}]: {severity_counts[sev_name]}")

    lines.append(
        f"  CONFIDENCE: VERY_HIGH={confidence_counts['VERY_HIGH']} "
        f"HIGH={confidence_counts['HIGH']} MEDIUM={confidence_counts['MEDIUM']} LOW={confidence_counts['LOW']}"
    )

    if verify_summary is not None:
        lines.append(
            "  VERIFY (passive): "
            f"attempt={verify_summary.get('requested', 0)} "
            f"open={verify_summary.get('verified_open', 0)} "
            f"protected={verify_summary.get('verified_live_protected', 0)} "
            f"redirect={verify_summary.get('verified_redirect', 0)} "
            f"errors={verify_summary.get('errors', 0)}"
        )

    if top_risks:
        lines.append("\n" + "-" * 70)
        lines.append("  PRIORITY RISK LIST (Likely Real Risks)")
        lines.append("-" * 70)
        for idx, risk in enumerate(top_risks, 1):
            verify = f" verify={risk['verification']}" if risk['verification'] != 'UNVERIFIED' else ""
            lines.append(
                f"  {idx:>2}. risk={risk['risk_score']} [{risk['severity']}] "
                f"[{risk['confidence_label']}:{risk['confidence_score']}] {risk['pattern']} "
                f"@ {risk['file']}:{risk['line']}{verify}"
            )

    if findings:
        lines.append("\n" + "-" * 70)
        lines.append("  DETAILED FINDINGS")
        lines.append("-" * 70)

        sorted_patterns = sorted(
            findings.items(),
            key=lambda x: severity_order.get(PATTERN_SEVERITY.get(x[0], "INFO"), 4)
        )

        for pattern_name, items in sorted_patterns:
            sev = PATTERN_SEVERITY.get(pattern_name, "INFO")
            lines.append(f"\n  [{sev}] {pattern_name} ({len(items)} finding)")
            lines.append(f"  {'-' * 50}")

            file_groups = defaultdict(list)
            for item in items:
                file_groups[item['file']].append(item)

            for filepath, file_items in file_groups.items():
                lines.append(f"    File: {filepath}")
                for item in file_items:
                    conf = item.get('confidence_label', 'LOW')
                    score = item.get('confidence_score', 0)
                    verify = (item.get('verification') or {}).get('classification')
                    verify_note = f" | verify={verify}" if verify else ""
                    lines.append(f"      Line {item['line']:>5} [{conf}:{score}]: {item['context']}{verify_note}")
    else:
        lines.append("\n  [OK] No sensitive data exposure found!")

    if domains:
        lines.append("\n" + "-" * 70)
        lines.append(f"  EXTRACTED DOMAINS ({len(domains)} items)")
        lines.append("-" * 70)
        for domain in domains:
            lines.append(f"    - {domain}")

    lines.append("\n" + "=" * 70)
    lines.append("  End of Report")
    lines.append("=" * 70)

    report_text = "\n".join(lines)

    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(report_text)
        print(f"  {Colors.GREEN}[+] Report saved: {os.path.abspath(output_file)}{Colors.RESET}")

    return report_text


def generate_html_report(findings, domains, url, total_sources, total_scanned, output_file):
    """Generate a detailed HTML report."""
    import html as html_module
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    severity_colors = {
        "CRITICAL": {"bg": "#dc2626", "text": "#fff", "badge": "#fca5a5", "border": "#f87171", "glow": "rgba(220,38,38,0.3)"},
        "HIGH":     {"bg": "#ea580c", "text": "#fff", "badge": "#fdba74", "border": "#fb923c", "glow": "rgba(234,88,12,0.3)"},
        "MEDIUM":   {"bg": "#ca8a04", "text": "#fff", "badge": "#fde047", "border": "#facc15", "glow": "rgba(202,138,4,0.3)"},
        "LOW":      {"bg": "#2563eb", "text": "#fff", "badge": "#93c5fd", "border": "#60a5fa", "glow": "rgba(37,99,235,0.2)"},
        "INFO":     {"bg": "#6b7280", "text": "#fff", "badge": "#d1d5db", "border": "#9ca3af", "glow": "rgba(107,114,128,0.2)"},
    }
    severity_icons = {"CRITICAL": "[CRIT]", "HIGH": "[HIGH]", "MEDIUM": "[MED]", "LOW": "[LOW]", "INFO": "[INFO]"}

    total_findings = sum(len(v) for v in findings.values())
    severity_counts = defaultdict(int)
    for pattern_name, items in findings.items():
        sev = PATTERN_SEVERITY.get(pattern_name, "INFO")
        severity_counts[sev] += len(items)

    top_risks = build_priority_risks(findings, top_n=20)

    scan_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    summary_badges = ""
    for sev_name in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = severity_counts.get(sev_name, 0)
        sc = severity_colors[sev_name]
        summary_badges += f"""
        <div class="stat-card" style="border-left: 4px solid {sc['bg']};">
          <div class="stat-count" style="color: {sc['bg']};">{count}</div>
          <div class="stat-label">{severity_icons[sev_name]} {sev_name}</div>
        </div>"""
    risk_score = min(100, (
        severity_counts.get("CRITICAL", 0) * 25 +
        severity_counts.get("HIGH", 0) * 10 +
        severity_counts.get("MEDIUM", 0) * 4 +
        severity_counts.get("LOW", 0) * 1 +
        severity_counts.get("INFO", 0) * 0
    ))
    if risk_score >= 75:
        risk_color, risk_label = "#dc2626", "CRITICAL"
    elif risk_score >= 50:
        risk_color, risk_label = "#ea580c", "HIGH"
    elif risk_score >= 25:
        risk_color, risk_label = "#ca8a04", "ORTA"
    elif risk_score > 0:
        risk_color, risk_label = "#2563eb", "LOW"
    else:
        risk_color, risk_label = "#16a34a", "CLEAN"
    findings_html = ""
    sorted_patterns = sorted(
        findings.items(),
        key=lambda x: severity_order.get(PATTERN_SEVERITY.get(x[0], "INFO"), 4)
    )

    for pattern_name, items in sorted_patterns:
        sev = PATTERN_SEVERITY.get(pattern_name, "INFO")
        sc = severity_colors[sev]
        file_groups = defaultdict(list)
        for item in items:
            file_groups[item['file']].append(item)

        file_rows = ""
        for filepath, file_items in file_groups.items():
            escaped_path = html_module.escape(filepath)
            rows_for_file = ""
            for item in file_items:
                escaped_context = html_module.escape(item['context'])
                escaped_match = html_module.escape(item['match'][:120])
                rows_for_file += f"""
                <tr>
                  <td class="line-num">Line {item['line']}</td>
                  <td class="context-cell"><code>{escaped_context}</code></td>
                </tr>"""

            file_rows += f"""
            <div class="file-group">
              <div class="file-path">[FILE] {escaped_path} <span class="file-count">({len(file_items)} matches)</span></div>
              <table class="findings-table">
                {rows_for_file}
              </table>
            </div>"""

        findings_html += f"""
        <div class="finding-card" style="border-left: 4px solid {sc['bg']};">
          <div class="finding-header" onclick="this.parentElement.classList.toggle('collapsed')">
            <div class="finding-title">
              <span class="sev-badge" style="background:{sc['bg']};color:{sc['text']};">{sev}</span>
              <span class="pattern-name">{html_module.escape(pattern_name)}</span>
              <span class="finding-count">{len(items)} finding</span>
            </div>
            <span class="collapse-icon">v</span>
          </div>
          <div class="finding-body">
            {file_rows}
          </div>
        </div>"""
    domains_html = ""
    if domains:
        domain_items = ""
        for d in domains:
            domain_items += f'<span class="domain-tag">{html_module.escape(d)}</span>\n'
        domains_html = f"""
        <div class="section">
          <h2 class="section-title">[DOMAIN] Extracted Domains <span class="section-count">({len(domains)})</span></h2>
          <div class="domains-grid">
            {domain_items}
          </div>
        </div>"""

    priority_rows = ""
    for idx, risk in enumerate(top_risks, 1):
        verify_text = "" if risk['verification'] == 'UNVERIFIED' else f" | {risk['verification']}"
        priority_rows += f"""
        <tr>
          <td class="line-num">#{idx}</td>
          <td class="context-cell"><code>[{html_module.escape(risk['severity'])}] risk={risk['risk_score']} conf={risk['confidence_label']}:{risk['confidence_score']} | {html_module.escape(risk['pattern'])} | {html_module.escape(risk['file'])}:{risk['line']}{html_module.escape(verify_text)}</code></td>
        </tr>"""

    top_risks_html = ""
    if top_risks:
        top_risks_html = f"""
        <div class="section">
          <h2 class="section-title">[HOT] Priority Risk List <span class="section-count">(Top {len(top_risks)})</span></h2>
          <table class="findings-table">
            {priority_rows}
          </table>
        </div>"""
    source_ext_counts = defaultdict(int)
    for filepath in (f for f in findings.keys()):
        pass  # findings key = pattern name, not filepath
    all_files_in_findings = set()
    for items in findings.values():
        for item in items:
            all_files_in_findings.add(item['file'])
            ext = item['file'].rsplit('.', 1)[-1].lower() if '.' in item['file'] else 'other'
            source_ext_counts[ext] += 1

    escaped_url = html_module.escape(url)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>akha-sourcemap - Report | {escaped_url}</title>
  <style>
    :root {{
      --bg-primary: #0a0e17;
      --bg-secondary: #111827;
      --bg-card: #1a1f2e;
      --bg-card-hover: #1f2937;
      --text-primary: #e5e7eb;
      --text-secondary: #9ca3af;
      --text-muted: #6b7280;
      --border-color: #374151;
      --accent: #10b981;
      --accent-glow: rgba(16, 185, 129, 0.15);
      --code-bg: #0d1117;
      --scrollbar-bg: #1a1f2e;
      --scrollbar-thumb: #374151;
    }}

    * {{ box-sizing: border-box; margin: 0; padding: 0; }}

    body {{
      font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
      background: var(--bg-primary);
      color: var(--text-primary);
      line-height: 1.6;
      min-height: 100vh;
    }}

    ::-webkit-scrollbar {{ width: 8px; height: 8px; }}
    ::-webkit-scrollbar-track {{ background: var(--scrollbar-bg); }}
    ::-webkit-scrollbar-thumb {{ background: var(--scrollbar-thumb); border-radius: 4px; }}
    ::-webkit-scrollbar-thumb:hover {{ background: #4b5563; }}

    .container {{
      max-width: 1400px;
      margin: 0 auto;
      padding: 20px;
    }}

    /* HEADER */
    .report-header {{
      background: linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #0f172a 100%);
      border: 1px solid var(--border-color);
      border-radius: 16px;
      padding: 40px;
      margin-bottom: 24px;
      position: relative;
      overflow: hidden;
    }}
    .report-header::before {{
      content: '';
      position: absolute;
      top: 0; left: 0; right: 0;
      height: 3px;
      background: linear-gradient(90deg, #10b981, #3b82f6, #8b5cf6, #ef4444);
    }}
    .header-top {{
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      flex-wrap: wrap;
      gap: 20px;
    }}
    .header-brand {{
      display: flex;
      align-items: center;
      gap: 15px;
    }}
    .header-logo {{
      font-size: 2.2em;
      line-height: 1;
    }}
    .header-title {{
      font-size: 1.8em;
      font-weight: 700;
      background: linear-gradient(135deg, #10b981, #3b82f6);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
    }}
    .header-subtitle {{
      color: var(--text-secondary);
      font-size: 0.9em;
      margin-top: 4px;
    }}
    .header-meta {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 12px;
      margin-top: 24px;
      padding-top: 20px;
      border-top: 1px solid var(--border-color);
    }}
    .meta-item {{
      display: flex;
      flex-direction: column;
      gap: 2px;
    }}
    .meta-label {{
      font-size: 0.75em;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }}
    .meta-value {{
      font-size: 0.95em;
      color: var(--text-primary);
      word-break: break-all;
    }}

    /* RISK GAUGE */
    .risk-gauge {{
      text-align: center;
      padding: 20px;
    }}
    .risk-circle {{
      width: 100px;
      height: 100px;
      border-radius: 50%;
      display: inline-flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      border: 4px solid {risk_color};
      box-shadow: 0 0 20px {risk_color}33;
    }}
    .risk-score {{
      font-size: 1.8em;
      font-weight: 800;
      color: {risk_color};
      line-height: 1;
    }}
    .risk-label {{
      font-size: 0.7em;
      color: {risk_color};
      font-weight: 600;
      margin-top: 2px;
    }}

    /* STATS */
    .stats-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
      gap: 12px;
      margin-bottom: 24px;
    }}
    .stat-card {{
      background: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: 10px;
      padding: 16px;
      text-align: center;
      transition: transform 0.2s, box-shadow 0.2s;
    }}
    .stat-card:hover {{
      transform: translateY(-2px);
      box-shadow: 0 4px 12px rgba(0,0,0,0.3);
    }}
    .stat-count {{
      font-size: 2em;
      font-weight: 800;
      line-height: 1.2;
    }}
    .stat-label {{
      font-size: 0.85em;
      color: var(--text-secondary);
      margin-top: 4px;
    }}
    .stat-total {{
      border-left: 4px solid var(--accent) !important;
    }}
    .stat-total .stat-count {{ color: var(--accent); }}

    /* FILTER BAR */
    .filter-bar {{
      background: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: 10px;
      padding: 12px 16px;
      margin-bottom: 20px;
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      align-items: center;
    }}
    .filter-bar label {{
      font-size: 0.85em;
      color: var(--text-secondary);
      margin-right: 4px;
    }}
    .filter-btn {{
      padding: 6px 14px;
      border-radius: 6px;
      border: 1px solid var(--border-color);
      background: var(--bg-secondary);
      color: var(--text-secondary);
      cursor: pointer;
      font-size: 0.8em;
      transition: all 0.2s;
    }}
    .filter-btn:hover {{ border-color: var(--accent); color: var(--accent); }}
    .filter-btn.active {{
      background: var(--accent);
      color: #fff;
      border-color: var(--accent);
    }}
    .search-input {{
      flex: 1;
      min-width: 200px;
      padding: 6px 12px;
      border-radius: 6px;
      border: 1px solid var(--border-color);
      background: var(--bg-secondary);
      color: var(--text-primary);
      font-size: 0.85em;
      outline: none;
    }}
    .search-input:focus {{ border-color: var(--accent); box-shadow: 0 0 0 2px var(--accent-glow); }}

    /* SECTIONS */
    .section {{
      margin-bottom: 24px;
    }}
    .section-title {{
      font-size: 1.2em;
      font-weight: 700;
      margin-bottom: 16px;
      padding-bottom: 8px;
      border-bottom: 1px solid var(--border-color);
      color: var(--text-primary);
    }}
    .section-count {{
      font-weight: 400;
      color: var(--text-muted);
      font-size: 0.85em;
    }}

    /* FINDING CARDS */
    .finding-card {{
      background: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: 10px;
      margin-bottom: 12px;
      overflow: hidden;
      transition: box-shadow 0.2s;
    }}
    .finding-card:hover {{
      box-shadow: 0 2px 12px rgba(0,0,0,0.2);
    }}
    .finding-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 14px 18px;
      cursor: pointer;
      user-select: none;
      transition: background 0.2s;
    }}
    .finding-header:hover {{
      background: var(--bg-card-hover);
    }}
    .finding-title {{
      display: flex;
      align-items: center;
      gap: 10px;
      flex-wrap: wrap;
    }}
    .sev-badge {{
      padding: 3px 10px;
      border-radius: 4px;
      font-size: 0.7em;
      font-weight: 700;
      letter-spacing: 0.05em;
    }}
    .pattern-name {{
      font-weight: 600;
      font-size: 0.95em;
    }}
    .finding-count {{
      color: var(--text-muted);
      font-size: 0.8em;
    }}
    .collapse-icon {{
      color: var(--text-muted);
      transition: transform 0.3s;
      font-size: 0.8em;
    }}
    .finding-card.collapsed .collapse-icon {{
      transform: rotate(-90deg);
    }}
    .finding-card.collapsed .finding-body {{
      display: none;
    }}
    .finding-body {{
      border-top: 1px solid var(--border-color);
      padding: 0;
    }}

    /* FILE GROUP */
    .file-group {{
      border-bottom: 1px solid var(--border-color);
    }}
    .file-group:last-child {{ border-bottom: none; }}
    .file-path {{
      padding: 10px 18px;
      background: rgba(16, 185, 129, 0.05);
      color: #34d399;
      font-family: 'Cascadia Code', 'Fira Code', monospace;
      font-size: 0.82em;
      font-weight: 500;
    }}
    .file-count {{
      color: var(--text-muted);
      font-weight: 400;
    }}
    .findings-table {{
      width: 100%;
      border-collapse: collapse;
    }}
    .findings-table tr {{
      border-bottom: 1px solid rgba(55, 65, 81, 0.5);
      transition: background 0.15s;
    }}
    .findings-table tr:hover {{ background: rgba(255,255,255,0.02); }}
    .findings-table tr:last-child {{ border-bottom: none; }}
    .line-num {{
      padding: 8px 12px 8px 24px;
      color: var(--text-muted);
      font-family: 'Cascadia Code', 'Fira Code', monospace;
      font-size: 0.78em;
      white-space: nowrap;
      vertical-align: top;
      width: 100px;
    }}
    .context-cell {{
      padding: 8px 18px 8px 0;
    }}
    .context-cell code {{
      font-family: 'Cascadia Code', 'Fira Code', monospace;
      font-size: 0.8em;
      color: #d1d5db;
      background: var(--code-bg);
      padding: 3px 8px;
      border-radius: 4px;
      display: inline-block;
      max-width: 100%;
      overflow-x: auto;
      word-break: break-all;
      white-space: pre-wrap;
    }}

    /* DOMAINS */
    .domains-grid {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
    }}
    .domain-tag {{
      background: var(--bg-secondary);
      border: 1px solid var(--border-color);
      padding: 5px 12px;
      border-radius: 6px;
      font-family: monospace;
      font-size: 0.82em;
      color: #60a5fa;
      transition: all 0.2s;
    }}
    .domain-tag:hover {{
      border-color: #60a5fa;
      background: rgba(96, 165, 250, 0.1);
    }}

    /* FOOTER */
    .report-footer {{
      text-align: center;
      padding: 24px;
      color: var(--text-muted);
      font-size: 0.8em;
      border-top: 1px solid var(--border-color);
      margin-top: 40px;
    }}
    .report-footer a {{ color: var(--accent); text-decoration: none; }}

    /* CHART */
    .chart-bar-container {{
      display: flex;
      align-items: center;
      gap: 10px;
      margin-bottom: 6px;
    }}
    .chart-bar-label {{
      width: 80px;
      text-align: right;
      font-size: 0.8em;
      color: var(--text-secondary);
    }}
    .chart-bar-track {{
      flex: 1;
      height: 22px;
      background: var(--bg-secondary);
      border-radius: 4px;
      overflow: hidden;
    }}
    .chart-bar-fill {{
      height: 100%;
      border-radius: 4px;
      display: flex;
      align-items: center;
      padding-left: 8px;
      font-size: 0.72em;
      font-weight: 600;
      color: #fff;
      transition: width 0.8s ease;
    }}

    /* PRINT */
    @media print {{
      body {{ background: #fff; color: #000; }}
      .filter-bar {{ display: none; }}
      .finding-card.collapsed .finding-body {{ display: block !important; }}
      .report-header::before {{ display: none; }}
    }}

    /* Responsive */
    @media (max-width: 768px) {{
      .container {{ padding: 10px; }}
      .report-header {{ padding: 20px; }}
      .header-title {{ font-size: 1.3em; }}
      .stats-grid {{ grid-template-columns: repeat(3, 1fr); }}
    }}
  </style>
</head>
<body>

<div class="container">

  <!-- HEADER -->
  <div class="report-header">
    <div class="header-top">
      <div class="header-brand">
        <div class="header-logo">[SEC]</div>
        <div>
          <div class="header-title">akha-sourcemap</div>
          <div class="header-subtitle">JavaScript Source Map Exposure Scan Report</div>
        </div>
      </div>
      <div class="risk-gauge">
        <div class="risk-circle">
          <div class="risk-score">{risk_score}</div>
          <div class="risk-label">{risk_label}</div>
        </div>
      </div>
    </div>
    <div class="header-meta">
      <div class="meta-item">
        <span class="meta-label">Target URL</span>
        <span class="meta-value">{escaped_url}</span>
      </div>
      <div class="meta-item">
        <span class="meta-label">Scan Date</span>
        <span class="meta-value">{scan_time}</span>
      </div>
      <div class="meta-item">
        <span class="meta-label">Total Source Files</span>
        <span class="meta-value">{total_sources} files ({total_scanned} scanned)</span>
      </div>
      <div class="meta-item">
        <span class="meta-label">Scan Patterns</span>
        <span class="meta-value">{len(SCAN_PATTERNS)} regex pattern</span>
      </div>
    </div>
  </div>

  <!-- STATS -->
  <div class="stats-grid">
    <div class="stat-card stat-total">
      <div class="stat-count">{total_findings}</div>
      <div class="stat-label">Total Findings</div>
    </div>
    {summary_badges}
    <div class="stat-card" style="border-left: 4px solid #8b5cf6;">
      <div class="stat-count" style="color: #8b5cf6;">{len(domains)}</div>
    <div class="stat-label">[DOMAIN] Domains</div>
    </div>
  </div>

  <!-- SEVERITY BAR CHART -->
  <div class="section">
    <h2 class="section-title">[CHART] Finding Distribution</h2>
    {"".join(f'''
    <div class="chart-bar-container">
      <div class="chart-bar-label">{sev_name}</div>
      <div class="chart-bar-track">
        <div class="chart-bar-fill" style="width: {max(2, (severity_counts.get(sev_name, 0) / max(total_findings, 1)) * 100):.1f}%; background: {severity_colors[sev_name]['bg']};">
          {severity_counts.get(sev_name, 0)}
        </div>
      </div>
    </div>''' for sev_name in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] if severity_counts.get(sev_name, 0) > 0)}
  </div>

  <!-- FILTER BAR -->
  <div class="filter-bar">
    <label>Filter:</label>
    <button class="filter-btn active" onclick="filterFindings('ALL')">All</button>
    {"".join(f'<button class="filter-btn" onclick="filterFindings(&apos;{sev}&apos;)" data-sev="{sev}">{severity_icons[sev]} {sev} ({severity_counts.get(sev, 0)})</button>' for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] if severity_counts.get(sev, 0) > 0)}
    <input type="text" class="search-input" placeholder="[SEARCH] Search findings..." oninput="searchFindings(this.value)">
  </div>

  <!-- PRIORITY RISKS -->
  {top_risks_html}

  <!-- FINDINGS -->
  <div class="section" id="findings-section">
    <h2 class="section-title">[SEARCH] Detailed Findings <span class="section-count">({len(findings)} categories, {total_findings} findings)</span></h2>
    {findings_html if findings_html else '<p style="color: var(--text-muted); padding: 20px;">[OK] No sensitive data exposure found!</p>'}
  </div>

  <!-- DOMAINS -->
  {domains_html}

  <!-- FOOTER -->
  <div class="report-footer">
    akha-sourcemap v1.0 - Report generated: {scan_time}<br>
    Powered by <strong>akha-security</strong> - <a href="https://www.github.com/akha-security" target="_blank">GitHub</a>
  </div>

</div>

<script>
    // Severity filtering
  function filterFindings(severity) {{
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    if (severity === 'ALL') {{
      document.querySelectorAll('.finding-card').forEach(c => c.style.display = '');
      document.querySelector('.filter-btn').classList.add('active');
    }} else {{
      event.target.classList.add('active');
      document.querySelectorAll('.finding-card').forEach(c => {{
        const badge = c.querySelector('.sev-badge');
        c.style.display = badge && badge.textContent.trim() === severity ? '' : 'none';
      }});
    }}
  }}

    // Text search
  function searchFindings(query) {{
    query = query.toLowerCase();
    document.querySelectorAll('.finding-card').forEach(card => {{
      if (!query) {{
        card.style.display = '';
        return;
      }}
      const text = card.textContent.toLowerCase();
      card.style.display = text.includes(query) ? '' : 'none';
    }});
  }}

    // Auto-collapse LOW and INFO on page load
  document.addEventListener('DOMContentLoaded', () => {{
    document.querySelectorAll('.finding-card').forEach(card => {{
      const badge = card.querySelector('.sev-badge');
      if (badge) {{
        const sev = badge.textContent.trim();
        if (sev === 'LOW' || sev === 'INFO') {{
          card.classList.add('collapsed');
        }}
      }}
    }});
  }});
</script>

</body>
</html>"""

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_content)

    print(f"  {Colors.GREEN}[+] HTML Report saved: {os.path.abspath(output_file)}{Colors.RESET}")
    return output_file


def save_sources_to_disk(file_contents, url, output_dir):
    """Save source files to disk."""
    parsed = urlparse(url)
    host = parsed.netloc.replace(':', '_')
    path_parts = [p for p in parsed.path.split('/') if p]
    filename = path_parts[-1] if path_parts else 'unknown'
    filename = filename.replace('.js.map', '').replace('.map', '').replace('.js', '')
    folder_name = f"{host}_{filename}"[:100]
    base_dir = os.path.join(output_dir, folder_name)
    saved = 0
    errors = 0

    for source_path, content in file_contents.items():
        if content is None:
            content = f"/* sourcesContent not found.\nFile: {source_path} */"

        save_path = sanitize_path(base_dir, source_path)
        abs_path = os.path.abspath(save_path)
        if len(abs_path) > 250:
            short_name = os.path.basename(save_path)[:100]
            save_path = os.path.join(base_dir, '_long_paths', short_name)

        try:
            os.makedirs(os.path.dirname(save_path), exist_ok=True)
            with open(save_path, 'w', encoding='utf-8') as f:
                f.write(content)
            saved += 1
        except (OSError, IOError):
            errors += 1

    msg = f"  {Colors.GREEN}[+] {saved} source files saved: {os.path.abspath(base_dir)}{Colors.RESET}"
    if errors:
        msg += f" {Colors.YELLOW}({errors} files could not be saved){Colors.RESET}"
    print(msg)
    return base_dir


def process_single_url(url, args):
  """Process a single URL: download -> extract -> scan -> report."""
    start_ts = time.perf_counter()
    data, resolved_url = download_sourcemap(url)
    if data is None:
        elapsed = time.perf_counter() - start_ts
        print(f"  {Colors.YELLOW}[!] Scan could not complete (source map unavailable). Duration: {elapsed:.2f}s{Colors.RESET}")
        return False
    file_contents = extract_sources(data)
    total_sources = len(file_contents)
    print(f"  {Colors.GREEN}[+] {total_sources} source files extracted{Colors.RESET}")
    fill_missing_sources(data, resolved_url or url, file_contents)
    output_dir = args.sources_dir or './output'
    save_sources_to_disk(file_contents, resolved_url or url, output_dir)
    print(f"  {Colors.CYAN}[*] Starting sensitive data scan...{Colors.RESET}")
    findings, total_scanned = scan_content(file_contents)
    total_findings = sum(len(v) for v in findings.values())

    if total_scanned == 0:
        print(f"  {Colors.YELLOW}[!] Warning: No scannable source content found (0 files processed).{Colors.RESET}")

    verify_summary = None
    if args.verify_passive:
        print(f"  {Colors.CYAN}[*] Passive verify mode: checking endpoint liveness...{Colors.RESET}")
        verify_summary = verify_findings_passive(
            findings,
            resolved_url or url,
            timeout=max(3, args.verify_timeout),
            max_targets=max(5, args.verify_max_targets),
        )
    domains = extract_domains(file_contents)
    print_findings(findings, resolved_url or url, verify_summary=verify_summary)

    if domains:
        print(f"  {Colors.BOLD}EXTRACTED DOMAINS ({len(domains)} items):{Colors.RESET}")
        for d in domains[:30]:
          print(f"    - {Colors.CYAN}{d}{Colors.RESET}")
        if len(domains) > 30:
          print(f"    {Colors.DIM}... and {len(domains) - 30} more domains{Colors.RESET}")
        print()
    if args.output:
        generate_report(
            findings,
            domains,
            resolved_url or url,
            total_sources,
            total_scanned,
            args.output,
            verify_summary=verify_summary,
        )
    html_file = args.output.rsplit('.', 1)[0] + '.html' if args.output else f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    generate_html_report(findings, domains, resolved_url or url, total_sources, total_scanned, html_file)

    elapsed = time.perf_counter() - start_ts
    print(
      f"  {Colors.BOLD}[*] Summary:{Colors.RESET} "
      f"sources={total_sources}, scanned={total_scanned}, findings={total_findings}, duration={elapsed:.2f}s"
    )

    return True


def main():
    parser = argparse.ArgumentParser(
        description="akha-sourcemap - Download JS source maps and scan for exposure",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -u https://example.com/app.js
  %(prog)s -u https://example.com/app.js.map -o report.txt
  %(prog)s -f urls.txt
  %(prog)s -u https://example.com/app.js --sources-dir ./source_files
        """
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-u', '--url', help='Single JS/JS.map URL to scan')
    group.add_argument('-f', '--file', help='File containing URL list (one URL per line)')

    parser.add_argument('-o', '--output', help='Report output file (e.g. report.txt)')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Concurrent worker count (default: 5)')
    parser.add_argument('--sources-dir', default='./output', help='Directory to save source files (default: ./output)')
    parser.add_argument('--verify-passive', action='store_true', help='Run passive endpoint verification (no payload/exploit)')
    parser.add_argument('--verify-timeout', type=int, default=8, help='Passive verify timeout in seconds (default: 8)')
    parser.add_argument('--verify-max-targets', type=int, default=40, help='Maximum target URLs for passive verify (default: 40)')

    args = parser.parse_args()

    banner()

    if args.url:
        print(f"  {Colors.BOLD}[*] Target: {args.url}{Colors.RESET}\n")
        ok = process_single_url(args.url, args)
        if not ok:
          print(f"  {Colors.RED}[!] Operation failed.{Colors.RESET}\n")
            sys.exit(1)
    elif args.file:
        if not os.path.isfile(args.file):
          print(f"  {Colors.RED}[!] Error: File not found: '{args.file}'{Colors.RESET}")
            sys.exit(1)

        with open(args.file, 'r', encoding='utf-8', errors='ignore') as f:
            urls = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]

        if not urls:
          print(f"  {Colors.RED}[!] Error: File is empty or has no valid URLs.{Colors.RESET}")
            sys.exit(1)

        print(f"  {Colors.BOLD}[*] Loaded {len(urls)} URLs.{Colors.RESET}\n")
        all_findings = defaultdict(list)
        all_domains = set()
        success_count = 0

        for i, url in enumerate(urls, 1):
            print(f"\n{'=' * 70}")
            print(f"  {Colors.BOLD}[{i}/{len(urls)}] {url}{Colors.RESET}")
            print(f"{'=' * 70}")

            data, resolved_url = download_sourcemap(url)
            if data is None:
                continue

            file_contents = extract_sources(data)
            total_sources = len(file_contents)
            print(f"  {Colors.GREEN}[+] {total_sources} source files extracted{Colors.RESET}")
            fill_missing_sources(data, resolved_url or url, file_contents)

            output_dir = args.sources_dir or './output'
            save_sources_to_disk(file_contents, resolved_url or url, output_dir)

            print(f"  {Colors.CYAN}[*] Scanning...{Colors.RESET}")
            findings, total_scanned = scan_content(file_contents)

            verify_summary = None
            if args.verify_passive:
                print(f"  {Colors.CYAN}[*] Passive verify: endpoint liveness check...{Colors.RESET}")
                verify_summary = verify_findings_passive(
                    findings,
                    resolved_url or url,
                    timeout=max(3, args.verify_timeout),
                    max_targets=max(5, args.verify_max_targets),
                )

            domains = extract_domains(file_contents)
            all_domains.update(domains)

            print_findings(findings, resolved_url or url, verify_summary=verify_summary)
            for k, v in findings.items():
                all_findings[k].extend(v)

            success_count += 1
        print(f"\n{'=' * 70}")
        print(f"  {Colors.BOLD}OVERALL SUMMARY{Colors.RESET}")
        print(f"  Scanned URLs: {success_count}/{len(urls)}")
        total_all = sum(len(v) for v in all_findings.values())
        print(f"  Total Findings: {total_all}")
        print(f"  Total Domains: {len(all_domains)}")
        print(f"{'=' * 70}")
        if args.output:
            generate_report(
                all_findings,
                sorted(all_domains),
                f"{len(urls)} URL",
                0,
                0,
                args.output,
                verify_summary=None,
            )
        html_file = args.output.rsplit('.', 1)[0] + '.html' if args.output else f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        generate_html_report(all_findings, sorted(all_domains), f"{len(urls)} URL", 0, 0, html_file)

    print(f"  {Colors.GREEN}[OK] Operation completed!{Colors.RESET}\n")


if __name__ == '__main__':
    main()

