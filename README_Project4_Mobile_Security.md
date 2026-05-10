# 🔐 Project 4: Mobile Security Implementation & Compliance Lab

## Overview
This project demonstrates practical mobile security hardening for Android and backend systems against MITM attacks and data theft, aligned with GDPR and ISO 27002.

## 1. System Configuration

### Android Network Security
```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <domain-config cleartextTrafficPermitted="false">
        <domain includeSubdomains="true">10.0.2.2</domain>
        <pin-set expiration="2027-01-01">
            <pin digest="SHA-256">B+k1n+h3qxEjS2bMGKH27YXsU4D8aj++9gqnZ4624EU=</pin>
        </pin-set>
        <trust-anchors>
            <certificates src="system"/>
        </trust-anchors>
    </domain-config>
</network-security-config>
```

### Secure Storage (Kotlin)
```kotlin
val masterKeyAlias = MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC)
val sharedPrefs = EncryptedSharedPreferences.create(
    "secure_data",
    masterKeyAlias,
    context,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
)
sharedPrefs.edit().putString("auth_token", token).apply()
```

## 2. Implementation Process
1. Setup Android Emulator API 30+, Screen Lock, Device Encryption.
2. Run secure backend:
```bash
node server_hard.js
```
3. Test vulnerable version:
```bash
adb shell run-as com.demo.mitm cat files/token.txt
```
4. Harden app: HTTPS, certificate pinning, encrypted storage.

## 3. Compliance Evaluation

| ID | Vulnerability | Control | Standard | Status |
|---|---|---|---|---|
| VULN-001 | MITM Attack | HTTPS + Pinning | GDPR Art.32 | Pass |
| VULN-002 | Token Theft | EncryptedSharedPreferences | ISO 27002 8.24 | Pass |
| VULN-003 | Weak MFA | OTP / Biometrics | ISO 27002 8.05 | Pass |

## 4. Quick Start

```bash
node server_hard.js
adb shell run-as com.demo.mitm rm files/token.txt
python 03_storage_audit.py --phase defense
```

## Author
Name: [Your Name]  
Student ID: [Your Student ID]
