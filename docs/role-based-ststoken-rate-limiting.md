## QoS when Non Static idetites are used. 

### Introduction

In S3, a client can assume a role, which means a client can use AWS Security Token Service (STS) to temporarily adopt an IAM role with specific permissions for accessing S3 resources, instead of relying on long-term credentials such as access key/secret key. A user or service calls AssumeRole to receive a short-lived STS token scoped by the role’s policy, enabling controlled and auditable access to S3 buckets—often across accounts or environments. [AssumeRole](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html), [boto3 eg](https://docs.aws.amazon.com/boto3/latest/reference/services/sts/client/assume_role.html#) 

### Changes to incorposrate ephemeral identities (IAM/RBAC)

When a client uses an ephemeral identity (Assume Role/Assume Role with web identity, etc.), Ceph or other identity providers give them a temporary identity (e.g., token). This token is mapped to the entity which defines the rate that’s allocated to a user (e.g., Role - WriteRole can get 100 GETs per sec or 10 GB per minute if they have XYZ plan).

For enforcing rates on these, we extract the Role<>Token mapping when a user does an assume role. Role being the entity which defines the limit and token being the ephemeral identity in this case.

This mapping is stored in Redis. Each time a user uses the token to perform data operations, we extract the token and the usage stats (bandwidth, request rate, and concurrent requests). The usage stats are then aggregated at a role level using the Role<>Token mapping. This aggregated number is used to enforce the rate limiting.

Tokens which violate the limits are sent back to HAProxy to be throttled. Much like the earlier approach, HAProxy maintains a table of tokens and users to be throttled and enforces throttling.