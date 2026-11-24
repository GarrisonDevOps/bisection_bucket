---
stage: Security Factory
group: Secret Detection
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Detected secrets
---

{{< details >}}

- Tier: Free, Premium, Ultimate
- Offering: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

## Secret categories

GitLab Secret Detection identifies secrets using two approaches: rule-based detection and generic detection.

### Rule-based detection

Rule-based detection identifies secrets by matching scanned content against a known pattern for each
credential type, called a rule. For example, a GitLab personal access token is identified by the pattern
`glpat-` followed by a 20-character string. GitLab supports
[200+ rules](#supported-rules-for-rule-based-detection) covering popular vendors by default.

Rule-based detection's coverage is limited to the rules the analyzer supports.
Secrets that don't match a supported rule aren't detected. Both the Gitleaks-based analyzer
and [GitLab Secret Scanning for Source Code](gitlab_secret_scanner/_index.md)
support rule-based detection.

### Generic detection

{{< details >}}

- Tier: Ultimate
- Offering: GitLab.com, GitLab Self-Managed, GitLab Dedicated
- Status: Beta

{{< /details >}}

Rule-based detection can only find secrets that match a pattern it already knows about.
Many credentials don't follow a published or consistent format, so no rule can match them.
For example, a password for an internal service, a database connection string, or an API key
with no distinguishing prefix.
Generic detection targets these secrets.
Instead of matching a fixed pattern, generic detection examines the context around a value and the properties
of the value itself. Both signals determine whether the value is likely to be a credential.

Because generic detection doesn't depend on a known pattern, it can catch secrets that rule-based
detection misses. It's also more prone to false positives, so GitLab Secret Scanning for Source Code
includes false positive reduction to reduce noise.

GitLab Secret Scanning for Source Code is the only GitLab analyzer that supports generic detection.
For more information, see [generic secrets](gitlab_secret_scanner/_index.md#generic-secrets).

Generic detection isn't limited to an obvious `secret = "value"` assignment.
The following snippet shows less obvious values it identifies, and the finding each one produces:

```plaintext
# Secret assigned in a Perl hash, not a plain key-value pair
$config{'webhook_token'} = "Of0Pg2Qh4Ri6Sj8Tk";

# Password stored as the content of an XML element, not an attribute
<db_password>Ct8Du0Ev2Fw4Gx6Hy</db_password>

# API key passed as a URL query parameter
https://app.gitlab.com?api_key=Of3Pg5Qh7Ri9Sj1Tk

# Token embedded as a literal value in a SQL statement
INSERT INTO secrets (key, value) VALUES ('api_token', 'Kb1Lc3Md5Ne7Of9Pg');

# Password assigned through an environment variable lookup, not a plain variable
ENV["redis_pass"] = "Tt7Yy9Uu1Ii3OoPp5"

# Token passed as an argument to a setter method, not a direct assignment
config.put("dbToken", "Kb8Lc0Md2Ne4Of6Pg");

# Bearer token embedded in an XML configuration property
<property name="authorizationHeader" value="Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"/>

# Secret passed as a CLI flag, not a variable assignment
curl "https://api.example.com/v1/deploy" --api-token=7bN2vLpQ9wXzKfM4

# Credential left behind in a comment
# old admin password was T3mpP@ssw0rd2023XyZ1, rotate before removing this line

# UUID-formatted secret
client_secret: 123e4567-e89b-12d3-a456-426614174000

# Secret disguised by Base64 encoding
auth_token = "c2VjcmV0LWFwaS1rZXktdmFsdWU="

# Secret disguised by hex encoding
signing_key = "4f3c2b1a9e8d7c6b5a4938271605f4e3d2c1b0a"
```

#### Generic secret findings

When a generic secret is found, GitLab labels the finding in the vulnerability report based on the type of value it detected:

- `Generic Password`: A human-defined password, such as a database password or a service password.
- `Generic Secret`: A machine-generated credential, such as an API key or access token, that doesn't match a known vendor format.
- `Generic UUID Secret`, `Generic Base64-Encoded Secret`, `Generic Base64URL-Encoded Secret`, `Generic Hex-Encoded Secret`, `Generic JWT Token`, and `Generic Paseto Token`: Machine-generated credentials that GitLab further classified by their format.

Each finding includes a description that explains why the value was flagged. The description provides
guidance on how to confirm whether the value is a real secret, rotate a confirmed secret, or
dismiss a false positive.

#### Secrets generic detection might miss

Generic detection identifies a secret from its surroundings, such as a keyword or the format of the value,
not from confirming what the value does. This approach has trade-offs. Even with false positive reduction in
place, some non-secret values can show up as findings. For example:

- A secret built through concatenation or string interpolation, such as `full_key = prefix + secret_suffix`.
- A secret with no recognizable keyword nearby, such as a hardcoded value with no label like `key`, `secret`, `token`, or `password` next to it.
- A secret in a file or path that generic detection excludes, such as a vendored dependency, a generated file, or documentation.
- A value that's shorter than the minimum length generic detection expects for that type of secret.
- A secret reported at medium or low confidence. By default, GitLab Secret Scanning for Source Code shows only high-confidence findings in the vulnerability report. To change this, see [confidence level](gitlab_secret_scanner/_index.md#confidence-level).

## Supported rules for rule-based detection

This table lists the rules used for rule-based detection.
Both the Gitleaks-based analyzer and GitLab Secret Scanning for Source Code analyzers use the same ruleset,
but a validity check might run only on findings from one analyzer.

For each rule, the table shows:

- Pipeline secret detection, client-side secret detection, and secret push protection:
  Whether that type of secret detection supports the rule.
- Validity check: Whether GitLab can check if a secret detected by the rule is active.
- Validity check analyzer: Which analyzer findings GitLab checks for validity:
  - `Both`: Findings from both analyzers.
  - `GitLab Secret Scanning for Source Code`: Findings from GitLab Secret Scanning for Source Code only.
  - `None`: The rule has no validity check.

For more information, see [validity checks](../vulnerabilities/validity_check.md).

Secret detection rules are updated in the [default ruleset](https://gitlab.com/gitlab-org/security-products/secret-detection/secret-detection-rules/-/tree/main).
Detected secrets with patterns that have been removed or updated remain open so you can triage them.

If you want to add a new secret detection rule, you can [propose new detection rules](pipeline/configure.md#propose-new-detection-rules) for all GitLab users, or [customize rulesets](pipeline/configure.md#customize-analyzer-rulesets) for your specific project.

<!--
  The "Validity check" and "Validity check analyzer" columns are generated.
  Do not edit them by hand. To update them, run:
    bundle exec rake gitlab:secret_detection:validity_docs:compile
  Add new rule rows by hand. The task fills in the last two columns of each row.
-->
<!-- markdownlint-disable MD044 -->
<!-- vale gitlab_base.Spelling = NO -->
<!-- vale gitlab_base.SentenceSpacing = NO -->

| Description                                   | ID                                            | Pipeline secret detection | Client-side secret detection | Secret push protection | Validity check | Validity check analyzer                |
|:----------------------------------------------|:----------------------------------------------|:--------------------------|:-----------------------------|:-----------------------|:---------------|:---------------------------------------|
| Adafruit IO Key                                   | AdafruitIOKey                                 | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< yes >}} | GitLab Secret Scanning for Source Code |
| Adobe Client ID (OAuth Web)                       | Adobe Client ID (Oauth Web)                   | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| Adobe client secret                               | Adobe Client Secret                           | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| Adobe IMS Access Token                            | AdobeIMSAccessToken                           | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| Age secret key                                    | Age secret key                                | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| Aiven Service Password                            | AivenServicePassword                          | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| Alibaba AccessKey ID                              | Alibaba AccessKey ID                          | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| Alibaba Secret Key                                | Alibaba Secret Key                            | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| Amazon OAuth Client ID                            | AmazonOAuthClientID                           | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| Anthropic API key                                 | anthropic_key                                 | {{< yes >}} | {{< yes >}} | {{< yes >}} | {{< yes >}} | GitLab Secret Scanning for Source Code |
| Artifactory API Key                               | ArtifactoryApiKey                             | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| Artifactory Identity Token                        | ArtifactoryIdentityToken                      | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| Asana client ID                                   | Asana Client ID                               | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| Asana client secret                               | Asana Client Secret                           | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| Asana Personal Access Token V1                    | AsanaPersonalAccessTokenV1                    | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< yes >}} | GitLab Secret Scanning for Source Code |
| Asana Personal Access Token V2                    | AsanaPersonalAccessTokenV2                    | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< yes >}} | GitLab Secret Scanning for Source Code |
| Atlassian admin API key / Bitbucket repository access token | AtlassianApiKey                               | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| Atlassian API token                               | Atlassian API token                           | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| Atlassian user API token                          | AtlassianUserApiToken                         | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| Auth0 Application Client Secret                   | Auth0ApplicationClientSecret                  | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| AWS Access Key ID                                 | AWS                                           | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< yes >}} | Both |
| AWS Secret Access Key                             | AWSSecretAccessKey                            | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| AWS Session Token                                 | AWSSessionToken                               | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| AWS Cognito Identity Pool ID                      | AWSCognitoIdentityPoolID                      | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| AWS Bedrock Key                                   | AWSBedrockKey                                 | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| AWS Bedrock Short Lived Key                       | AWSBedrockShortLivedKey                       | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| Azure API Management Gateway Key                  | AzureAPIManagementGatewayKey                  | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| Azure API Management Direct Key                   | AzureAPIManagementDirectKey                   | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| Azure App Config Connection String                | AzureAppConfigConnectionString                | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| Azure Communication Services Connection String    | AzureCommServicesConnectionString             | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| Azure Cosmos DB Credentials                       | AzureCosmosDBCredentials                      | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| Azure Entra Client Secret                         | AzureEntraClientSecret                        | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| Azure Entra ID Token                              | AzureEntraIDToken                             | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| Azure EventGrid Access Key                        | AzureEventGridAccessKey                       | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| Azure EventGrid Access via Shared Access Signature | AzureEventGridSAS                             | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| Azure Functions API Key (header)                  | AzureFunctionsAPIKeyViaHeader                 | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| Azure Functions API Key (URL)                     | AzureFunctionsAPIKeyViaURL                    | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| Azure Logic App Shared Access Signature           | AzureLogicAppSAS                              | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| Azure OpenAI API key                              | AzureOpenAIAPIKey                             | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| Azure Personal Access Token                       | AzurePersonalAccessToken                      | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| Azure SignalR Access Key                          | AzureSignalRAccessKey                         | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| Beamer API token                                  | Beamer API token                              | {{< yes >}} | {{< no >}} | {{< no >}} | {{< yes >}} | GitLab Secret Scanning for Source Code |
| Bitbucket client ID                               | Bitbucket client ID                           | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| Bitbucket client secret                           | Bitbucket client secret                       | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| Brevo API token                                   | Sendinblue API token                          | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< yes >}} | GitLab Secret Scanning for Source Code |
| Brevo SMTP token                                  | Sendinblue SMTP token                         | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| Canada Digital Service Notify API Key             | CDSCanadaNotifyAPIKey                         | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< yes >}} | GitLab Secret Scanning for Source Code |
| CircleCI access token                             | CircleCI access tokens                        | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| Clojars deploy token                              | Clojars API token                             | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| Contentful delivery API token                     | Contentful delivery API token                 | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| Contentful personal access token                  | ContentfulPersonalAccessToken                 | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< yes >}} | GitLab Secret Scanning for Source Code |
| Contentful preview API token                      | Contentful preview API token                  | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| Databricks API token                              | Databricks API token                          | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| DataDog API Key                                   | DataDogAPIKey                                 | {{< yes >}} | {{< no >}} | {{< no >}} | {{< yes >}} | GitLab Secret Scanning for Source Code |
| DigitalOcean OAuth access token                   | digitalocean-access-token                     | {{< yes >}} | {{< no >}} | {{< no >}} | {{< yes >}} | GitLab Secret Scanning for Source Code |
| DigitalOcean personal access token                | digitalocean-pat                              | {{< yes >}} | {{< no >}} | {{< no >}} | {{< yes >}} | GitLab Secret Scanning for Source Code |
| DigitalOcean refresh token                        | digitalocean-refresh-token                    | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| Discord API key                                   | Discord API key                               | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| Discord client ID                                 | Discord client ID                             | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| Discord client secret                             | Discord client secret                         | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| Docker Personal Access Token                      | DockerPersonalAccessToken                     | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| Doppler API token                                 | Doppler API token                             | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< yes >}} | GitLab Secret Scanning for Source Code |
| Doppler Service token                             | Doppler Service token                         | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< yes >}} | GitLab Secret Scanning for Source Code |
| Dropbox API secret/key                            | Dropbox API secret/key                        | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| Dropbox application access token                  | DropboxAppAccessToken                         | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< yes >}} | GitLab Secret Scanning for Source Code |
| Dropbox long lived API token                      | Dropbox long lived API token                  | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| Dropbox short lived API token                     | Dropbox short lived API token                 | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< yes >}} | GitLab Secret Scanning for Source Code |
| Duffel API token                                  | Duffel API token                              | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| Dynatrace platform token / OAuth client secret    | DynatracePlatformToken                        | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| EasyPost production API key                       | EasyPost API token                            | {{< yes >}} | {{< no >}} | {{< no >}} | {{< yes >}} | GitLab Secret Scanning for Source Code |
| EasyPost test API key                             | EasyPost test API token                       | {{< yes >}} | {{< no >}} | {{< no >}} | {{< yes >}} | GitLab Secret Scanning for Source Code |
| Facebook token                                    | Facebook token                                | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| Fastly API user or automation token               | Fastly API token                              | {{< yes >}} | {{< no >}} | {{< no >}} | {{< yes >}} | GitLab Secret Scanning for Source Code |
| Figma Personal Access Token                       | FigmaPersonalAccessToken                      | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| Finicity API token                                | Finicity API token                            | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| Finicity client secret                            | Finicity client secret                        | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| Flutterwave production encrypted key              | FlutterwaveProdEncryptedKey                   | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| Flutterwave test encrypted key                    | Flutterwave encrypted key                     | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| Flutterwave production public key                 | FlutterwaveProdPublicKey                      | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| Flutterwave test public key                       | Flutterwave public key                        | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| Flutterwave production secret key                 | FlutterwaveProdSecretKey                      | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< yes >}} | GitLab Secret Scanning for Source Code |
| Flutterwave test secret key                       | Flutterwave secret key                        | {{< yes >}} | {{< no >}} | {{< no >}} | {{< yes >}} | GitLab Secret Scanning for Source Code |
| Frame.io API token                                | Frame.io API token                            | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| GCP API key or Google API key                     | GCP API key                                   | {{< yes >}} | {{< no >}} | {{< no >}} | {{< yes >}} | Both |
| GCP OAuth client secret                           | GCP OAuth client secret                       | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| Google (GCP) service account                      | Google (GCP) Service-account                  | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| GCP Vertex Express Mode Key                       | GCPVertexExpressModeKey                       | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| GitHub app token                                  | Github App Token                              | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| GitHub App Installation Token                     | GithubAppInstallationToken                    | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< yes >}} | GitLab Secret Scanning for Source Code |
| GitHub fine-grained personal access token         | GithubFineGrainedPersonalAccessToken          | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< yes >}} | GitLab Secret Scanning for Source Code |
| GitHub OAuth Access Token                         | Github OAuth Access Token                     | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< yes >}} | GitLab Secret Scanning for Source Code |
| GitHub personal access token (classic)            | Github Personal Access Token                  | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< yes >}} | GitLab Secret Scanning for Source Code |
| GitHub refresh token                              | Github Refresh Token                          | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| GitLab CI/CD job token                            | gitlab_ci_build_token                         | {{< yes >}} | {{< yes >}} | {{< no >}} | {{< yes >}} | Both |
| GitLab CI/CD job token (JWT)                      | gitlab_ci_build_token_jwt                     | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| GitLab deploy token                               | gitlab_deploy_token                           | {{< yes >}} | {{< yes >}} | {{< yes >}} | {{< yes >}} | Both |
| GitLab deploy token (routable)                    | gitlab_deploy_token_routable                  | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| GitLab deploy token in a Git URL                  | gitlab_deploy_token_in_url                    | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| GitLab feature flags client token                 | gitlab_feature_flags_client_token             | {{< yes >}} | {{< yes >}} | {{< yes >}} | {{< no >}} | None |
| GitLab feed token                                 | gitlab_feed_token                             | {{< yes >}} | {{< yes >}} | {{< no >}} | {{< no >}} | None |
| GitLab feed token v2                              | gitlab_feed_token_v2                          | {{< yes >}} | {{< yes >}} | {{< yes >}} | {{< yes >}} | Both |
| GitLab IAM OAuth access token                     | gitlab_iam_access_token                       | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| GitLab IAM OAuth authorization code               | gitlab_iam_authorization_code                 | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| GitLab IAM OAuth refresh token                    | gitlab_iam_refresh_token                      | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| GitLab incoming email token                       | gitlab_incoming_email_token                   | {{< yes >}} | {{< yes >}} | {{< yes >}} | {{< yes >}} | Both |
| GitLab Kubernetes agent token                     | gitlab_kubernetes_agent_token                 | {{< yes >}} | {{< yes >}} | {{< yes >}} | {{< yes >}} | Both |
| GitLab Kubernetes agent token (routable)          | gitlab_kubernetes_agent_token_routable        | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| GitLab OAuth application secret                   | gitlab_oauth_app_secret                       | {{< yes >}} | {{< yes >}} | {{< yes >}} | {{< yes >}} | Both |
| GitLab path-dependent feed token                  | gitlab_feed_token_path_dependent              | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| GitLab personal access token                      | gitlab_personal_access_token                  | {{< yes >}} | {{< yes >}} | {{< yes >}} | {{< yes >}} | Both |
| GitLab personal access token (routable)           | gitlab_personal_access_token_routable         | {{< yes >}} | {{< yes >}} | {{< yes >}} | {{< yes >}} | Both |
| GitLab personal access token (routable, versioned) | gitlab_personal_access_token_routable_versioned | {{< yes >}} | {{< yes >}} | {{< yes >}} | {{< yes >}} | Both |
| GitLab pipeline trigger token                     | gitlab_pipeline_trigger_token                 | {{< yes >}} | {{< yes >}} | {{< yes >}} | {{< yes >}} | Both |
| GitLab pipeline trigger token in a trigger URL    | gitlab_pipeline_trigger_token_in_url          | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| GitLab runner authentication token                | gitlab_runner_auth_token                      | {{< yes >}} | {{< yes >}} | {{< yes >}} | {{< yes >}} | Both |
| GitLab runner authentication token (routable)     | gitlab_runner_auth_token_routable             | {{< yes >}} | {{< yes >}} | {{< yes >}} | {{< yes >}} | Both |
| GitLab runner controller token                    | gitlab_runner_controller_token                | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| GitLab runner registration token                  | gitlab_runner_registration_token              | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| GitLab SCIM OAuth token                           | gitlab_scim_oauth_token                       | {{< yes >}} | {{< yes >}} | {{< no >}} | {{< yes >}} | Both |
| GitLab session cookie                             | gitlab_session_cookie                         | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| GitLab stateless access token                     | gitlab_stateless_access_token                 | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| GitLab workspace token                            | gitlab_workspace_token                        | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| GoCardless API token                              | GoCardless API token                          | {{< yes >}} | {{< no >}} | {{< no >}} | {{< yes >}} | GitLab Secret Scanning for Source Code |
| Grafana service account token                     | GrafanaServiceAccountToken                    | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| Grafana cloud access policy token                 | GrafanaCloudAccessPolicyToken                 | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< yes >}} | GitLab Secret Scanning for Source Code |
| HashiCorp Terraform API token                     | Hashicorp Terraform user/org API token        | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< yes >}} | GitLab Secret Scanning for Source Code |
| HashiCorp Vault batch token                       | Hashicorp Vault batch token                   | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| HashiCorp Vault Service Token                     | HashicorpVaultServiceToken                    | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| Heroku API key or application authorization token | Heroku API Key                                | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< yes >}} | GitLab Secret Scanning for Source Code |
| Highnote Live Secret Key                          | HighnoteLiveSecretKey                         | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< yes >}} | GitLab Secret Scanning for Source Code |
| Highnote Test Secret Key                          | HighnoteTestSecretKey                         | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< yes >}} | GitLab Secret Scanning for Source Code |
| HubSpot private app API token                     | Hubspot API token                             | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< yes >}} | GitLab Secret Scanning for Source Code |
| Hugging Face User Access Token                    | HuggingFaceUserAccessToken                    | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< yes >}} | GitLab Secret Scanning for Source Code |
| Instagram access token                            | Instagram access token                        | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| Intercom API Token                                | Intercom API token                            | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< yes >}} | GitLab Secret Scanning for Source Code |
| Intercom client secret or client ID               | Intercom client secret/ID                     | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| Ionic personal access token                       | Ionic API token                               | {{< yes >}} | {{< no >}} | {{< no >}} | {{< yes >}} | GitLab Secret Scanning for Source Code |
| JFrog Platform Access Tokens                      | JfrogPlatformAccessToken                      | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| Kubernetes Service Account Token                  | KubernetesServiceAccToken                     | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| LangChain API Key                                 | LangChainAPIKey                               | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< yes >}} | GitLab Secret Scanning for Source Code |
| Linear API token                                  | Linear API token                              | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< yes >}} | GitLab Secret Scanning for Source Code |
| Linear client secret or ID (OAuth 2.0)            | Linear client secret/ID                       | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| LinkedIn client ID                                | Linkedin Client ID                            | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| LinkedIn client secret                            | Linkedin Client secret                        | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| Lob API key                                       | Lob API Key                                   | {{< yes >}} | {{< no >}} | {{< no >}} | {{< yes >}} | GitLab Secret Scanning for Source Code |
| Lob publishable API key                           | Lob Publishable API Key                       | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| Mailchimp API key                                 | Mailchimp API key                             | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| Mailgun private API token                         | Mailgun private API token                     | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< yes >}} | GitLab Secret Scanning for Source Code |
| Mailgun public verification key                   | Mailgun public validation key                 | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| Mailgun webhook signing key                       | Mailgun webhook signing key                   | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| Mapbox API token                                  | Mapbox API token                              | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| Mapbox secret API token                           | MapboxSecretApiToken                          | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| MaxMind License Key                               | MaxMind License Key                           | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| MessageBird access key                            | messagebird-api-token                         | {{< yes >}} | {{< no >}} | {{< no >}} | {{< yes >}} | GitLab Secret Scanning for Source Code |
| MessageBird API client ID                         | MessageBird API client ID                     | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| Meta access token                                 | Meta access token                             | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| New Relic ingest browser API token                | New Relic ingest browser API token            | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| New Relic ingest browser API token v2             | New Relic ingest browser API token v2         | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| New Relic REST API key                            | New Relic REST API Key                        | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| New Relic user API ID                             | New Relic user API ID                         | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| New Relic user API key                            | New Relic user API Key                        | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< yes >}} | GitLab Secret Scanning for Source Code |
| npm access token                                  | npm access token                              | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< yes >}} | GitLab Secret Scanning for Source Code |
| Oculus access token                               | Oculus access token                           | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| Okta API Token                                    | OktaAPIToken                                  | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| Okta API Token (SSWS header)                      | OktaAPITokenHeader                            | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| Okta Client Secret                                | OktaClientSecret                              | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| Onfido Live API Token                             | Onfido Live API Token                         | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< yes >}} | GitLab Secret Scanning for Source Code |
| OpenAI API key                                    | open ai token                                 | {{< yes >}} | {{< no >}} | {{< no >}} | {{< yes >}} | GitLab Secret Scanning for Source Code |
| OpenAI project key                                | OpenAiProjectKey                              | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< yes >}} | GitLab Secret Scanning for Source Code |
| OpenAI service account key                        | OpenAiServiceAccountKey                       | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< yes >}} | GitLab Secret Scanning for Source Code |
| OpenAI admin key                                  | OpenAiServiceAdminKey                         | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< yes >}} | GitLab Secret Scanning for Source Code |
| Password in URL                                   | Password in URL                               | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| PGP private key                                   | PGP private key                               | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| PKCS8 private key                                 | PKCS8 private key                             | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| PlanetScale API token                             | Planetscale API token                         | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| PlanetScale App secret                            | PlanetscaleAppSecret                          | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| PlanetScale OAuth secret                          | PlanetscaleOAuthSecret                        | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| PlanetScale password                              | Planetscale password                          | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| PostHog Personal API key                          | PostHogPersonalAPIkey                         | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< yes >}} | GitLab Secret Scanning for Source Code |
| PostHog Project API key                           | PostHogProjectAPIkey                          | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| Postman API token                                 | Postman API token                             | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< yes >}} | Both |
| Postman collection access key                     | PostmanCollectionAccessKey                    | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| Pulumi API token                                  | Pulumi API token                              | {{< yes >}} | {{< no >}} | {{< no >}} | {{< yes >}} | GitLab Secret Scanning for Source Code |
| PyPi upload token                                 | PyPI upload token                             | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| RSA private key                                   | RSA private key                               | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| RubyGems API token                                | Rubygem API token                             | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< yes >}} | GitLab Secret Scanning for Source Code |
| Segment public API token                          | Segment Public API token                      | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< yes >}} | GitLab Secret Scanning for Source Code |
| SendGrid API token                                | Sendgrid API token                            | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< yes >}} | GitLab Secret Scanning for Source Code |
| Shippo API token                                  | Shippo API token                              | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< yes >}} | GitLab Secret Scanning for Source Code |
| Shippo Test API token                             | Shippo Test API token                         | {{< yes >}} | {{< no >}} | {{< no >}} | {{< yes >}} | GitLab Secret Scanning for Source Code |
| Shopify Partner API token                         | ShopifyPartnerAPIToken                        | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| Shopify personal access token                     | Shopify access token                          | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| Shopify private app access token                  | Shopify private app access token              | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| Shopify custom app access token                   | Shopify custom app access token               | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| Shopify shared secret                             | Shopify shared secret                         | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| Slack app configuration token                     | SlackAppConfigurationToken                    | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| Slack app configuration refresh token             | SlackAppConfigurationRefreshToken             | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| Slack app level token                             | SlackAppLevelToken                            | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| Slack bot user OAuth token                        | Slack token                                   | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| Slack webhook                                     | Slack Webhook                                 | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| SonarQube Global Analysis Token                   | SonarQubeGlobalAnalysisToken                  | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| SonarQube Project Analysis Token                  | SonarQubeProjectAnalysisToken                 | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| SonarQube User Token                              | SonarQubeUserToken                            | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| Splunk Authentication Token                       | SplunkAuthToken                               | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| Splunk HEC Token                                  | SplunkHECToken                                | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| SSH (DSA) private key                             | SSH (DSA) private key                         | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| SSH (EC) private key                              | SSH (EC) private key                          | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| SSH private key                                   | SSH private key                               | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| Stripe live restricted key                        | StripeLiveRestrictedKey                       | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< yes >}} | GitLab Secret Scanning for Source Code |
| Stripe live secret key                            | StripeLiveSecretKey                           | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< yes >}} | GitLab Secret Scanning for Source Code |
| Stripe Live Short Secret Key                      | StripeLiveShortSecretKey                      | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< yes >}} | GitLab Secret Scanning for Source Code |
| Stripe publishable live key                       | StripeLivePublishableKey                      | {{< yes >}} | {{< no >}} | {{< no >}} | {{< yes >}} | GitLab Secret Scanning for Source Code |
| Stripe publishable test key                       | StripeTestPublishableKey                      | {{< yes >}} | {{< no >}} | {{< no >}} | {{< yes >}} | GitLab Secret Scanning for Source Code |
| Stripe restricted test key                        | StripeTestRestrictedKey                       | {{< yes >}} | {{< no >}} | {{< no >}} | {{< yes >}} | GitLab Secret Scanning for Source Code |
| Stripe secret test key                            | StripeTestSecretKey                           | {{< yes >}} | {{< no >}} | {{< no >}} | {{< yes >}} | GitLab Secret Scanning for Source Code |
| Stripe Test Short Secret Key                      | StripeTestShortSecretKey                      | {{< yes >}} | {{< no >}} | {{< no >}} | {{< yes >}} | GitLab Secret Scanning for Source Code |
| Tailscale OAuth client secret                     | TailscaleOauthClientSecret                    | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| Tailscale API access token                        | TailscaleApiAccessToken                       | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< yes >}} | GitLab Secret Scanning for Source Code |
| Tailscale personal authentication key             | TailscalePersonalAuthKey                      | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| Tencent Cloud Secret ID                           | TencentCloudSecretID                          | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| Twilio Account SID                                | Twilio Account SID                            | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| Twilio API key                                    | Twilio API Key                                | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| Twitch OAuth client secret                        | Twitch API token                              | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| Typeform personal access token                    | Typeform API token                            | {{< yes >}} | {{< no >}} | {{< no >}} | {{< yes >}} | GitLab Secret Scanning for Source Code |
| Volcengine Access Key ID                          | VolcengineAccessKeyID                         | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| WakaTime API Key                                  | WakaTimeAPIKey                                | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| X token                                           | Twitter token                                 | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| Yandex.Cloud AWS API compatible access secret     | Yandex.Cloud AWS API compatible Access Secret | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| Yandex.Cloud API Key                              | Yandex.Cloud API Key                          | {{< yes >}} | {{< no >}} | {{< yes >}} | {{< no >}} | None |
| Yandex.Cloud IAM cookie v1-1                      | Yandex.Cloud IAM Cookie v1 - 1                | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |
| Yandex.Cloud IAM cookie v1-2                      | Yandex.Cloud IAM Cookie v1 - 2                | {{< yes >}} | {{< no >}} | {{< no >}} | {{< no >}} | None |

<!-- vale gitlab_base.SentenceSpacing = YES -->
<!-- vale gitlab_base.Spelling = YES -->
<!-- markdownlint-enable MD044 -->
