# Geo Developer Console

This console is not user-facing. It is a place for Geo engineers and
Support engineers to store snippets with little overhead, to save time and reduce copy-paste errors
in Rails console. Remember, entering commands in Rails console is considered
[unacceptably complex](https://gitlab.com/gitlab-com/content-sites/handbook/-/merge_requests/4412)
for customer-use. Any functionality provided by this console should be treated as **unsafe** as a
bare snippet.

- Do not add features intended for use by customers. Instead, consider adding a UI feature, an API
  endpoint, or a Rake task.
- Do not expose this console to customers for example via a Rake task. First, sufficient test
  coverage must be added, and its functionality must be validated in a production or production-like
  environment.

## Quick start

If you are not deeply familiar with the code and its safety, then DO NOT RUN IT on a production
environment.

1. Open the Geo Console Main Menu.

   ```ruby
   Geo::Console::MainMenu.new.open
   ```

## Example usage

```plaintext
[35] pry(main)> Geo::Console::MainMenu.new.open

--------------------------------------------------------------------------------
Geo Developer Console | Geo Secondary Site | gdk2
Main menu
--------------------------------------------------------------------------------

1) Troubleshoot replication or verification
2) Show cached Geo status
3) Show uncached Geo status (Slow. Will run all the queries)
4) Exit Geo console

What would you like to do?
Enter a number: 2
You entered: 2
You chose: Show cached Geo status

--------------------------------------------------------------------------------
Geo Developer Console | Geo Secondary Site | gdk2
Show cached Geo status
--------------------------------------------------------------------------------


Name: gdk2
URL: https://gdk2.test:3444
-----------------------------------------------------
                   GitLab Version: 17.4.0-pre
                         Geo Role: Secondary
                    Health Status: Healthy
                      Lfs Objects: succeeded 9 / total 9 (100%)
              Merge Request Diffs: succeeded 0 / total 0 (0%)
                    Package Files: succeeded 25 / total 25 (100%)
         Terraform State Versions: succeeded 18 / total 18 (100%)
             Snippet Repositories: succeeded 20 / total 20 (100%)
          Group Wiki Repositories: succeeded 0 / total 0 (0%)
               Pipeline Artifacts: succeeded 0 / total 0 (0%)
                Pages Deployments: succeeded 0 / total 0 (0%)
                          Uploads: succeeded 53 / total 53 (100%)
                    Job Artifacts: succeeded 100 / total 100 (100%)
                  Ci Secure Files: succeeded 0 / total 0 (0%)
           Dependency Proxy Blobs: succeeded 0 / total 0 (0%)
       Dependency Proxy Manifests: succeeded 0 / total 0 (0%)
        Project Wiki Repositories: succeeded 18 / total 18 (100%)
   Design Management Repositories: succeeded 0 / total 0 (0%)
             Project Repositories: succeeded 18 / total 18 (100%)
             Lfs Objects Verified: succeeded 9 / total 9 (100%)
     Merge Request Diffs Verified: succeeded 0 / total 0 (0%)
           Package Files Verified: succeeded 25 / total 25 (100%)
Terraform State Versions Verified: succeeded 18 / total 18 (100%)
    Snippet Repositories Verified: succeeded 20 / total 20 (100%)
 Group Wiki Repositories Verified: succeeded 0 / total 0 (0%)
      Pipeline Artifacts Verified: succeeded 0 / total 0 (0%)
       Pages Deployments Verified: succeeded 0 / total 0 (0%)
                 Uploads Verified: succeeded 53 / total 53 (100%)
           Job Artifacts Verified: succeeded 100 / total 100 (100%)
         Ci Secure Files Verified: succeeded 0 / total 0 (0%)
  Dependency Proxy Blobs Verified: succeeded 0 / total 0 (0%)
Dependency Proxy Manifests Verified: succeeded 0 / total 0 (0%)
Project Wiki Repositories Verified: succeeded 18 / total 18 (100%)
Design Management Repositories Verified: succeeded 0 / total 0 (0%)
    Project Repositories Verified: succeeded 18 / total 18 (100%)
                    Sync Settings: Full
         Database replication lag: 0 seconds
  Last event ID seen from primary: 262 (about 3 hours ago)
          Last event ID processed: 262 (about 3 hours ago)
           Last status report was: 2 minutes ago

1) Show cached Geo status
2) Back to Main menu

What would you like to do?
Enter a number: 2
You entered: 2
You chose: Main menu

--------------------------------------------------------------------------------
Geo Developer Console | Geo Secondary Site | gdk2
Main menu
--------------------------------------------------------------------------------

1) Troubleshoot replication or verification
2) Show cached Geo status
3) Show uncached Geo status (Slow. Will run all the queries)
4) Exit Geo console

What would you like to do?
Enter a number: 1
You entered: 1
You chose: Troubleshoot replication or verification

--------------------------------------------------------------------------------
Geo Developer Console | Geo Secondary Site | gdk2
Troubleshoot replication or verification
--------------------------------------------------------------------------------

1) Troubleshoot replication or verification for Lfs Object
2) Troubleshoot replication or verification for Merge Request Diff
3) Troubleshoot replication or verification for Package File
4) Troubleshoot replication or verification for Terraform State Version
5) Troubleshoot replication or verification for Snippet Repository
6) Troubleshoot replication or verification for Group Wiki Repository
7) Troubleshoot replication or verification for Pipeline Artifact
8) Troubleshoot replication or verification for Pages Deployment
9) Troubleshoot replication or verification for Upload
10) Troubleshoot replication or verification for Job Artifact
11) Troubleshoot replication or verification for Ci Secure File
12) Troubleshoot replication or verification for Dependency Proxy Blob
13) Troubleshoot replication or verification for Dependency Proxy Manifest
14) Troubleshoot replication or verification for Project Wiki Repository
15) Troubleshoot replication or verification for Design Management Repository
16) Troubleshoot replication or verification for Project Repository
17) Show cached Geo status
18) Show uncached Geo status (Slow. Will run all the queries)
19) Back to Main menu

What would you like to do?
Enter a number: 10
You entered: 10
You chose: Troubleshoot replication or verification for Job Artifact

--------------------------------------------------------------------------------
Geo Developer Console | Geo Secondary Site | gdk2
Troubleshoot replication or verification for Job Artifact
--------------------------------------------------------------------------------

1) Show top 10 sync failures for Job Artifact
2) Show top 10 verification failures for Job Artifact
3) Back to Troubleshoot replication or verification

What would you like to do?
Enter a number: 1
You entered: 1
You chose: Show top 10 sync failures for Job Artifact

--------------------------------------------------------------------------------
Geo Developer Console | Geo Secondary Site | gdk2
Show top 10 sync failures for Job Artifact
--------------------------------------------------------------------------------

Total failed to sync: 0

{}

1) Show top 10 sync failures for Job Artifact
2) Back to Troubleshoot replication or verification for Job Artifact

What would you like to do?
Enter a number: 2
You entered: 2
You chose: Troubleshoot replication or verification for Job Artifact

--------------------------------------------------------------------------------
Geo Developer Console | Geo Secondary Site | gdk2
Troubleshoot replication or verification for Job Artifact
--------------------------------------------------------------------------------

1) Show top 10 sync failures for Job Artifact
2) Show top 10 verification failures for Job Artifact
3) Back to Troubleshoot replication or verification

What would you like to do?
Enter a number: 2
You entered: 2
You chose: Show top 10 verification failures for Job Artifact

--------------------------------------------------------------------------------
Geo Developer Console | Geo Secondary Site | gdk2
Show top 10 verification failures for Job Artifact
--------------------------------------------------------------------------------

Total failed to verify: 0

{}

1) Show top 10 verification failures for Job Artifact
2) Back to Troubleshoot replication or verification for Job Artifact

What would you like to do?
Enter a number: 2
You entered: 2
You chose: Troubleshoot replication or verification for Job Artifact

--------------------------------------------------------------------------------
Geo Developer Console | Geo Secondary Site | gdk2
Troubleshoot replication or verification for Job Artifact
--------------------------------------------------------------------------------

1) Show top 10 sync failures for Job Artifact
2) Show top 10 verification failures for Job Artifact
3) Back to Troubleshoot replication or verification

What would you like to do?
Enter a number: 3
You entered: 3
You chose: Troubleshoot replication or verification

--------------------------------------------------------------------------------
Geo Developer Console | Geo Secondary Site | gdk2
Troubleshoot replication or verification
--------------------------------------------------------------------------------

1) Troubleshoot replication or verification for Lfs Object
2) Troubleshoot replication or verification for Merge Request Diff
3) Troubleshoot replication or verification for Package File
4) Troubleshoot replication or verification for Terraform State Version
5) Troubleshoot replication or verification for Snippet Repository
6) Troubleshoot replication or verification for Group Wiki Repository
7) Troubleshoot replication or verification for Pipeline Artifact
8) Troubleshoot replication or verification for Pages Deployment
9) Troubleshoot replication or verification for Upload
10) Troubleshoot replication or verification for Job Artifact
11) Troubleshoot replication or verification for Ci Secure File
12) Troubleshoot replication or verification for Dependency Proxy Blob
13) Troubleshoot replication or verification for Dependency Proxy Manifest
14) Troubleshoot replication or verification for Project Wiki Repository
15) Troubleshoot replication or verification for Design Management Repository
16) Troubleshoot replication or verification for Project Repository
17) Show cached Geo status
18) Show uncached Geo status (Slow. Will run all the queries)
19) Back to Main menu

What would you like to do?
Enter a number: 19
You entered: 19
You chose: Main menu

--------------------------------------------------------------------------------
Geo Developer Console | Geo Secondary Site | gdk2
Main menu
--------------------------------------------------------------------------------

1) Troubleshoot replication or verification
2) Show cached Geo status
3) Show uncached Geo status (Slow. Will run all the queries)
4) Exit Geo console

What would you like to do?
Enter a number: 4
You entered: 4
You chose: Exit Geo console
=> nil
[36] pry(main)>
```