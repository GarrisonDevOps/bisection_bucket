---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: Manage access control and security for files uploaded to issues, merge requests, and epics.
title: User file uploads
---

{{< details >}}

- Tier: Free, Premium, Ultimate
- Offering: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Users can upload files to:

- Issues or merge requests in a project.
- Epics in a group.

GitLab generates direct URLs for these uploaded files with a random 32-character ID to prevent unauthorized users from guessing the URLs. This randomization offers some security for files containing sensitive information.

Files uploaded by users to GitLab issues, merge requests, and epics contain `/uploads/<32-character-id>` in the URL path.

> [!warning]
> Exercise caution in downloading files uploaded by unknown or untrusted sources, especially if the file is an executable or script.

## Access control for uploaded files

Access to an uploaded file through its direct URL depends on where the file was uploaded and the file type.
Media files are images, videos, and audio files that GitLab can display inline, like PNG, MP4, and MP3 files.
SVG files are not media files.

| Uploaded to | Media files | Other files, like PDFs |
|-------------|-------------|------------------------|
| Public project | Anyone with the URL | Anyone with the URL |
| Private or internal project, with [authorization checks for media files](#turn-off-authorization-checks-for-media-files) turned on (default) | Users who can view the project | Users who can view the project |
| Private or internal project, with authorization checks for media files turned off | Anyone with the URL | Users who can view the project |
| Group, including a private group | Anyone with the URL | Users who can view the group |

Access does not depend on the issue, merge request, or epic the file is attached to.
For example, in a public project, anyone with the URL can access a file attached to a confidential issue.

Authentication checks for images can cause display issues in the body of notification emails.
Emails are frequently read from clients (such as Outlook, Apple Mail, or your mobile device)
not authenticated with GitLab. Images in emails appear broken and unavailable if
the client is not authenticated with GitLab.

Direct attachment URLs do not accept access tokens.
To download an uploaded file with an access token, use the REST API for
[projects](../api/project_markdown_uploads.md#download-a-file-linked-from-a-description-or-comment) or
[groups](../api/group_markdown_uploads.md#download-a-file-linked-from-a-description-or-comment).

## Turn off authorization checks for media files

In private and internal projects, authorization checks for media files are turned on by default.
When this setting is turned off, anyone with the URL can view media files uploaded to the project.

Prerequisites:

- You must have the Maintainer or Owner role for the project.
- Your project visibility settings must be **Private** or **Internal**.

To turn off authorization checks for media files:

1. In the top bar, select **Search or go to** and find your project.
1. In the left sidebar, select **Settings** > **General**.
1. Expand **Visibility, project features, permissions**.
1. Scroll to **Project visibility** and clear the **Require authentication to view media files** checkbox.

## Delete uploaded files

{{< history >}}

- REST API [added](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/157066) support in GitLab 17.2.

{{< /history >}}

You should delete an uploaded file when that file contains sensitive or confidential information. When you have deleted that file, users cannot access the file and the direct URL returns a 404 error.

Project Owners and Maintainers can use the [interactive GraphQL explorer](../api/graphql/_index.md#interactive-graphql-explorer) to access a [GraphQL endpoint](../api/graphql/reference/mutations.md#uploaddelete) and delete an uploaded file.

For example:

```graphql
mutation{
  uploadDelete(input: { projectPath: "<path/to/project>", secret: "<32-character-id>", filename: "<filename>" }) {
    upload {
      id
      size
      path
    }
    errors
  }
}
```

Project members that do not have the Maintainer or Owner role cannot access this GraphQL endpoint.

You can also use the REST API for [projects](../api/project_markdown_uploads.md#delete-an-uploaded-file-by-secret-and-filename) or [groups](../api/group_markdown_uploads.md#delete-an-uploaded-file-by-secret-and-filename) to delete an uploaded file.
