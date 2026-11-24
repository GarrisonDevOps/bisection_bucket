---
stage: none
group: unassigned
info: For assistance with this Style Guide page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments-to-other-projects-and-subjects>.
description: Rules for links, link text, videos, and click-through demos in GitLab documentation.
title: Links and videos
---

## Links

Links are an important way to help readers find what they need.

However, most content is found by searching, and you should avoid putting too many links on any page.
Too many links can hinder readability.

- Do not duplicate links on the same page. For example, on **Page A**, do not link to **Page B** multiple times.
- Do not use links in headings. Headings that contain links cause errors.
- Do not use a hard line wrap between any words in a link.
- Avoid multiple links in a single paragraph.
- Avoid multiple links in a single task.
- On any one page, try not to use more than 15 links to other pages.
- Consider the use of [Related topics](../topic_types/_index.md#related-topics) to reduce links that interrupt the flow of a task.
- Try to avoid anchor links to sections on the same page. Let users rely on the right navigation instead.

### Inline links

Use inline links instead of reference links. Inline links are easier to parse
and edit.
([Vale](../testing/vale.md) rule: [`ReferenceLinks.yml`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/doc/.vale/gitlab_docs/ReferenceLinks.yml))

- Do:

  ```markdown
  For more information, see [merge requests](path/to/merge_requests.md)
  ```

- Don't:

  ```markdown
  For more information, see [merge requests][1].

  [1]: path/to/merge_requests.md
  ```

### Links in the same repository

To link to another documentation (`.md`) file in the same repository:

- Use an inline link with a relative file path. For example, `[GitLab.com settings](../user/gitlab_com/_index.md)`.
- Put the entire link on a single line, even if the link is very long. ([Vale](../testing/vale.md) rule: [`MultiLineLinks.yml`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/doc/.vale/gitlab_base/MultiLineLinks.yml)).

> [!note]
> In the GitLab repository, do not link to the `/development` directory from any other directory.

To link to a file outside of the documentation files, for example to link from development
documentation to a specific code file:

- Use a full URL. For example: ``[`app/views/help/show.html.haml`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/app/views/help/show.html.haml)``
- Optional. Use a full URL with a specific ref. For example: ``[`app/views/help/show.html.haml`](https://gitlab.com/gitlab-org/gitlab/-/blob/6d01aa9f1cfcbdfa88edf9d003bd073f1a6fff1d/app/views/help/show.html.haml)``

### Links in separate repositories

To link to a page in a different repository, use a full URL.
For example, to link from a page in the GitLab repository to the Charts repository,
use a URL like `[GitLab Charts documentation](https://docs.gitlab.com/charts/)`.

### Anchor links

Each topic title has an anchor link. For example, a topic with the title
`## This is an example` has the anchor `#this-is-an-example`.

When you change topic title text, the anchor link changes. To avoid broken links:

- Do not use step numbers in topic titles.
- When possible, do not use words that might change in the future.

#### Changing links and titles

When you change a topic title, the anchor link changes. If other documentation pages
or code files link to this anchor, [pipeline jobs could fail](../testing/_index.md).

Consider [running the link checks locally](../testing/links.md) before pushing your changes
to prevent failing pipelines.

### Text for links

Follow these guidelines for link text.

For writing link text in the UI, see [Pajamas](https://design.gitlab.com/patterns/contextual-help#link-text).

#### Standard text

Use text that follows one of these patterns:

- `For more information, see [link text](link.md)`.
- `To [DO THIS THING], see [link text](link.md)`

For example:

- `For more information, see [merge requests](link.md).`
- `To create a review app, see [review apps](link.md).`

To expand on this text, use phrases like
`For more information about this feature, see...`

Do not use the following constructions:

- `Learn more about...`
- `To read more...`.
- `For more information, see the [Merge requests](link.md) page.`
- `For more information, see the [Merge requests](link.md) documentation.`

#### Descriptive text rather than `here`

Use descriptive text for links, rather than words like `here` or `this page.`
For the name of a topic or page, use lowercase.
You don't have to match the text to the topic or page name exactly.
Edit the text to be descriptive and fit the guidelines.

Do:

- `For more information, see [merge requests](link.md)`.
- `For more information, see [roles and permissions](link.md)`.
- `For more information, see [how to configure common settings](link.md)`.

Don't:

- `For more information, see [this page](link.md).`
- `For more information, go [here](link.md).`
- `For more information, see [this documentation](link.md).`

#### Links to issues

When linking to an issue, include the issue number in the link. For example:

- `For more information, see [issue 12345](link.md).`

Do not use the pound sign (`issue #12345`).

#### Links to APIs

When linking to API documentation, use lowercase. For example:

- `To import your GitHub repository, see the [import API](link.md).`

Do not capitalize the first letter to match the page title. For example, do not use:

- `To import your GitHub repository, see the [Import API](link.md).`

### Links to external documentation

When possible, avoid links to external documentation. These links can become outdated and are difficult to maintain.

- [They lead to link rot](https://en.wikipedia.org/wiki/Link_rot).
- [They create issues with maintenance](https://gitlab.com/gitlab-org/gitlab/-/issues/368300).

Sometimes links are required. They might clarify troubleshooting steps or help prevent duplication of content.
Sometimes they are more precise and will be maintained more actively.

For each external link you add, weigh the customer benefit with the maintenance difficulties.

### Links to handbook

Limit links to the handbook. Some links are unavoidable, like licensing terms, data usage and access policies,
testing agreements, and terms and conditions.

### Confidential or restricted access links

Don't link directly to:

- [Confidential issues](../../../user/project/issues/confidential_issues.md).
- Internal handbook pages.
- Project features that require [special permissions](../../../user/permissions.md)
  to view.

These links fail for:

- Those without sufficient permissions.
- Automated link checkers.

If you must use one of these links:

- If the link is to a confidential issue or internal handbook page, mention that the issue or page is visible only to GitLab team members.
- If the link requires a specific role or permissions, mention that information.
- Put the link in backticks so that it does not cause link checkers to fail.

Examples:

- ```markdown
  GitLab team members can view more information in this confidential issue:
  `https://gitlab.com/gitlab-org/gitlab/-/issues/<issue_number>`
  ```

- ```markdown
  GitLab team members can view more information in this internal handbook page:
  `https://internal.gitlab.com/handbook/<link>`
  ```

- ```markdown
  Users with the Maintainer role for the project can use the pipeline editor:
  `https://gitlab.com/gitlab-org/gitlab/-/ci/editor`
  ```

### Link to specific lines of code

When linking to specific lines in a file, link to a commit instead of to the
branch. Lines of code change over time. Linking to a line by using
the commit link ensures the user lands on the line you're referring to. The
**Permalink** dropdown item in the ellipsis menu, displayed when viewing a file in a project,
provides a link to the most recent commit of that file.

- Do: `[link to line 3](https://gitlab.com/gitlab-org/gitlab/-/blob/11f17c56d8b7f0b752562d78a4298a3a95b5ce66/.gitlab/issue_templates/Feature%20proposal.md#L3)`
- Don't: `[link to line 3](https://gitlab.com/gitlab-org/gitlab/-/blob/master/.gitlab/issue_templates/Feature%20proposal.md#L3).`

If that linked expression has changed line numbers due to additional
commits, you can still search the file for that query. In this case, update the
document to ensure it links to the most recent version of the file.

## Videos

Adding GitLab YouTube video tutorials to the documentation is highly
encouraged, unless the video is outdated. Videos should not replace
documentation, but complement or illustrate it. If content in a video is
fundamental to a feature and its key use cases, but isn't adequately
covered in the documentation, you should:

- Add this detail to the documentation text.
- Create an issue to review the video and update the page.

Do not upload videos to the product repositories. [Add a link](#link-to-video) or
[embed](#embed-videos) them instead.

### Link to video

To link to a video, include a YouTube icon so that readers can scan the page
for videos before reading. For the link text, follow the [general guidelines](#text-for-links).
Include the video's publication date after the link, to help identify
videos that might be out-of-date.

```markdown
<i class="fa-youtube-play" aria-hidden="true"></i>
For an overview, see [merge requests](https://link-to-video).
<!-- Video published on YYYY-MM-DD -->
```

You can link any up-to-date video that's useful to the GitLab user.

### Embed videos

The [GitLab documentation site](https://docs.gitlab.com) supports embedded
videos.

You can embed videos from [the official YouTube account for GitLab](https://www.youtube.com/channel/UCnMGQ8QHMAnVIsI3xJrihhg) only.
For videos from other sources, [link them](#link-to-video) instead.

In most cases, [link to a video](#link-to-video), because
embedded videos take up a lot of space on the page and can be distracting to readers.

To embed a video:

1. Copy the code from this procedure and paste it into your Markdown file. Leave a
   blank line above and below it. Do not edit the code (don't remove or add any spaces).
1. In YouTube, visit the video URL you want to display. Copy the regular URL
   from your browser (`https://www.youtube.com/watch?v=VIDEO-ID`) and replace
   the video title and link in the line under `<div class="video-fallback">`.
1. In YouTube, select **Share**, and then select **Embed**.
1. Copy the `<iframe>` source (`src`) **URL only**
   (`https://www.youtube-nocookie.com/embed/VIDEO-ID`),
   and paste it, replacing the content of the `src` field in the
   `iframe` tag.
1. Include the video's publication date below the link, to help identify
   videos that might be out-of-date.

```html
leave a blank line here
<div class="video-fallback">
  See the video: <a href="https://www.youtube.com/watch?v=MqL6BMOySIQ">Video title</a>.
</div>
<figure class="video-container">
  <iframe src="https://www.youtube-nocookie.com/embed/MqL6BMOySIQ" frameborder="0" allowfullscreen> </iframe>
</figure>
<!-- Video published on YYYY-MM-DD -->
leave a blank line here
```

This is how it renders on the GitLab documentation site:

<div class="video-fallback">
  See the video: <a href="https://www.youtube.com/watch?v=enMumwvLAug">What is GitLab</a>.
</div>
<figure class="video-container">
  <iframe src="https://www.youtube-nocookie.com/embed/MqL6BMOySIQ" frameborder="0" allowfullscreen> </iframe>
</figure>

With this formatting:

- The `figure` tag is required for semantic SEO and the `video-container`
  class is necessary to make sure the video is responsive and displays on
  different mobile devices.
- The `<div class="video-fallback">` is a fallback necessary for
  `/help`, because the GitLab Markdown processor doesn't support iframes. It's
  hidden on the documentation site, but is displayed by `/help`.
- The `www.youtube-nocookie.com` domain enables the [Privacy Enhanced Mode](https://support.google.com/youtube/answer/171780?hl=en#zippy=%2Cturn-on-privacy-enhanced-mode)
  of the YouTube embedded player. This mode allows users with restricted cookie preferences to view embedded videos.

## Link to click-through demos

Linking to click-through demos should follow similar guidelines to [videos](#videos).

```markdown
For a click-through demo, see [Demo Title](https://link-to-demo).
<!-- Demo published on YYYY-MM-DD -->
```
