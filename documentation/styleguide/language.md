---
stage: none
group: unassigned
info: For assistance with this Style Guide page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments-to-other-projects-and-subjects>.
description: Grammar, voice, capitalization, and word choice rules for GitLab documentation.
title: Language
---

GitLab documentation should be clear and easy to understand.

- Avoid unnecessary words.
- Be clear, concise, and stick to the goal of the topic.
- Write in US English with US grammar. (Tested in [`British.yml`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/doc/.vale/gitlab_base/British.yml).)

## Active voice

In most cases, text is easier to understand and to translate if you use active voice instead of passive.

For example, use:

- The developer writes code for the application.

Instead of:

- Application code is written by the developer.

Sometimes, `GitLab` as the subject can be awkward. For example, `GitLab exports the report`.
In this case, use passive voice instead. For example, `The report is exported`.

## Customer perspective

Focus on the functionality and benefits that GitLab brings to customers,
rather than what GitLab has created.

For example, use:

- Use merge requests to compare code in the source and target branches.

Instead of:

- GitLab allows you to compare code.
- GitLab created the ability to let you compare code.
- Merge requests let you compare code.

Words that indicate you are not writing from a customer perspective are
[allow and enable](word_list.md#allow-enable). Try instead to use
[you](word_list.md#you-your-yours) and to speak directly to the user.

## Building trust

Product documentation should be focused on providing clear, concise information,
without the addition of sales or marketing text.

- Do not use words like [easily](word_list.md#easily) or [simply](word_list.md#simply-simple).
- Do not use marketing phrases like "This feature will save you time and money."

Instead, focus on facts and achievable goals. Be specific. For example:

- The build time can decrease when you use this feature.
- Use this feature to save time when you create a project. The API creates the file and you
  do not have to manually intervene.

## Anthropomorphisms

Do not attribute human qualities such as perception, intent, or awareness to software,
systems, or data.

Describe what the system does mechanically, not what it experiences or intends.

Use:

- The field is removed before the response reaches the agent.
- A `reason:` is set on every error when the cause can be determined.
- The command prompts for confirmation before it displays the key.
- This setting configures the runner to deploy your website.
- The following commands require a directory of output files.
- The Planner Agent supports GitLab planning concepts, including work item hierarchies.
- The agent parses natural language inputs.
- The agent infers user intent from the provided context.

Instead of:

<!-- vale gitlab_base.Anthropomorphism = NO -->

- The field is removed before the agent sees the response.
- A `reason:` is set on every error when the tool knows why it failed.
- The command asks for confirmation before it displays the key.
- This setting tells the runner to deploy your website.
- The following commands assume that you have a directory of output files.
- The Planner Agent understands GitLab planning concepts, including work item hierarchies.
- The agent understands natural language.
- The agent understands what the user is trying to accomplish.

<!-- vale gitlab_base.Anthropomorphism = YES -->

When a system or component has a requirement, use "requires" or "must", not "needs".
A requirement is a fixed condition, such as a version, a setting, or a file location.
"Needs" describes something a person lacks or wants.

Use:

- The runner requires a registration token.
- The cache requires a directory to store its files in.
- The backup file must be owned by the `git` user.

Instead of:

<!-- vale gitlab_base.Anthropomorphism = NO -->

- The runner needs a registration token.
- The cache needs a directory to store its files in.
- The backup file needs to be owned by the `git` user.

<!-- vale gitlab_base.Anthropomorphism = YES -->

Tested in [`Anthropomorphism.yml`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/doc/.vale/gitlab_base/Anthropomorphism.yml).

## Self-referential writing

Avoid writing about the document itself. For example, do not use:

- This page shows...
- This guide explains...

These phrases slow the user down. Instead, get right to the point. For example, instead of:

- This page explains different types of pipelines.

Use:

- GitLab has different types of pipelines to help address your development needs.

Tested in [`SelfReferential.yml`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/doc/.vale/gitlab_base/SelfReferential.yml).

## Capitalization

As a company, we tend toward lowercase.

### Topic titles

Use sentence case for topic titles. For example:

- `# Use variables to configure pipelines`
- `## Use the To-Do List`

### Feature names

Feature names should be lowercase.

However, in a few rare cases, features can be title case. These exceptions are:

- Added as a proper name to [markdownlint](https://gitlab.com/gitlab-org/gitlab/-/blob/master/.markdownlint-cli2.yaml),
  so they can be consistently applied across all documentation.
- Added to the [word list](word_list.md).

If the term is not in the word list, ask a GitLab Technical Writer for advice.
For assistance naming a feature and ensuring it meets GitLab standards, see
[the handbook](https://handbook.gitlab.com/handbook/product/categories/gitlab-the-product/#naming-features).

Do not match the capitalization of terms or phrases on the [Features page](https://about.gitlab.com/features/)
or [`features.yml`](https://gitlab.com/gitlab-com/www-gitlab-com/blob/master/data/features.yml)
by default.

### Other terms

Capitalize names of:

- GitLab [product tiers](https://about.gitlab.com/pricing/). For example,
  GitLab Free and GitLab Ultimate.
- Third-party organizations, software, and products. For example, Prometheus,
  Kubernetes, Git, and The Linux Foundation.
- Methods or methodologies. For example, Continuous Integration,
  Continuous Deployment, Scrum, and Agile.

Follow the capitalization style listed at the authoritative source
for the entity, which might use non-standard case styles. For example: GitLab and
npm.

## Fake user information

Do not include real usernames or email addresses in the documentation.

For text:

- Use diverse or non-gendered names with common surnames, like `Sidney Jones`, `Zhang Wei`, or `Alex Garcia`.
- Make fake email addresses end in `example.com`.

For screenshots:

- Temporarily edit the page before you take the screenshot:

  1. Right-click the text you want to change.
  1. Select **Inspect**.
  1. In the **Elements** dialog, edit the HTML to replace text that contains real user information with example data.
  1. Close the dialog. All of the user data in the web page should now be replaced with the example data you entered.
  1. Take the screenshot.

- Alternatively, create example accounts in a test environment, and take the screenshot there.
- If you can't reproduce the environment, blur the user data by using an image editing tool like Preview on macOS.

## Fake URLs

When including sample URLs in the documentation, use:

- `example.com` when the domain name is generic.
- `gitlab.example.com` when referring only to GitLab Self-Managed.
  Use `gitlab.com` for GitLab.com.

## Fake tokens

Do not use real tokens in the documentation.

Use these fake tokens as examples:

| Token type            | Token value |
|:----------------------|:------------|
| Personal access token | `<your_access_token>` |
| Application ID        | `2fcb195768c39e9a94cec2c2e32c59c0aad7a3365c10892e8116b5d83d4096b6` |
| Application secret    | `04f294d1eaca42b8692017b426d53bbc8fe75f827734f0260710b83a556082df` |
| CI/CD variable        | `Li8j-mLUVA3eZYjPfd_H` |
| Project runner token  | `yrnZW46BrtBFqM7xDzE7dddd` |
| Instance runner token | `6Vk7ZsosqQyfreAxXTZr` |
| Trigger token         | `be20d8dcc028677c931e04f3871a9b` |
| Webhook secret token  | `6XhDroRcYPM5by_h-HLY` |
| Health check token    | `Tu7BgjR9qeZTEyRzGG2P` |

## Contractions

Contractions are encouraged, and can create a friendly and informal tone,
especially in tutorials, instructional documentation, and
[user interfaces](https://design.gitlab.com/content/punctuation/#contractions).

Some contractions, however, should be avoided:

<!-- vale gitlab_base.Possessive = NO -->

| Do not use a contraction      | Example                                   | Use instead |
|-------------------------------|-------------------------------------------|-------------|
| With a proper noun and a verb | **Terraform's** a helpful tool.           | **Terraform** is a helpful tool. |
| To emphasize a negative       | **Don't** install X with Y.               | **Do not** install X with Y. |
| In reference documentation    | **Don't** set a limit.                    | **Do not** set a limit. |
| In error messages             | Requests to localhost **aren't** allowed. | Requests to localhost **are not** allowed. |

<!-- vale gitlab_base.Possessive = YES -->

## Possessives

Do not use possessives (`'s`) for proper nouns, like organization or product names.

For example, instead of `Docker's CLI`, use `the Docker CLI`.

## Prepositions

Use prepositions at the end of the sentence when needed.
Dangling or stranded prepositions are fine. For example:

- You can leave the group you're a member of.
- Share the credentials with users you want to give access to.

These constructions are more casual than the alternatives:

- You can leave the group of which you're a member.
- Share the credentials with users to which you want to give access.

## Acronyms

If you use an acronym, spell it out on first use on a page. Do not spell it out more than once on a page.

- **Titles**: Try to avoid acronyms in topic titles, especially if the acronym is not widely used.
- **Plurals**: Try not to make acronyms plural. For example, use `YAML files`, not `YAMLs`. If you must make an acronym plural, do not use an apostrophe. For example, use `APIs`, not `API's`.
- **Possessives**: Use caution when making an acronym possessive. If possible,
  write the sentence to avoid making the acronym possessive. If you must make the
  acronym possessive, consider spelling out the words.

## Numbers

For numbers in text, spell out zero through nine and use numbers for 10 and greater.

For numbers in the UI, see [Pajamas](https://design.gitlab.com/content/punctuation#numbers).

## Dates and times

Use the `month day, year` format for dates, and use `AM` and `PM` for times.
For example:

```plaintext
January 3, 2026 at 10:30 AM
```

For dates and times in the UI, see [Pajamas](https://design.gitlab.com/content/date-and-time).
