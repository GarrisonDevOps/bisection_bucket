---
stage: none
group: unassigned
info: For assistance with this Style Guide page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments-to-other-projects-and-subjects>.
description: Writing styles, markup, formatting, and other standards for GitLab Documentation.
title: Documentation Style Guide
---

This document defines the standards for GitLab documentation.

## Structure

The Documentation Style Guide is split into these pages.

### Writing

| Page | Contents |
|------|----------|
| [Language](language.md) | Grammar, voice, capitalization, and word choice rules for GitLab documentation. |
| [Products, features, and standard sections](products_and_sections.md) | Rules for product names and standard sections in GitLab documentation. |
| [Recommended word list](word_list.md) | Recommended word choices for GitLab documentation. |
| [Text and formatting](text_and_formatting.md) | Punctuation, line length, bold, code, and other text formatting rules for GitLab documentation. |
| [UI elements and navigation paths](ui_text.md) | How to use shortcodes to tag UI elements in GitLab documentation. |

### Page elements

| Page | Contents |
|------|----------|
| [Images, diagrams, and icons](images_and_diagrams.md) | Rules for screenshots, diagrams, and icons in GitLab documentation. |
| [Links and videos](links.md) | Rules for links, link text, videos, and click-through demos in GitLab documentation. |
| [Markdown and lists](markdown.md) | Markdown, heading levels, and list rules for GitLab documentation. |
| [Metadata](../metadata.md) | Front matter metadata for GitLab documentation pages. |
| [Shortcodes and content blocks](shortcodes.md) | Shortcodes, alert boxes, tabs, and other content blocks in GitLab documentation. |
| [Tables](tables.md) | Rules for creating and formatting tables in GitLab documentation. |

### Related guidelines

- [Feature status and versions](../feature_status_and_versions.md): availability details, feature flags, experiment and beta features, deprecations, and upgrade notes.
- [API and CLI reference](../api_and_cli_styleguides.md): REST API, GraphQL, and GitLab CLI (glab) documentation.

## Other guidance

The GitLab handbook provides guidance on:

- [Top misused terms](https://handbook.gitlab.com/handbook/communication/top-misused-terms/)
- [Use of third-party trademarks](https://handbook.gitlab.com/handbook/legal/policies/product-third-party-trademarks-guidelines/)

For guidance not in the Documentation Style Guide, we defer to these style guides:

- [Microsoft Writing Style Guide](https://learn.microsoft.com/en-us/style-guide/welcome/)
- [Google Developer Documentation Style Guide](https://developers.google.com/style)

## The GitLab voice

The GitLab brand guidelines define the
[voice used by the larger organization](https://design.gitlab.com/brand-messaging/brand-voice).

Building on that guidance, the voice in the GitLab documentation strives to be concise,
direct, and precise. The goal is to provide information that's easy to search and scan.

The voice in the documentation should be conversational but brief, friendly but succinct.

## Documentation is the single source of truth (SSoT)

The GitLab documentation is the SSoT for all product information related to implementation,
use, and troubleshooting. The documentation evolves continuously. It is updated with
new products and features, and with improvements for clarity, accuracy, and completeness.

This policy:

- Prevents information silos and makes it easier to find information about GitLab products.
- Does not mean that content cannot be duplicated in multiple places in the documentation.

## Topic types

GitLab uses [topic types](../topic_types/_index.md) to organize the product documentation.

Topic types help users digest information more quickly. They also help address these issues:

- **Content is hard to find.** The GitLab documentation is comprehensive and includes a large amount of
  useful information. Topic types create repeatable patterns that make the content easier
  to scan and parse.
- **Content is often written from the contributor's point of view.** The GitLab documentation is
  written by a variety of contributors. Topic types (tasks, specifically) help put
  information into a format that is geared toward helping others, rather than
  documenting how a feature was implemented.

## Docs-first methodology

The product documentation should be a complete and trusted resource.

- If the answer to a question exists in documentation, share the link to the
  documentation instead of rephrasing the information.
- When you encounter information that's not available in GitLab documentation,
  create a merge request (MR) to add the information to the
  documentation. Then share the MR to communicate the information.

The more we reflexively add information to the documentation, the more
the documentation helps others efficiently accomplish tasks and solve problems.

## Writing for localization

We follow guidelines that help us write for a global audience.

[The GitLab voice](#the-gitlab-voice) dictates that we write clearly and directly with translation in mind.
Our Documentation Style Guide, [word list](word_list.md), and [Vale rules](../testing/_index.md) ensure consistency in the documentation.

When documentation is translated into other languages, the meaning of each word must be clear.
The increasing use of machine translation, GitLab Duo Chat, and other AI tools
means that consistency is even more important.

The following rules can help documentation be translated more efficiently.

Avoid:

- Phrases that hide the subject like [**there is** and **there are**](word_list.md#there-is-there-are).
- Ambiguous pronouns like [**it**](word_list.md#it).
- Words that end in [**-ing**](word_list.md#-ing-words).
- Words that can be confused with one another like [**since**](word_list.md#since) and **because**.
- Latin abbreviations like [**e.g.**](word_list.md#eg) and [**i.e.**](word_list.md#ie).
- Culture-specific references like **kill two birds with one stone**.

Use:

- Standard [text for links](links.md#text-for-links).
- [Lists](markdown.md#lists) and [tables](tables.md) instead of complex sentences and paragraphs.
- Common abbreviations like [**AI**](word_list.md#ai-artificial-intelligence) and
  [**CI/CD**](word_list.md#cicd) and abbreviations you've previously spelled out.

Also, keep the following guidance in mind:

- Be consistent with [feature names](language.md#feature-names) and how to interact with them.
- Break up noun strings. For example, instead of **project integration custom settings**,
  use **custom settings for project integrations**.
- Format [dates and times](language.md#dates-and-times)
  consistently and for an international audience.
- Use [illustrations](images_and_diagrams.md#illustrations), including screenshots, sparingly.
- For [UI text](ui_text.md), allow for up to 30% expansion and contraction in translation.
  To see how much a string expands or contracts in another language, paste the string
  into [Google Translate](https://translate.google.com/) and review the results.
  Ask a colleague who speaks the language to verify if the translation is clear.

## Plagiarism

Do not copy and paste content from other sources unless it is a limited
quotation with the source cited. Typically, it is better to rephrase
relevant information in your own words or link to the source.

## AI-generated content

When you use AI tools to generate or assist with documentation, check the output carefully
before you submit it for review. AI is designed to write convincingly but
AI-generated content often has these problems:

Repetition
: Content that restates what has already been said on the page
  or in a linked topic.
  Each section should add new information.
  Do not summarize what was just explained.
  Do not restate the title or introduction in the first paragraph.

Vague or unverifiable claims
: Descriptions of how a feature works that
  are not grounded in the codebase or existing documentation.
  Only include information you can ground in the existing codebase, linked documentation,
  or content already on the page.
  Do not speculate or infer how a feature works.
  Do not invent command syntax, API parameters, or UI element names.

Incorrect scope
: A new page has been created for a concept or procedure when a suitable
  page already exists.
  Do not create a new page for a single concept, term, or procedure step.

## Promising features in future versions

Do not promise to deliver features in a future release. For example, avoid phrases like,
"Support for this feature is planned."

We cannot guarantee future feature work, and promises
like these can raise legal issues. Instead, say that an issue exists.
For example:

- Support for improvements is proposed in `[issue <issue_number>](https://work-item-link)`.
- You cannot do this thing, but `[issue 12345](https://work-item-link)` proposes to change this behavior.

You can say that we plan to remove a feature.

If you must document a future feature, use the [disclaimer](shortcodes.md#disclaimer).
