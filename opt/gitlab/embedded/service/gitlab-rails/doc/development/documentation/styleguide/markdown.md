---
stage: none
group: unassigned
info: For assistance with this Style Guide page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments-to-other-projects-and-subjects>.
description: Markdown, heading levels, and list rules for GitLab documentation.
title: Markdown and lists
---

## Markdown

All GitLab documentation is written in [Markdown](https://en.wikipedia.org/wiki/Markdown).

The [documentation website](https://docs.gitlab.com) uses the [Hugo](https://gohugo.io/) static site generator with its default Markdown engine, [Goldmark](https://gohugo.io/content-management/formats/#markdown).

Markdown formatting is tested by using [markdownlint](../testing/markdownlint.md) and [Vale](../testing/vale.md).

### HTML in Markdown

Hard-coded HTML is valid, although it's discouraged for a few reasons:

- Custom markup has potential to break future site-wide changes or design system updates.
- Custom markup does not have test coverage to ensure consistency across the site.
- Custom markup might not be responsive or accessible.
- Custom markup might not adhere to [Pajamas](https://design.gitlab.com) guidelines.
- HTML and CSS in Markdown do not render on `/help`.
- Hand-coding HTML can be error-prone. It's possible to break the page layout or other components with malformed HTML.

HTML is permitted if:

- No equivalent exists in Markdown.
- The content is reviewed and approved by a technical writer.
- The need for a custom element is urgent and cannot wait for implementation by Technical Writing engineers.

Any links created with HTML `<a>` tags must use absolute URLs as their
`href` attributes. Unlike regular links, do not use relative links to
Markdown files, as Hugo can only process and replace Markdown-formatted links.

If you have an idea or request for a new element that would be useful on the Docs site,
submit a [feature request](https://gitlab.com/gitlab-org/technical-writing/docs-gitlab-com/-/issues/new?description_template=Default).

### Heading levels in Markdown

Each documentation page must include a `title` attribute in its [metadata](../metadata.md).
The `title` becomes the `H1` element when rendered to HTML.
Do not add an `H1` heading in Markdown because there can be only one for each page.

- For each subsection, increment the heading level. In other words, increment the number of `#` characters
  in front of the topic title.
- Avoid heading levels greater than `H5` (`#####`). If you need more than five heading levels, move the topics to a new page instead.
  Heading levels greater than `H4` do not display in the right sidebar navigation.
- Do not skip a level. For example: `##` > `####`.
- Leave one blank line before and after the topic title.
- If you use code in topic titles, ensure the code is in backticks.
- Do not use bold text in topic titles.

To prevent a heading from appearing in the table of contents (TOC),
add the `{.no_toc}` attribute after the heading text:

```markdown
## My heading {.no_toc}
```

The heading still renders on the page, but it is excluded from the TOC.

### Description lists in Markdown

To define terms or differentiate between options, use description lists. For a list of UI elements,
use a regular [list](#lists) instead of a description list.

Do not mix description lists with other styles.

```markdown
Term 1
: Definition of Term 1

Term 2
: Definition of Term 2 is much longer, but we can use
  multiple lines.
```

These lists render like this:

Term 1
: Definition of Term 1

Term 2
: Definition of Term 2 is much longer, but we can use
  multiple lines.

## Lists

Use lists to present information in a format that is easier to scan.

- Make all items in the list parallel.
  For example, do not start some items with nouns and others with verbs.
- Start all items with a capital letter.
- Give all items the same punctuation.
- Do not use a period if the item is not a complete sentence.
- Use a period after every complete sentence, or where the list item forms a complete sentence when combined with the introductory phrase.
  Do not use semicolons or commas.
- Add a colon (`:`) after the introductory phrase.
  For example:

  ```markdown
  The basket contains these fruits:

  - Bananas
  - Apples
  ```

- Do not use [bold](text_and_formatting.md#bold) formatting to define keywords or concepts in a list. Use bold for UI element labels only. For example:

  - `**Start a review**: This is a description of the button that starts a review.`
  - `Offline environments: This is a description of offline environments.`

  For keywords and concepts, consider a [reference topic](../topic_types/reference.md) or
  [description list](#description-lists-in-markdown) for alternative formatting.
- Avoid using list items to complete an introductory phrase. This format can be difficult to localize
  into languages that use different sentence structures.
  For example, use:

  ```markdown
  You can get the license key in the following ways:

  - Copy the license key from the email.
  - Download the file.
  ```

  Instead of:

  ```markdown
  You can get the license key by:

  - Copying it from the email.
  - Downloading the file.
  ```

### Choose between an ordered or unordered list

Use ordered lists for a sequence of steps. For example:

```markdown
Follow these steps to do something.

1. First, do the first step.
1. Then, do the next step.
1. Finally, do the last step.
```

Use an unordered list when the steps do not need to be completed in order. For example:

```markdown
These things are imported:

- Thing 1
- Thing 2
- Thing 3
```

### List markup

- Use dashes (`-`) for unordered lists instead of asterisks (`*`).
- Start every item in an ordered list with `1.`. When rendered, the list items
  are sequential.
- Leave a blank line before and after a list.
- Begin a line with spaces (not tabs) to denote a [nested sub-item](#nesting-inside-a-list-item).

### Nesting inside a list item

The following items can be nested under a list item, so they render with the same
indentation as the list item:

- [Code blocks](text_and_formatting.md#code-blocks)
- [Blockquotes](shortcodes.md#blockquotes)
- [Alert boxes](shortcodes.md#alert-boxes)
- [Illustrations](images_and_diagrams.md#illustrations)
- [Tabs](shortcodes.md#tabs)

Nested items should always align with the first character of the list
item. For unordered lists (using `-`), use two spaces for each level of
indentation:

````markdown
- Unordered list item 1

  A line nested that uses 2 spaces to align with the `U` above.

- Unordered list item 2

  > A quote block that will nest
  > inside list item 2.

- Unordered list item 3

  ```plaintext
  a code block that nests inside list item 3
  ```

- Unordered list item 4

  ![An image nested under list item 4.](image.png)
````

For ordered lists, use three spaces for each level of indentation:

````markdown
1. Ordered list item 1

   A line nested that uses 3 spaces to align with the `O` above.
````

You can nest lists in other lists.

```markdown
1. Ordered list item one.
1. Ordered list item two.
   - Nested unordered list item one.
   - Nested unordered list item two.
1. Ordered list item three.

- Unordered list item one.
- Unordered list item two.
  1. Nested ordered list item one.
  1. Nested ordered list item two.
- Unordered list item three.
```
