---
stage: none
group: unassigned
info: For assistance with this Style Guide page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments-to-other-projects-and-subjects>.
description: Rules for creating and formatting tables in GitLab documentation.
title: Tables
---

Tables should be used to describe complex information in a straightforward
manner. In many cases, an unordered list is sufficient to describe a
list of items with a single description for each item. But, if you have data
that's best described by a matrix, tables are the best choice.

## Creation guidelines

To keep tables accessible and scannable, avoid empty cells. For [feature tables](#feature-tables), use shortcodes to indicate feature availability.
Otherwise, if no meaningful value for a cell exists, use **None**.

To make tables easier to maintain:

- If the table has a `Description` column, make it the right-most column if possible.
- Add additional spaces to make the column widths consistent. For example:

  ```markdown
  | Parameter | Default      | Requirements |
  |-----------|--------------|--------------|
  | `param1`  | `true`       | A and B.     |
  | `param2`  | `gitlab.com` | None         |
  ```

- Skip the additional spaces in the rightmost column for tables that are very wide.
  For example:

  ```markdown
  | Setting   | Default | Description |
  |-----------|---------|-------------|
  | Setting 1 | `1000`  | A short description. |
  | Setting 2 | `2000`  | A long description that would make the table too wide and add too much whitespace if every cell in this column was aligned. |
  | Setting 3 | `0`     | Another short description. |
  ```

- The header (first) row and the delimiter (second) row of the table should be the same length.
  Do not use shortened delimiter rows like `|-|-|-|` or `|--|--|`.
- If a large table does not auto-format well, you can skip the auto-format but:
  - Make the first two rows the same length.
  - Put spaces between the `|` characters and cell contents.
    For example `| Cell 1 | Cell 2 |`, not `|Cell1|Cell2|`.

## Options for large tables

You can use [Hugo class attributes](https://gohugo.io/content-management/markdown-attributes/) to make a table condensed, expandable, or sortable.
To avoid introducing linting errors in a table, test the table locally with all rules enabled.

Hugo class attributes only render on the GitLab documentation site (`https://docs.gitlab.com`).

Put the attribute on the line directly after the last row of the table.
Otherwise, Hugo ignores the attribute. For example:

```markdown
| Parameter | Default      | Requirements |
|-----------|--------------|--------------|
| `param1`  | `true`       | A and B.     |
| `param2`  | `gitlab.com` | None         |
{.condensed}
```

### Condensed tables

A condensed table is scrollable vertically and horizontally, as necessary, and has a restricted height.
By default, wide tables that do not fit on the page are condensed. Long tables are not condensed. You can optionally add
the `condensed` class attribute to reduce the space the table takes up on a page.

```markdown
{.condensed}
```

Or:

```markdown
{class="condensed"}
```

### Expandable tables

Expandable tables have an **Expand table** button that, when selected, opens the table in a dialog.
To create an expandable table, use the `expandable` class attribute.

To make a table both condensed and expandable, use both attributes. For example:

```markdown
{.condensed .expandable}
```

Or:

```markdown
{class="condensed expandable"}
```

### Sortable tables

Sortable tables have column headers that users can select to sort the rows:

- First selection: Ascending order.
- Second selection: Descending order.
- Third selection: Original order.

Make a table sortable when users look up a row by name, like in an attribute,
parameter, setting, or event table.

Do not make a table sortable when:

- The row order has meaning, like a sequence of steps or values over time.
- The table groups rows under subheading rows.
- Users scan the table as a grid, like a permissions matrix or a truth table.

To create a sortable table, use the `sortable` class attribute.

To make a table both condensed and sortable, use both attributes:

```markdown
{.condensed .sortable}
```

Or:

```markdown
{class="condensed sortable"}
```

Before you add the attribute, check how each column sorts:

- Text sorts without regard to case.
- Each group of digits sorts as a whole number, and a period separates these groups.
  Version numbers sort correctly, like `17.2` before `17.10`.
  Decimal values might not, like `1.5` before `1.25`.
- Cells that use the `{{</* yes */>}}` and `{{</* no */>}}` shortcodes sort as `Yes` and `No`.
- Empty cells always sort last.
- Headers that contain a link cannot be sorted.

## Editor extensions for table formatting

To ensure consistent table formatting across all Markdown files, consider formatting your tables
with the VS Code [Markdown Table Formatter](https://github.com/fcrespo82/vscode-markdown-table-formatter).
To configure this extension to follow the guidelines above, turn on the **Follow header row length** setting.
To turn on the setting:

- In the UI:

  1. In the VS Code menu, go to **Code** > **Settings** > **Settings**.
  1. Search for `Limit Last Column Length`.
  1. In the **Limit Last Column Length** dropdown list, select **Follow header row length**.

- In your VS Code `settings.json`, add a new line with:

  ```json
  {
    "markdown-table-formatter.limitLastColumnLength": "Follow header row length"
  }
  ```

To format a table with this extension, select the entire table, right-click the selection,
and select **Format Selection With**. Select **Markdown Table Formatter** in the VS Code Command Palette.

If you use Sublime Text, try the
[Markdown Table Formatter](https://packagecontrol.io/packages/Markdown%20Table%20Formatter)
plugin, but it does not have a **Follow header row length** setting.

## Updates to existing tables

When you add or edit rows in an existing table, some rows might not be aligned anymore.
Don't realign the entire table if only changing a few rows.
If you realign the columns to account for the width, the diff becomes difficult to read,
because the entire table shows as modified.

Markdown tables naturally fall out of alignment over time, but still render correctly
on `docs.gitlab.com`. The technical writing team can realign cells the next time
the page is refactored.

## Table headers

Use sentence case for table headers. For example, `Keyword value` or `Project name`.

## Feature tables

When creating tables of lists of features (such as the features
available to each role on the [Permissions](../../../user/permissions.md#project-permissions)
page), use these shortcodes:

| Option | Markdown          | Renders     | Notes |
|--------|-------------------|-------------|-------|
| No     | `{{</* no */>}}`  | {{< no >}}  | Renders a hidden `span` for screen readers: `<span class="gl-sr-only">no</span>` |
| Yes    | `{{</* yes */>}}` | {{< yes >}} | Renders a visible checkmark icon and a hidden `span` for screen readers: `<span class="gl-sr-only">yes</span>` |

Do not use these shortcodes in API documentation or inline text. For API documentation, follow
the [API topic template](../restful_api_styleguide.md#api-topic-template).

## Footnotes

Use footnotes below tables only when you cannot include the content in the table itself.
For example, use footnotes when you must:

- Provide the same information in several table cells.
- Include content that would disrupt the table's layout.

### Footnote format

In the table cell, write a footnote reference as `[^label]`.
Add the reference at the end of the sentence, with no space before it.
If a cell or sentence needs more than one footnote reference, separate them with a comma and a space.
For example, `[^registration-shell], [^default-shell]`.
Write the matching definition as `[^label]: Footnote text.`

For example:

```markdown
| App name | Description |
|:---------|:------------|
| App A    | Description text.[^rate-limit] |
| App B    | Description text.[^retention] |

[^rate-limit]: This is the first footnote.
[^retention]: This is the second footnote.
```

Add a table's definitions directly below that table, so the source stays readable.
Do not put a footnote reference or definition inside a shortcode, like tabs (`{{</* tabs */>}}`).

The renderer numbers the footnotes and adds a `Footnotes` heading below the table.

### Footnote indentation

If a footnote definition contains more than one line, indent every line after the first with
four spaces.
This applies to lines in the same paragraph and to additional paragraphs or lists.

The indent is required after a blank line.
If you don't add the indent, all text after the blank line is not included in the footnote and renders as ordinary text.

For example:

```markdown
[^rate-limit]: This is the first footnote description sentence.
    This is the second sentence.

    This is the second paragraph of the same footnote.
```

### Footnote numbering

Footnotes are numbered in the order they're first referenced.
The count is page-wide and includes every table and paragraph on the page.

Footnote labels are also page-wide.
Use the same label in several references when you want them to share one footnote.
Otherwise, give each footnote a unique label.
If you define the same label twice, the renderer keeps the first definition and discards the second without a warning.
