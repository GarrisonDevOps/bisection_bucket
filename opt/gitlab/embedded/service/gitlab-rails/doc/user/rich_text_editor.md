---
stage: Plan
group: Planner Intelligence
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Rich text editor
---

{{< details >}}

- Tier: Free, Premium, Ultimate
- Offering: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- Rich text editor [set to default editor for new users](https://gitlab.com/gitlab-org/gitlab/-/issues/536611) in GitLab 18.2.

{{< /history >}}

The rich text editor is the default text editor for new users in GitLab.

You can use the rich text editor in:

- [Wikis](project/wiki/_index.md)
- Issues
- Epics
- Merge requests
- [Designs](project/issues/design_management.md)

Features of the editor include:

- Format text, including as bold, italics, block quotes, headings, and inline code.
- Format ordered lists, unordered lists, and checklists.
- Insert links, attachments, images, video, and audio.
- Create and edit a table structure.
- Insert and format code blocks with syntax highlighting.
- Preview Mermaid, PlantUML, and Kroki diagrams in real time.

To track work on adding the rich text editor to more places across GitLab, see
[epic 7098](https://gitlab.com/groups/gitlab-org/-/epics/7098).

## Switch to the rich text editor

Use the rich text editor to edit descriptions, wiki pages, add comments.

To switch to the rich text editor: In a text box, in the lower-left corner, select
{{< ui text="Switch to rich text editing" >}}.

## Switch to the plain text editor

If you want to enter Markdown source in the text box, return to using the plain text editor.

To switch to the plain text editor: In a text box, in the lower-left corner, select
{{< ui text="Switch to plain text editing" >}}.

![A text editor in rich text editing mode with the "Switch to plain text editing" text box in the lower-left](img/rich_text_editor_01_v16_2.png)

## Compatibility with GitLab Flavored Markdown

The rich text editor is fully compatible with [GitLab Flavored Markdown](markdown.md).
It means that you can switch between plain text and rich text modes without losing any data.

### Input rules

Rich text editor also supports input rules that let you work with rich content as if you were
typing Markdown.

Supported input rules:

| Input rule syntax                                         | Content inserted     |
| --------------------------------------------------------- | -------------------- |
| `# Heading 1` through `###### Heading 6`                  | Headings 1 through 6 |
| `**bold**` or `__bold__`                                  | Bold text            |
| `_italics_` or `*italics*`                                | Italicized text      |
| `~~strike~~`                                              | Strikethrough        |
| `[link](https://example.com)`                             | Hyperlink            |
| `code`                                                    | Inline code          |
| ` ```rb ` + <kbd>Enter</kbd> <br> ` ```js ` + <kbd>Enter</kbd> | Code block      |
| `* List item`, or<br> `- List item`, or<br> `+ List item` | Unordered list       |
| `1. List item`                                            | Numbered list        |
| `<details>`                                               | Collapsible section  |
{.sortable}

## Tables

Unlike in raw Markdown, you can use the rich text editor to insert block content paragraphs,
list items, diagrams (or even another table!) in table cells.

### Insert a table

To insert a table:

1. Select {{< ui text="Insert table" >}} {{< icon name="table" >}}.
1. From the dropdown list, select the dimensions of the new table.

![A table size selector with 3 rows and 3 columns.](img/rich_text_editor_02_v16_2.png)

### Edit a table

Inside a table cell, you can use a menu to insert or delete rows or columns.

To open the menu: In the upper-right corner of a cell, select the chevron {{< icon name="chevron-down" >}}.

![An active chevron menu showing table actions.](img/rich_text_editor_03_v16_2.png)

### Operations on multiple cells

Select multiple cells and merge or split them.

To merge selected cells into one:

1. Select multiple cells - select one and drag your cursor.
1. In the upper-right corner of a cell, select the chevron {{< icon name="chevron-down" >}} > **Merge N cells**.

To split merged cells: In the upper-right corner of a cell, select the chevron {{< icon name="chevron-down" >}} > {{< ui text="Split cell" >}}.

### Paste into a table cell

{{< history >}}

- Table menu paste actions [introduced](https://gitlab.com/gitlab-org/gitlab/-/work_items/627112) in GitLab 19.4.
- Keyboard shortcut for pasting into a table cell [introduced](https://gitlab.com/gitlab-org/gitlab/-/work_items/627699) in GitLab 19.4.

{{< /history >}}

When you press <kbd>Control</kbd>+<kbd>V</kbd> (or <kbd>Command</kbd>+<kbd>V</kbd> on macOS),
GitLab merges the copied cells into the table by default.

To choose how the content is pasted:

1. In the upper-right corner of the target cell, select the chevron
   {{< icon name="chevron-down" >}}.
1. Select one of these options:
   - {{< ui text="ContentEditor|Paste into cell" >}}: Inserts the copied content at the cursor. A copied table becomes a
     table nested inside the cell.
   - {{< ui text="ContentEditor|Paste and merge into table" >}}: Distributes the copied cells across the table (default behavior).

Each option also shows its keyboard shortcut next to its label.
To paste a copied table as a nested table without opening the menu, place your cursor in a table cell.
Then press <kbd>Control</kbd>+<kbd>Alt</kbd>+<kbd>V</kbd>
(or <kbd>Command</kbd>+<kbd>Option</kbd>+<kbd>V</kbd> on macOS).

The first time you use either option, your browser might ask for permission to read your
clipboard.

> [!note]
> On GitLab Self-Managed, the paste options and the keyboard shortcut are not available if your
> instance is served over plain HTTP. These features require browser access to the clipboard, and
> browsers allow that access only on pages served over HTTPS or from `localhost`.

## Insert diagrams

Insert [Mermaid](https://mermaidjs.github.io/) and [PlantUML](https://plantuml.com/) diagrams and
preview them live as you type the diagram code.

To insert a diagram:

1. In the editor toolbar, select {{< ui text="More options" >}} ({{< icon name="plus" >}}) >
   {{< ui text="Mermaid diagram" >}} or {{< ui text="PlantUML diagram" >}}.
1. Enter the code for your diagram. The diagram preview appears in the text box.

![A mermaid diagram preview in rich text editor with LR syntax creating a left to right flowchart](img/rich_text_editor_04_v16_2.png)

## Embed external content

{{< details >}}

- Offering: GitLab.com, GitLab Self-Managed
- Status: Experiment

{{< /details >}}

{{< history >}}

- [Introduced](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/231412) in GitLab 19.0 [with a feature flag](../administration/feature_flags/_index.md) named `allow_iframes_in_markdown`. Disabled by default.
- Inserting embedded content from the editor toolbar [introduced](https://gitlab.com/gitlab-org/gitlab/-/issues/282443) in GitLab 19.6.
- Option to turn a link into embedded content [introduced](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/265667) in GitLab 19.6.

{{< /history >}}

> [!flag]
> The availability of this feature is controlled by a feature flag.
> For more information, see the history.
> This feature is available for testing, but not ready for production use.

Insert content, like a YouTube video or a Figma design, from an
[embed provider](markdown.md#embedded-content) that your administrator allows.

To embed content, paste the image Markdown or the `<iframe>` embed code from the provider.

### From the editor toolbar

To insert embedded content from the editor toolbar:

1. In the editor toolbar, select {{< ui text="More options" >}} ({{< icon name="plus" >}}) >
   {{< ui text="Embedded content" >}}.
1. Complete the fields. {{< ui text="URL" >}} must be from an allowed embed provider.
1. Select {{< ui text="Insert" >}}.

### From a link

If a link points to an allowed embed provider, you can turn it into embedded content.

To turn a link into embedded content:

1. In the text box, select the link.
1. Select {{< ui text="Embed link" >}} ({{< icon name="live-preview" >}}).

### Edit embedded content

To resize embedded content, select it, then drag one of its corners.

To change the URL or title of embedded content:

1. Select the embedded content.
1. Select {{< ui text="Edit embed URL and title" >}} ({{< icon name="pencil" >}}).
1. Edit the {{< ui text="URL" >}} or {{< ui text="Alt text" >}}.
1. Select {{< ui text="Apply" >}}.

## Related topics

- [Set the default text editor](profile/preferences.md#set-the-default-text-editor)
- [Keyboard shortcuts](shortcuts.md#rich-text-editor) for rich text editor
- [GitLab Flavored Markdown](markdown.md)
