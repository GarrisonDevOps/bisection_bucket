---
stage: none
group: unassigned
info: Any user with at least the Maintainer role can merge updates to this content. For details, see <https://docs.gitlab.com/development/development_processes/#development-guidelines-review>.
title: Accessibility best practices
---

## Quick summary

Since [no ARIA is better than bad ARIA](https://w3c.github.io/aria-practices/#no_aria_better_bad_aria),
review the following recommendations before using `aria-*`, `role`, and `tabindex`.
Use semantic HTML, which has accessibility semantics baked in, and ideally test with
[relevant combinations of screen readers and browsers](https://www.accessibility-developer-guide.com/knowledge/screen-readers/relevant-combinations/).

In [WebAIM's accessibility analysis of the top million home pages](https://webaim.org/projects/million/#aria),
they found that "ARIA correlated to higher detectable errors".
It is likely that misuse of ARIA is a big cause of increased errors,
so when in doubt don't use `aria-*`, `role`, and `tabindex` and stick with semantic HTML.

## Enable keyboard navigation on macOS

By default, macOS limits the <kbd>tab</kbd> key to **Text boxes and lists only**. To enable full keyboard navigation:

1. Open **System Preferences**.
1. Select **Keyboard**.
1. Open the **Shortcuts** tab.
1. Enable the setting **Use keyboard navigation to move focus between controls**.

You can read more about enabling browser-specific keyboard navigation on [a11yproject](https://www.a11yproject.com/posts/macos-browser-keyboard-navigation/).

## Quick checklist

- [Text](https://design.gitlab.com/components/text-input#accessibility),
  [textarea](https://design.gitlab.com/components/textarea#accessibility),
  [select](https://design.gitlab.com/components/select#accessibility),
  [checkbox](https://design.gitlab.com/components/checkbox#accessibility),
  [radio](https://design.gitlab.com/components/radio-button#accessibility),
  [file](#form-inputs-with-accessible-names),
  and [toggle](https://design.gitlab.com/components/toggle#accessibility) inputs have accessible names.
- [Buttons](#buttons-and-links-with-descriptive-accessible-names),
  [links](#buttons-and-links-with-descriptive-accessible-names),
  and [images](#images-with-accessible-names) have descriptive accessible names.
- Icons
  - [Non-decorative icons](#icons-that-convey-information) have an `aria-label`.
  - [Clickable icons](#icons-that-are-clickable) are buttons, that is, `<gl-button icon="close" />` is used and not `<gl-icon />`.
  - Icon-only buttons have an `aria-label`.
- Interactive elements can be [accessed with the Tab key](#support-keyboard-only-use) and have a visible focus state.
- Elements with [tooltips](https://design.gitlab.com/components/tooltip#accessibility) are focusable using the Tab key.
  See [Tooltips on elements that cannot take focus](#tooltips-on-elements-that-cannot-take-focus).
- [Tooltips contain no interactive content](#tooltips-with-interactive-content). Use a popover instead.
- Are any `role`, `tabindex`, or `aria-*` attributes unnecessary?
- Can any `div` or `span` elements be replaced with a more semantic [HTML element](https://developer.mozilla.org/en-US/docs/Web/HTML/Element) like `p`, `button`, or `time`?

## Provide a good document outline

[Headings are the primary mechanism used by screen reader users to navigate content](https://webaim.org/projects/screenreadersurvey8/#finding).
Therefore, the structure of headings on a page should make sense, like a good table of contents.
We should ensure that:

- There is only one `h1` element on the page. This is the page's primary role or purpose.
- Second level `h2` text should support the primary role or purpose.
- Heading levels are not skipped.
- Heading levels are nested correctly.
- It is [permissible](https://www.w3.org/WAI/WCAG22/Techniques/html/H42) to have an `h2` before the primary `h1`. This can be helpful for navigation, alerts, or banners. The `h2` must not be visually more prominent than the `h1`, because heading levels must match the [visual hierarchy](https://vispero.com/resources/heading-off-confusion-when-do-headings-fail-wcag/).

## Provide accessible names for screen readers

To provide markup with accessible names, ensure every:

- input has an [associated `label`](#examples-of-providing-accessible-names).
- button and link have [visible text](#buttons-and-links-with-descriptive-accessible-names), or `aria-label` when there is no visible text, such as for an icon button with no content.
- button and link have a unique accessible name. This name must be descriptive and not repeat.
- image has an [`alt` attribute](#images-with-accessible-names).
- [chart has a long and short description](https://www.w3.org/WAI/tutorials/images/complex/).
- `fieldset` has `legend` as its first child.
- `figure` has `figcaption` as its first child.
- `table` has `caption` as its first child.
- `table` row has a [row header](https://design.gitlab.com/components/table#row-headers).

Remember that an [`alt` attribute](#images-with-accessible-names) should not be longer than approximately 150 characters. While there are no official guidelines on the length, some screen readers will not read longer strings inside the `alt` attribute. If an image is decorative or visual styling only, it must have an empty `alt=""` attribute.

An accessible name can be provided in multiple ways and is decided with [accessible name calculation](https://www.w3.org/WAI/ARIA/apg/practices/names-and-descriptions/#name_calculation). Here is the simplified order of different techniques taking precedence:

1. `aria-labelledby`
1. `aria-label`
1. `alt`, `legend`, `figcaption`, or `caption`
1. `title`.

### Examples of providing accessible names

The following subsections contain examples of markup that render HTML elements with accessible names.

Note that [when using `GlFormGroup`](https://bootstrap-vue.org/docs/components/form-group#accessibility):

- Passing only a `label` prop renders a `fieldset` with a `legend` containing the `label` value.
- Passing both a `label` and a `label-for` prop renders a `label` that points to the form input with the same `label-for` ID.

#### Form inputs with accessible names

Groups of checkboxes and radio inputs should be grouped together in a `fieldset` with a `legend`.
`legend` gives the group of checkboxes and radio inputs a label.

If the `label`, child text, or child element is not visually desired,
use the class name `gl-sr-only` to hide the element from everything but screen readers.

File input examples:

```html
<!-- File input with a label -->
<label for="attach-file">{{ __('Attach a file') }}</label>
<input id="attach-file" type="file" />

<!-- File input with a hidden label -->
<label for="attach-file" class="gl-sr-only">{{ __('Attach a file') }}</label>
<input id="attach-file" type="file" />
```

#### Images with accessible names

Image examples:

```html
<img :src="imagePath" :alt="__('A description of the image')" />

<!-- SVGs implicitly have a graphics role so if it is semantically an image we should apply `role="img"` -->
<svg role="img" :alt="__('A description of the image')" />

<!-- A decorative image, hidden from screen readers -->
<img :src="imagePath" :alt="" />
```

#### Buttons and links with descriptive accessible names

Buttons and links should have accessible names that are descriptive enough to be understood in isolation.

```html
<!-- bad -->
<gl-button @click="handleClick">{{ __('Submit') }}</gl-button>

<gl-link :href="url">{{ __('page') }}</gl-link>

<!-- good -->
<gl-button @click="handleClick">{{ __('Submit review') }}</gl-button>

<gl-link :href="url">{{ __("GitLab's accessibility page") }}</gl-link>
```

## Role

In general, avoid using `role`.
Use semantic HTML elements that implicitly have a `role` instead.

| Bad | Good |
| --- | --- |
| `<div role="button">` | `<button>` |
| `<div role="img">` | `<img>` |
| `<div role="link">` | `<a>` |
| `<div role="header">` | `<h1>` to `<h6>` |
| `<div role="textbox">` | `<input>` or `<textarea>` |
| `<div role="article">` | `<article>` |
| `<div role="list">` | `<ol>` or `<ul>` |
| `<div role="listitem">` | `<li>` |
| `<div role="table">` | `<table>` |
| `<div role="rowgroup">` | `<thead>`, `<tbody>`, or `<tfoot>` |
| `<div role="row">` | `<tr>` |
| `<div role="columnheader">` | `<th>` |
| `<div role="cell">` | `<td>` |

## Support keyboard-only use

Keyboard users rely on focus outlines to understand where they are on the page. Therefore, if an
element is interactive you must ensure:

- It can receive keyboard focus.
- It has a visible focus state.

Focus management is also necessary to ensure good keyboard usability. If you use elements like modal dialogs, you must ensure:

- The modal dialog receives keyboard focus when it is opened or revealed.
- The element that triggered the change must receive keyboard focus when the dialog or drawer is closed.
- If the element that had keyboard focus is removed from the DOM, you must define where keyboard focus should be set.

Use semantic HTML, such as `a` (`GlLink`) and `button` (`GlButton`), which provides these behaviors by default.

Keep in mind that:

- <kbd>Tab</kbd> and <kbd>Shift-Tab</kbd> should only move between interactive elements, not static content.
- When you add `:hover` styles, in most cases you should add `:focus-visible` styles too so that the styling is applied for both mouse and keyboard users. Prefer `:focus-visible` over `:focus`, which also applies the styles when a mouse click focuses the element.
- If you remove an interactive element's `outline`, make sure you maintain visual focus state in another way such as with `box-shadow`.

See the [Pajamas Keyboard-only page](https://design.gitlab.com/accessibility/keyboard-only) for more detail.

## `tabindex`

Prefer no `tabindex` to using `tabindex`, since:

- Using semantic HTML such as `button` (`GlButton`) implicitly provides `tabindex="0"`.
- Tabbing order should match the visual reading order and positive `tabindex`s interfere with this.

### Avoid using `tabindex="0"` to make an element interactive

Use interactive elements instead of `div` and `span` tags.
For example:

- If the element should be clickable, use a `button` (`GlButton`).
- If the element should be text editable, use an [`input`](https://design.gitlab.com/components/text-input#accessibility) or [`textarea`](https://design.gitlab.com/components/textarea#accessibility).

Once the markup is semantically complete, use CSS to update it to its desired visual state.

```html
<!-- bad -->
<div role="button" tabindex="0" @click="expand">Expand</div>

<!-- good -->
<gl-button class="!gl-p-0" category="tertiary" @click="expand">Expand</gl-button>
```

### Do not use `tabindex="0"` on interactive elements

Interactive elements are already tab accessible so adding `tabindex` is redundant.

```html
<!-- bad -->
<gl-link href="help" tabindex="0">Help</gl-link>
<gl-button tabindex="0">Submit</gl-button>

<!-- good -->
<gl-link href="help">Help</gl-link>
<gl-button>Submit</gl-button>
```

### Do not use `tabindex="0"` on elements for screen readers to read

Screen readers can read text that is not tab accessible.
The use of `tabindex="0"` is unnecessary and can cause problems,
as screen reader users then expect to be able to interact with it.

```html
<!-- bad -->
<p tabindex="0" :aria-label="message">{{ message }}</p>

<!-- good -->
<p>{{ message }}</p>
```

> [!note]
> If a container's calculated height is less than the length of its
> content and scrolling is permitted by CSS `overflow: auto` or
> `overflow: scroll`, you must add a `tabindex="0"`. This allows
> keyboard users to set focus on the container and scroll using arrow
> keys.

### Do not use a positive `tabindex`

[Always avoid using `tabindex="1"`](https://webaim.org/techniques/keyboard/tabindex#overview)
or greater.

## Tooltips with interactive content

Keyboard users can't reach links, buttons, or other controls inside a tooltip.
This fails [WCAG 2.1 Success Criterion 2.1.1 Keyboard (Level A)](https://www.w3.org/WAI/WCAG21/Understanding/keyboard.html).
Use a popover for interactive content instead.

For more information, see the Pajamas tooltip guidance on [when not to use a tooltip](https://design.gitlab.com/components/tooltip/#when-not-to-use)
and [tooltip accessibility](https://design.gitlab.com/components/tooltip/#accessibility).

### What the ESLint rule detects

The [`@gitlab/vue-no-interactive-content-in-tooltip`](https://gitlab.com/gitlab-org/frontend/eslint-plugin/blob/main/docs/rules/vue-no-interactive-content-in-tooltip.md)
rule is enabled as `error`.
Inside `<gl-tooltip>` or `<GlTooltip>`, including nested wrappers and named slots, the rule reports:

- `a`, `button`, `input`, `select`, `textarea`, `gl-link`, `gl-button`, `router-link`,
  and `help-page-link` elements, and their PascalCase equivalents.
- Elements with a static or bound `tabindex`.
- Elements with a `@click` or `v-on:click` listener.

The rule doesn't fix violations automatically, because moving content to a popover changes the interaction.

The rule inspects only the static Vue template inside `<gl-tooltip>`.
Review these cases manually, because the rule doesn't detect them:

- Custom components that render links, buttons, or other focusable elements internally.
- Content rendered at runtime, such as dynamic components or `v-html`.
- Interactive content passed in from a parent component through props or slots.
- Tooltips attached with the `v-gl-tooltip` directive, `has-tooltip`, or `data-toggle="tooltip"`,
  and HTML in `title` or `data-title` attributes. This includes tooltips rendered by HAML or helpers.
- Elements that become interactive only through event handlers attached in JavaScript.

Development-mode warnings in GitLab UI for interactive tooltip content, including HTML titles,
are proposed in [Pajamas issue 3723](https://gitlab.com/gitlab-org/gitlab-services/design.gitlab.com/-/issues/3723).

### Example

```html
<!-- bad -->
<gl-button id="help-trigger">{{ __('Help') }}</gl-button>
<gl-tooltip target="help-trigger">
  <gl-link href="/help">{{ __('Learn more') }}</gl-link>
</gl-tooltip>

<!-- good -->
<gl-button id="help-trigger">{{ __('Help') }}</gl-button>
<gl-popover target="help-trigger" :title="__('More information')" triggers="click">
  <gl-link href="/help">{{ __('Learn more') }}</gl-link>
</gl-popover>
```

### Migrate a violation to `GlPopover`

To fix a violation:

1. Replace `GlTooltip` with `GlPopover`. Keep a tooltip only for plain, non-interactive text.
1. Set `triggers="click"` on the popover. The default `hover focus` triggers can close the
   popover before a user reaches its content.
1. Make sure the popover trigger can receive keyboard focus, for example by using `GlButton`.
1. Request a UX and accessibility review, because the interaction changes.

Don't add new files to `.eslint_todo/`.
If you can't fix a violation, [disable ESLint for that single violation](../tooling.md#disabling-eslint-for-a-single-violation).

## Tooltips on elements that cannot take focus

`v-gl-tooltip` and `GlTooltip` open on hover and focus of their own element only.
A tooltip on a static element such as a `span`, `strong`, or `h3` is never shown to keyboard users.
The [Pajamas tooltip accessibility guidance](https://design.gitlab.com/components/tooltip#accessibility)
recommends putting a static element, such as an icon, inside a button that can already take focus,
instead of adding `tabindex="0"` to the static element.

When the text that needs a tooltip is not focusable, pick the first option that fits.

### Put the tooltip on the element that already takes focus

This is usually the link or button the text sits in.
If the element is wide and the tooltip should sit over the text, use a placement modifier.

```html
<!-- bad: keyboard users never see the tooltip -->
<gl-link :href="url">
  <strong v-gl-tooltip :title="tooltipText">{{ title }}</strong>
</gl-link>

<!-- good: the link takes focus, so the tooltip shows on Tab -->
<gl-link v-gl-tooltip :href="url" :title="tooltipText">
  <strong>{{ title }}</strong>
</gl-link>

<!-- better: anchor the tooltip where the text is -->
<gl-link v-gl-tooltip.topleft :href="url" :title="tooltipText">
  <strong>{{ title }}</strong>
</gl-link>
```

### Forward the host's focus to a tooltip on the text inside it

Use this only when the tooltip must anchor to the text of a full-width host and no placement modifier does it.
The host shows and hides the text's tooltip itself, with the `showGlTooltip` and `hideGlTooltip` helpers from `~/vue_shared/utils/tooltips`.
Listen to the host's `focus` and `blur`, not `focusin` and `focusout`: those bubble, so tabbing to a focusable child inside the host would open two tooltips.

```html
<!-- bad: focusin bubbles from the child time element and opens two tooltips -->
<gl-link :href="url" @focusin="showTitleTooltip" @focusout="hideTitleTooltip">
  <strong :id="titleId" v-gl-tooltip :title="tooltipText">{{ title }}</strong>
  <time-ago-tooltip :time="updatedAt" />
</gl-link>

<!-- good: focus and blur do not bubble -->
<gl-link :href="url" @focus="showTitleTooltip" @blur="hideTitleTooltip">
  <strong :id="titleId" v-gl-tooltip :title="tooltipText">{{ title }}</strong>
  <time-ago-tooltip :time="updatedAt" />
</gl-link>
```

Showing a tooltip programmatically goes through the BootstrapVue root event bus, which depends on `$root.$on` and so on `@vue/compat`.
It is [tracked for replacement](https://gitlab.com/gitlab-org/gitlab/-/work_items/634652), so prefer the first option when the placement allows it.
See also [Event hub](../vue3_migration.md#event-hub).

### Add `tabindex="0"` only when the tooltip holds information available nowhere else

Add `focus-visible:gl-focus` so the focus ring is visible.
This does not contradict [Do not use `tabindex="0"` on elements for screen readers to read](#do-not-use-tabindex0-on-elements-for-screen-readers-to-read): keyboard users gain content they cannot reach otherwise, rather than a read-out of visible text.

```html
<!-- bad: a tab stop that announces nothing new -->
<h3 tabindex="0" v-gl-tooltip :title="title">{{ title }}</h3>

<!-- good: the tooltip adds the session ID, and the focus ring is visible -->
<h3 tabindex="0" v-gl-tooltip :title="`${title} ${sessionId}`" class="focus-visible:gl-focus">
  {{ title }}
</h3>
```

### Use `GlPopover` when the content is a link or an action

See [Tooltips with interactive content](#tooltips-with-interactive-content).

## Icons

Icons can be split into three different types:

- Icons that are decorative
- Icons that convey meaning
- Icons that are clickable

### Icons that are decorative

Icons are decorative when there's no loss of information to the user when they are removed from the UI.

As the majority of icons within GitLab are decorative, `GlIcon` automatically hides its rendered icons from screen readers.
Therefore, you do not need to add `aria-hidden="true"` to `GlIcon`, as this is redundant.

```html
<!-- unnecessary: gl-icon hides icons from screen readers by default -->
<gl-icon name="rocket" aria-hidden="true" />

<!-- good -->
<gl-icon name="rocket" />
```

### Icons that convey information

Icons convey information if there is loss of information to the user when they are removed from the UI.

An example is a confidential icon that conveys the issue is confidential, and does not have the text "Confidential" next to it.

Icons that convey information must have an accessible name so that the information is conveyed to screen reader users too.

```html
<!-- bad -->
<gl-icon name="eye-slash" />

<!-- good -->
<gl-icon name="eye-slash" :aria-label="__('Confidential issue')" />
```

### Icons that are clickable

Icons that are clickable are semantically buttons, so they should be rendered as buttons, with an accessible name.

```html
<!-- bad -->
<gl-icon name="close" :aria-label="__('Close')" @click="handleClick" />

<!-- good -->
<gl-button icon="close" category="tertiary" :aria-label="__('Close')" @click="handleClick" />
```

## Hiding elements

Use the following table to hide elements from users, when appropriate.

| Hide from sighted users | Hide from screen readers | Hide from both sighted and screen reader users |
| --- | --- | --- |
| `.gl-sr-only` | `aria-hidden="true"` | `display: none`, `visibility: hidden`, or `hidden` attribute |

### Hide decorative images from screen readers

To reduce noise for screen reader users, hide decorative images using `alt=""`.
If the image is not an `img` element, such as an inline SVG, you can hide it by adding both `role="img"` and `alt=""`.

`gl-icon` components automatically hide their icons from screen readers so `aria-hidden="true"` is
unnecessary when using `gl-icon`.

```html
<!-- good - decorative images hidden from screen readers -->

<img src="decorative.jpg" alt="">

<svg role="img" alt="" />

<gl-icon name="work-item-epic" />
```

## When to use ARIA

No ARIA is required when using semantic HTML, because it already incorporates accessibility.

However, there are some UI patterns that do not have semantic HTML equivalents.
General examples of these are dialogs (modals) and tabs.
GitLab-specific examples are assignee and label dropdowns.
Building such widgets require ARIA to make them understandable to screen readers.
Proper research and testing should be done to ensure compliance with [WCAG](https://www.w3.org/WAI/standards-guidelines/wcag/).
