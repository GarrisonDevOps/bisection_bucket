use std::io::Read;
use std::io::Write;

use clap::Parser;

mod glfm;
use glfm::{render, RenderOptions};
mod formatter;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// CommonMark file(s) to parse; or standard input if none passed
    #[arg(value_name = "FILE")]
    file: Option<String>,

    /// Write output to FILE instead of stdout
    #[arg(short, long, value_name = "FILE")]
    output: Option<String>,

    /// Enable 'alerts' extension
    #[arg(long)]
    alerts: bool,

    /// Enable 'autolink' extension
    #[arg(long)]
    autolink: bool,

    /// Enable 'cjk_friendly_emphasis' extension
    #[arg(long)]
    cjk_friendly_emphasis: bool,

    /// Only use default comrak HTML formatting
    #[arg(long)]
    default_html: bool,

    /// Enable 'description-lists' extension
    #[arg(long)]
    description_lists: bool,

    /// Escape raw HTML instead of clobbering it
    #[arg(long)]
    escape: bool,

    /// Wrap escaped characters in a `<span>` to allow any post-processing to recognize them
    #[arg(long)]
    escaped_char_spans: bool,

    /// Render the image as a figure element with the title as its caption
    #[arg(long)]
    figure_with_caption: bool,

    /// Enable 'footnotes' extension
    #[arg(long)]
    footnotes: bool,

    /// Ignore front-matter that starts and ends with the given string
    // #[arg(long, value_name = "DELIMITER", allow_hyphen_values = true)]
    // front_matter_delimiter: Option<String>,

    /// Enable full info strings for code blocks
    #[arg(long)]
    full_info_string: bool,

    /// Translate gemojis into UTF-8 characters
    #[arg(long)]
    gemojis: bool,

    /// Enables GFM-style quirks in output HTML, such as not nesting <strong>
    /// tags, which otherwise breaks CommonMark compatibility.
    #[arg(long)]
    gfm_quirks: bool,

    /// Use GitHub-style <pre lang> for code blocks
    #[arg(long)]
    github_pre_lang: bool,

    /// Requires at least one space after a `>` character to generate a blockquote,
    /// and restarts blockquote nesting across unique lines of input
    #[arg(long)]
    greentext: bool,

    /// Treat newlines as hard line breaks
    #[arg(long)]
    hardbreaks: bool,

    /// Use new header/anchor combination in HTML output, per
    /// https://gitlab.com/gitlab-org/ruby/gems/gitlab-glfm-markdown/-/merge_requests/112.
    #[arg(long)]
    header_accessibility: bool,

    /// Enable the 'header ID prefix' extension, with the given ID prefix
    #[arg(long, value_name = "PREFIX")]
    header_id_prefix: Option<String>,

    /// Include the header ID prefix in the heading anchor's href.
    #[arg(long)]
    header_id_prefix_in_href: bool,

    /// Prefix to prepend to heading anchor slugs.
    /// When set, slugs become `{header_slug_prefix}{anchorized_text}`.
    #[arg(long, value_name = "PREFIX")]
    header_slug_prefix: Option<String>,

    /// Ignore empty links in input.
    #[arg(long)]
    ignore_empty_links: bool,

    /// Ignore setext headings in input.
    #[arg(long)]
    ignore_setext: bool,

    /// Detect inapplicable tasks (`- [~]`)
    #[arg(long)]
    inapplicable_tasks: bool,

    /// Enables `math code` extension, using math code syntax
    #[arg(long)]
    math_code: bool,

    /// Enables `math dollar` extension, using math dollar syntax
    #[arg(long)]
    math_dollars: bool,

    /// Enable 'multiline block quotes' extension
    #[arg(long)]
    multiline_block_quotes: bool,

    /// When the 'escaped_char_spans' render option is enabled, only emit `<span
    /// data-escaped-char>` around the characters in the supplied string.
    #[arg(long)]
    only_escape_chars: Option<String>,

    /// Detect and marks potential placeholder variables, which
    /// have the format `%{PLACEHOLDER}`
    #[arg(long)]
    placeholder_detection: bool,

    /// Enable relaxing of autolink parsing, allowing links to be recognized when in brackets
    #[arg(long)]
    relaxed_autolinks: bool,

    /// Enable relaxing which character is allowed in a tasklists
    #[arg(long)]
    relaxed_tasklist_character: bool,

    /// Use smart punctuation
    #[arg(long)]
    smart: bool,

    /// Include source mappings in HTML attributes
    #[arg(long)]
    sourcepos: bool,

    /// Enables spoilers using double vertical bars
    #[arg(long)]
    spoiler: bool,

    /// Enable 'strikethrough' extension
    #[arg(long)]
    strikethrough: bool,

    /// Enable 'subscript' extension
    #[arg(long)]
    subscript: bool,

    /// Enable 'superscript' extension
    #[arg(long)]
    superscript: bool,

    /// Syntax highlighting for codefence blocks. Choose a theme or 'none' for disabling.
    // #[arg(long, value_name = "THEME", default_value = "base16-ocean.dark")]
    // syntax_highlighting: String,

    /// Enable 'table' extension
    #[arg(long)]
    table: bool,

    /// Enable 'tasklist' extension
    #[arg(long)]
    tasklist: bool,

    /// Output classes on tasklist elements so that they can be styled with CSS
    #[arg(long)]
    tasklist_classes: bool,

    /// Enables parsing tasklist items within tables when they're the only content of a table cell
    #[arg(long)]
    tasklist_in_table: bool,

    /// Enables underlines using double underscores
    #[arg(long)]
    underline: bool,

    /// Allow raw HTML and dangerous URLs
    #[arg(long)]
    r#unsafe: bool,

    /// Enable 'wikilink_title_after_pipe' extension
    #[arg(long)]
    wikilinks_title_after_pipe: bool,

    /// Enable 'wikilink_title_before_pipe' extension
    #[arg(long)]
    wikilinks_title_before_pipe: bool,
}

fn main() {
    let mut s: Vec<u8> = Vec::with_capacity(2048);
    let cli = Args::parse();

    match cli.file {
        None => {
            std::io::stdin().read_to_end(&mut s).unwrap();
        }
        Some(fs) => {
            s = std::fs::read(fs).unwrap();
        }
    };

    let source = String::from_utf8_lossy(&s);
    let options = RenderOptions {
        alerts: cli.alerts,
        autolink: cli.autolink,
        cjk_friendly_emphasis: cli.cjk_friendly_emphasis,
        // default_info_string:
        default_html: cli.default_html,
        description_lists: cli.description_lists,
        escape: cli.escape,
        escaped_char_spans: cli.escaped_char_spans,
        figure_with_caption: cli.figure_with_caption,
        footnotes: cli.footnotes,
        // front_matter_delimiter:
        full_info_string: cli.full_info_string,
        gemojis: cli.gemojis,
        gfm_quirks: cli.gfm_quirks,
        github_pre_lang: cli.github_pre_lang,
        greentext: cli.greentext,
        hardbreaks: cli.hardbreaks,
        header_accessibility: cli.header_accessibility,
        header_id_prefix: cli.header_id_prefix,
        header_id_prefix_in_href: cli.header_id_prefix_in_href,
        header_slug_prefix: cli.header_slug_prefix,
        ignore_empty_links: cli.ignore_empty_links,
        ignore_setext: cli.ignore_setext,
        inapplicable_tasks: cli.inapplicable_tasks,
        math_code: cli.math_code,
        math_dollars: cli.math_dollars,
        multiline_block_quotes: cli.multiline_block_quotes,
        only_escape_chars: cli.only_escape_chars.map(|s| s.chars().collect()),
        placeholder_detection: cli.placeholder_detection,
        relaxed_autolinks: cli.relaxed_autolinks,
        relaxed_tasklist_character: cli.relaxed_tasklist_character,
        smart: cli.smart,
        sourcepos: cli.sourcepos,
        spoiler: cli.spoiler,
        strikethrough: cli.strikethrough,
        subscript: cli.subscript,
        superscript: cli.superscript,
        // syntax_highlighting:
        table: cli.table,
        tasklist: cli.tasklist,
        tasklist_classes: cli.tasklist_classes,
        tasklist_in_table: cli.tasklist_in_table,
        underline: cli.underline,
        r#unsafe: cli.r#unsafe,
        wikilinks_title_after_pipe: cli.wikilinks_title_after_pipe,
        wikilinks_title_before_pipe: cli.wikilinks_title_before_pipe,
    };

    let result = render(&source, &options);

    if let Some(output_filename) = cli.output {
        std::fs::write(output_filename, &result).unwrap();
    } else {
        std::io::stdout().write_all(result.as_bytes()).unwrap();
    };
}
