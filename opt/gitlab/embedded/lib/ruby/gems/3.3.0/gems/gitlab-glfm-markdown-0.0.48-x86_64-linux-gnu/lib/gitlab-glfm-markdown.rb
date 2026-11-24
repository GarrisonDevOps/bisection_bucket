# frozen_string_literal: true

require_relative 'gitlab_glfm_markdown/version'
require_relative 'gitlab_glfm_markdown/loader'

load_rust_extension

module GLFMMarkdown
  GLFM_DEFAULT_OPTIONS = {
    autolink: true,
    cjk_friendly_emphasis: true,
    escaped_char_spans: false,
    footnotes: true,
    full_info_string: true,
    gfm_quirks: true,
    github_pre_lang: false,
    hardbreaks: false,
    inapplicable_tasks: false,
    math_code: false,
    math_dollars: false,
    multiline_block_quotes: true,
    relaxed_autolinks: false,
    sourcepos: true,
    smart: false,
    strikethrough: true,
    table: true,
    tasklist: true,
    tasklist_classes: true,
    unsafe: true
  }.freeze

  class << self
    def to_html(markdown, options: {})
      raise TypeError, 'markdown must be a String' unless markdown.is_a?(String)
      raise TypeError, 'markdown must be UTF-8 encoded' unless markdown.encoding == Encoding::UTF_8
      raise TypeError, 'options must be a Hash' unless options.is_a?(Hash)

      default_options = options[:glfm] ? GLFM_DEFAULT_OPTIONS : {}

      render_to_html_rs(markdown, default_options.merge(options))
    end

    def escape_commonmark_inline(text)
      raise TypeError, 'text must be a String' unless text.is_a?(String)
      raise TypeError, 'text must be UTF-8 encoded' unless text.encoding == Encoding::UTF_8

      escape_commonmark_inline_rs(text)
    end

    def escape_commonmark_link_destination(url)
      raise TypeError, 'url must be a String' unless url.is_a?(String)
      raise TypeError, 'url must be UTF-8 encoded' unless url.encoding == Encoding::UTF_8

      escape_commonmark_link_destination_rs(url)
    end
  end
end
