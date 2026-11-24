# frozen_string_literal: true

require_relative 'untrusted_regexp'

module Slack
  class Messenger
    module Util
      class LinkFormatter
        # https://regex101.com/r/m7CTcW/1
        HTML_PATTERN =
          '<a' \
            '(?:.*?)' \
            'href=[\'"](?P<link>.+?)[\'"]' \
          '(?:.*?)>' \
            '(?P<text>.+?)' \
          '</a>'

        VALID_URI_CHARS = '\w\-\.\~\:\/\?\#\[\]\@\!\$\&\'\*\+\,\;\='

        # Attempt at only matching pairs of parens per
        # the markdown spec http://spec.commonmark.org/0.27/#links
        # https://regex101.com/r/komyFe/1
        MARKDOWN_PATTERN =
          '\[' \
            '(?P<text>[^\[\]]*?)' \
          '\]' \
          '\(' \
            '(?P<link>' \
              '(?:https?:\/\/|mailto:)' \
              "(?:[#{VALID_URI_CHARS}]*?|[#{VALID_URI_CHARS}]*?\\([#{VALID_URI_CHARS}]*?\\)[#{VALID_URI_CHARS}]*?)" \
            ')' \
          '\)'

        HTML_REGEXP = UntrustedRegexp.new(HTML_PATTERN, multiline: true)
        MARKDOWN_REGEXP = UntrustedRegexp.new(MARKDOWN_PATTERN, multiline: true)

        class << self
          def format string, **opts
            LinkFormatter.new(string, **opts).formatted
          end
        end

        attr_reader :formats

        def initialize string, formats: %i[html markdown]
          @formats = formats
          @orig    = string.respond_to?(:scrub) ? string.scrub : string
        end

        # rubocop:disable Lint/RescueWithoutErrorClass
        def formatted
          return @orig unless @orig.respond_to?(:gsub)

          sub_markdown_links(sub_html_links(@orig))
        rescue => e
          raise e unless RUBY_VERSION < "2.1" && e.message.include?("invalid byte sequence")
          raise e, "#{e.message}. Consider including the 'string-scrub' gem to strip invalid characters"
        end
        # rubocop:enable Lint/RescueWithoutErrorClass

        private

        def sub_html_links string
          return string unless formats.include?(:html)

          HTML_REGEXP.replace_gsub(string) do |html_link|
            slack_link(html_link[1], html_link[2])
          end
        end

        def sub_markdown_links string
          return string unless formats.include?(:markdown)

          MARKDOWN_REGEXP.replace_gsub(string) do |markdown_link|
            slack_link(markdown_link[2], markdown_link[1])
          end
        end

        def slack_link link, text=nil
          "<#{link}" \
          "#{text && !text.empty? ? "|#{text}" : ''}" \
          ">"
        end
      end
    end
  end
end
