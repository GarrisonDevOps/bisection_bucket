# frozen_string_literal: true

module Slack
  class Messenger
    module Util
      module Escape
        HTML_REGEXP  = /[&><]/
        HTML_REPLACE = { "&" => "&amp;", ">" => "&gt;", "<" => "&lt;" }.freeze

        def self.html string
          string.gsub(HTML_REGEXP, HTML_REPLACE)
        end
      end
    end
  end
end
