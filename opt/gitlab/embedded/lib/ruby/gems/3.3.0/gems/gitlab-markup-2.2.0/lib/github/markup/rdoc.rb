require "github/markup/implementation"
require "rdoc"
require "rdoc/markup/to_html"

module GitHub
  module Markup
    class RDoc < Implementation
      def initialize
        super /rdoc/
      end

      def render(content)
        # RDoc 8 changed ToHtml.new to take keyword arguments instead of
        # an RDoc::Options instance.
        h = if ::RDoc::VERSION.to_i >= 8
              ::RDoc::Markup::ToHtml.new
            else
              ::RDoc::Markup::ToHtml.new(::RDoc::Options.new)
            end
        h.convert(content)
      end

      def name
        "rdoc"
      end
    end
  end
end
