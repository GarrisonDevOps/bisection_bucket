# frozen_string_literal: true

module Gitlab
  module MarkdownCache
    # Knows about the relationship between markdown and html field names, and
    # stores the rendering contexts for the latter
    class FieldData
      def initialize
        @data = {}
        @invalidated_by = {}
        @conditions = {}
      end

      delegate :[], :key?, to: :@data

      def []=(markdown_field, context)
        @invalidated_by[markdown_field] = context.fetch(:invalidated_by, []).map(&:to_s)
        @conditions[markdown_field] = context.fetch(:if, ->(**) { true })
        @data[markdown_field] = context.except(:invalidated_by, :if)
      end

      def invalidated_by(markdown_field)
        @invalidated_by.fetch(markdown_field)
      end

      def condition(markdown_field)
        @conditions.fetch(markdown_field)
      end

      def markdown_fields
        @data.keys
      end

      def html_field(markdown_field)
        "#{markdown_field}_html"
      end

      def html_fields
        @html_fields ||= markdown_fields.map { |field| html_field(field) }
      end

      def html_fields_whitelisted
        markdown_fields.each_with_object([]) do |field, fields|
          if @data[field].fetch(:whitelisted, false)
            fields << html_field(field)
          end
        end
      end
    end
  end
end
