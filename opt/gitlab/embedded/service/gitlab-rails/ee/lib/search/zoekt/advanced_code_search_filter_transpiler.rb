# frozen_string_literal: true

module Search
  module Zoekt
    class AdvancedCodeSearchFilterTranspiler
      ADVANCED_CODE_SEARCH_FILTERS = %w[extension filename path].freeze

      def initialize(filter)
        @filter = filter
        @filter_name, @filter_value = filter.sub(/^-/, '').split(':', 2)
      end

      def transpile
        return filter if ADVANCED_CODE_SEARCH_FILTERS.exclude?(filter_name)

        negation = filter.start_with?('-') ? '-' : ''
        escaped_value = RE2::Regexp.escape(filter_value.strip)
        case filter_name
        when 'extension'
          "#{negation}file:\\.#{escaped_value}$"
        when 'filename'
          regex_value = escaped_value.gsub('\*', '[^/]*').gsub('\?', '[^/]')
          "#{negation}file:(^|/)#{regex_value}$"
        else # path
          regex_value = escaped_value.gsub('\*', '.*').gsub('\?', '.')
          "#{negation}file:(?:^|/)#{regex_value}"
        end
      end

      private

      attr_reader :filter, :filter_name, :filter_value
    end
  end
end
