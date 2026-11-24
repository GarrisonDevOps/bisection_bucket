# frozen_string_literal: true

module Analytics
  module Orbit
    class GrepLlmFormatter
      def initialize(grep)
        @grep = grep
      end

      def execute
        scope_names = grep[:scopes].map { |scope| scope.fetch(:name) }.join(',')
        lines = [
          "orbit_grep version=#{grep[:version]} target=#{grep.dig(:target, :token)} " \
            "search=#{format_value(grep.dig(:request, :search))} " \
            "scopes=#{format_value(scope_names)} results=#{grep[:result_count]} " \
            "truncated=#{grep[:truncated]}"
        ]
        grep[:results].each { |result| lines << format_result(result) }
        grep[:scopes].each do |scope|
          next if scope[:status] == 'ok'

          lines << "! #{scope[:status]} scope=#{scope[:name]} reason=#{scope.dig(:reason, :code)}"
        end
        lines.join("\n") << "\n"
      end

      private

      attr_reader :grep

      def format_result(result)
        identity = result[:token] || "#{result[:type]} #{format_fields(result[:reference])}"
        details = result[:token] ? result[:reference].except(:id) : {}
        details = format_fields(details.merge(result.slice(:state)))

        ["- #{identity}", "type=#{result[:type]}", details.presence, "text=#{format_value(result[:text])}"]
          .compact.join(' ')
      end

      def format_fields(fields)
        fields.compact.map { |key, value| "#{key}=#{format_value(value)}" }.join(' ')
      end

      def format_value(value)
        Gitlab::Json.generate(value.to_s)
      end
    end
  end
end
