# frozen_string_literal: true

module Geo
  module Console
    # An Action is a Choice that runs execute and then immediately opens its referer.
    class Action < Choice
      def open
        @output_stream.puts "\n#{header}\n"

        begin
          suppress_debug_logs_in_development do
            execute
          end
        rescue StandardError => e
          @output_stream.puts e.message
          @output_stream.puts e.backtrace.join("\n")
          raise
        end

        @referer&.open
      end

      def execute
        raise NotImplementedError, "#{self.class} must implement ##{__method__}"
      end

      private

      def suppress_debug_logs_in_development
        return yield unless development?

        level = Rails.logger.level
        Rails.logger.level = :info if level == 0

        begin
          result = yield
        ensure
          Rails.logger.level = 0 if level == 0
        end

        result
      end

      def development?
        Rails.env.development?
      end
    end
  end
end
