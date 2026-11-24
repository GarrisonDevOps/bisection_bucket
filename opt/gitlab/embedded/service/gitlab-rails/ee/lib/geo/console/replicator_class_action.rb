# frozen_string_literal: true

module Geo
  module Console
    class ReplicatorClassAction < Action
      def initialize(replicator_class:, referer: nil, input_stream: $stdin, output_stream: $stdout)
        @input_stream = input_stream
        @output_stream = output_stream
        @referer = referer
        @replicator_class = replicator_class
      end

      private

      def get_limit_from_user(default:)
        @output_stream.puts "How many results would you like to see? (max 1000)"
        @output_stream.puts "Enter a number (1-1000) or press enter to show the default of #{default}:"

        user_input = @input_stream.gets.chomp
        limit = user_input.to_i.between?(1, 1000) ? user_input.to_i : default

        @output_stream.puts "You entered: #{user_input}"
        @output_stream.puts "Using limit of: #{limit}"
        @output_stream.puts ""

        limit
      end
    end
  end
end
