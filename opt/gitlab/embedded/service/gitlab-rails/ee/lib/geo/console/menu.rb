# frozen_string_literal: true

module Geo
  module Console
    # A Menu is a Choice that prompts for user answer and then acts on it.
    class Menu < Choice
      def name
        self.class.name
      end

      def open
        @output_stream.puts "\n#{header}\n"
        @output_stream.print prompt.strip
        @output_stream.print " "
        @answer = get_answer(@input_stream)
        act_on_answer(@answer, @output_stream)
      end

      private

      def prompt
        raise NotImplementedError, "#{self.class} must implement ##{__method__}"
      end

      def get_answer(input_stream)
        input_stream.gets.chomp
      end

      def act_on_answer(answer, output_stream)
        output_stream.puts "You entered: #{answer}"
      end

      def next_choice_args
        { input_stream: @input_stream, output_stream: @output_stream, referer: self }
      end
    end
  end
end
