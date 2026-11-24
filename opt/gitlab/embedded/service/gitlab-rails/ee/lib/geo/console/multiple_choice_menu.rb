# frozen_string_literal: true

module Geo
  module Console
    # A MultipleChoiceMenu is a Menu that prompts for a number and then opens the Choice at that
    # index.
    #
    # The indexes are 1-based.
    # If a referer is provided, it is added to the list of choices as the last choice.
    class MultipleChoiceMenu < Menu
      private

      def prompt
        result = ""
        total_choices.each.with_index do |choice, index|
          result += "#{index + 1}) #{'Back to ' if choice == @referer}#{choice.name}\n"
        end

        result + <<~PROMPT

          What would you like to do?
          Enter a number:
        PROMPT
      end

      def total_choices
        result = (choices + [@referer]).compact
        raise "No choices found for #{self.class.name}" if result.empty?

        result
      end

      def choices
        raise NotImplementedError, "#{self.class} must implement ##{__method__}"
      end

      def act_on_answer(answer, output_stream)
        super

        choice = get_choice(total_choices, answer, output_stream)
        return open_choice(self) unless choice

        output_stream.puts "You chose: #{choice.name}"
        open_choice(choice)
      end

      def get_choice(choices, answer, output_stream)
        answer_number = answer.to_i
        max_allowed = choices.size + 1
        valid = (1..(max_allowed)).cover?(answer_number)

        unless valid
          output_stream.puts "Choice not found. Please try again."
          return
        end

        index = answer_number - 1
        choices.at(index)
      end

      def open_choice(choice)
        choice.open
      end
    end
  end
end
