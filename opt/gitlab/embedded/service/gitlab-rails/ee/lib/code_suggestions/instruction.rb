# frozen_string_literal: true

module CodeSuggestions
  class Instruction
    SMALL_FILE_INSTRUCTION = <<~PROMPT
      Create more new code for this file. If the cursor is inside an empty function,
      generate its most likely contents based on the function name and signature.
    PROMPT

    EMPTY_FUNCTION_INSTRUCTION = <<~PROMPT
      Complete the empty function and generate contents based on the function name and signature.
      Do not repeat the code. Only return the method contents.
    PROMPT

    COMMENT_TRIGGER = 'comment'
    EMPTY_FUNCTION_TRIGGER = 'empty_function'
    SMALL_FILE_TRIGGER = 'small_file'
    GENERATION_TRIGGER_TYPES = [COMMENT_TRIGGER, EMPTY_FUNCTION_TRIGGER, SMALL_FILE_TRIGGER].freeze

    attr_reader :trigger_type, :instruction

    def self.from_trigger_type(trigger_type)
      instruction =
        case trigger_type
        when EMPTY_FUNCTION_TRIGGER
          EMPTY_FUNCTION_INSTRUCTION
        when SMALL_FILE_TRIGGER
          SMALL_FILE_INSTRUCTION
        when COMMENT_TRIGGER
          ''
        else
          raise ArgumentError, "Unknown trigger type #{trigger_type}"
        end

      new(trigger_type: trigger_type, instruction: instruction)
    end

    def initialize(trigger_type: nil, instruction: nil)
      @trigger_type = trigger_type
      @instruction = instruction
    end
  end
end
