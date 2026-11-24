# frozen_string_literal: true

module CodeSuggestions
  class InstructionsExtractor
    INTENT_COMPLETION = 'completion'
    INTENT_GENERATION = 'generation'

    # Regex is looking for something that looks like a _single line_ code comment.
    # It looks for at least 10 characters afterwards.
    # It is case-insensitive.
    # It searches for the last instance of a match by looking for the end
    # of a text block and an optional line break.
    # `{10}[^\r\n]*` rather than `{10,}`, and no `[ \t]*` before it: Onigmo can then memoize
    # failed positions, so a long line that fails near its end is matched in linear time.
    FIRST_COMMENT_REGEX = "(?<comment>%{comment_format})(?<instruction>[^\\r\\n]{10}[^\\r\\n]*)\\s*\\Z"
    ALWAYS_GENERATE_CONTENT_ABOVE_CURSOR = %r{.*?}

    EMPTY_LINES_LIMIT = 1

    def initialize(file_content, intent, generation_type = nil, user_instruction = nil)
      @file_content = file_content
      @language = file_content.language
      @intent = intent
      @generation_type = generation_type
      @user_instruction = user_instruction
    end

    def extract
      return if intent == INTENT_COMPLETION

      return Instruction.new(instruction: user_instruction) if user_instruction.present?

      type = instruction_type
      return unless type

      Instruction.from_trigger_type(type)
    end

    private

    attr_reader :language, :file_content, :intent, :generation_type, :user_instruction

    def comment(lines)
      comment_block = []
      trimmed_lines = 0

      lines.reverse_each do |line|
        next trimmed_lines += 1 if trimmed_lines < EMPTY_LINES_LIMIT && comment_block.empty? && line.strip.empty?
        break unless language.single_line_comment?(line)

        comment_block.unshift(line)
      end

      comment_block
    end

    def instruction_type
      return generation_type if generation_type.present?

      # although new client versions will send "generation_type" parameter if intent is detected, current behavior is
      # that client sends only "intent" parameter and only when "comment" parameter is used
      return Instruction::COMMENT_TRIGGER if intent == INTENT_GENERATION

      comment_block = comment(file_content.lines_above_cursor)
      if comment_block.first&.match(first_line_regex)
        Instruction::COMMENT_TRIGGER
      elsif file_content.small?
        Instruction::SMALL_FILE_TRIGGER
      elsif language.cursor_inside_empty_function?(
        file_content.content_above_cursor, file_content.content_below_cursor)
        Instruction::EMPTY_FUNCTION_TRIGGER
      end
    end

    def first_line_regex
      return ALWAYS_GENERATE_CONTENT_ABOVE_CURSOR if intent == INTENT_GENERATION

      comment_format = language.single_line_comment_format
      Regexp.new(
        format(FIRST_COMMENT_REGEX, { comment_format: comment_format }),
        'im'
      )
    end
  end
end
