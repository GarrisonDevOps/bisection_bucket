# frozen_string_literal: true

module Gitlab
  module Llm
    module Utils
      class CodeSuggestionFormatter
        PROMPT =
          <<~MESSAGE.chomp
            When you are responding with a code suggestion, format your code suggestion as follows:
              - Use the following format:
                <from>
                  [existing lines that you are suggesting to change]
                </from>
                <to>
                  [your suggestion]
                </to>
                - <from> tag must be identical to the lines as they appear in the diff, including any leading spaces or tabs
                - <to> tag must contain your suggestion
                - Opening and closing `<from>` and `<to>` tags should not be on the same line as the content
                - When making suggestions, always maintain the exact indentation as shown in the original diff. The suggestion should match the indentation of the line you are commenting on precisely, as it will be applied directly in place of the existing line.
                - Do note that you are given a raw diff so you must parse the raw diff before using them in your suggestion:
                  - Remove the first character of each line ('+', '-', or ' ') as it's part of the diff syntax, not the actual code.
                  - Use the remaining content for your suggestion, maintaining the original indentation.
          MESSAGE

        # NOTE: We might get multiple code suggestions on the same line as that's still valid so we should take
        #   that possibility of extra `<from>` into account here.
        #   Also, sometimes LLM returns tags inline like `<to>  some text</to>` for single line suggestions which
        #   we need to handle as well just in case.
        CODE_SUGGESTION_REGEX =
          %r{(.*?)^(?:<from>\n(.*?)^</from>\n<to>\n(.*?)^</to>|<from>(.+?)</from>\n<to>(.+?)</to>)(.*?)(?=<from>|\z)}m

        def self.append_prompt(body)
          return '' if body.blank?

          [body, PROMPT].join("\n\n") # Leave an empty line in between for clarity
        end

        def self.parse(body)
          return { body: '' } if body.blank?

          body_with_suggestions = body
            .scan(CODE_SUGGESTION_REGEX)
            .map do |header, multiline_from, multiline_to, inline_from, inline_to, footer|
              from = multiline_from || inline_from
              to = multiline_to || inline_to

              next { body: "#{header}#{footer}", from: from } if from == to

              {
                body: "#{header}#{suggestion_block(from, to)}#{footer}",
                from: from
              }
            end

          # NOTE: Return original body if the body doesn't have any expected suggestion format.
          return { body: body } unless body_with_suggestions.present?

          # NOTE: It's unlikely that we have multiple suggestions within the same review comment,
          #   but when it does we expect the content of <from> start from the same line so we just take the first one.

          # rubocop:disable CodeReuse/ActiveRecord -- Not an activerecord object
          { body:  body_with_suggestions.pluck(:body).join, from: body_with_suggestions.first[:from] }
          # rubocop:enable CodeReuse/ActiveRecord
        end

        # The offset counts the existing lines being replaced, which the LLM cannot set
        # reliably itself. An empty `to` stays empty so the suggestion deletes the lines.
        def self.suggestion_block(from, to, span = from.lines.count)
          line_offset_below = span - 1
          to = "#{to}\n" unless to.empty? || to.end_with?("\n")

          "```suggestion:-0+#{line_offset_below}\n#{to}```"
        end
      end
    end
  end
end
