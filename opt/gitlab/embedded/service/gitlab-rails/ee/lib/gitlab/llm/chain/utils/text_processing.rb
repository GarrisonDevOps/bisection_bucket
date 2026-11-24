# frozen_string_literal: true

module Gitlab
  module Llm
    module Chain
      module Utils
        class TextProcessing
          STOP_REGEX = /Observation:/

          def self.text_before_stop_word(text, stop_word = STOP_REGEX)
            text.split(stop_word).first
          end

          def self.extract_keys(input)
            input.scan(/\[.*?\]/)
                 .map { |x| x[1..-2].delete("\"").delete("'") }
                 .map { |x| /^(\d)+$/.match?(x) ? Integer(x) : x }
          end
        end
      end
    end
  end
end
