# frozen_string_literal: true

module Gitlab
  module Llm
    module Chain
      module Parsers
        class ChainOfThoughtParser < OutputParser
          attr_reader :action, :action_input, :thought, :final_answer

          def parse
            unless duo_chat_feature_setting&.self_hosted?
              @output = Utils::TextProcessing.text_before_stop_word(output) || output
            end

            parse_action
            parse_action_input
            parse_thought
            parse_final_answer

            # this should be last (fallback) step after all parsing is done
            final_answer_from_unformatted_response
          end

          private

          # Match the first occurrence of "Action: " and capture everything until "Action Input"
          def parse_action
            /Action:(?<action>.+?)(?=Action Input:|Final Answer:)/m =~ output

            @action = action&.strip
          end

          # Match the first occurrence of "Action Input: " and capture everything until:
          # - "Observation" if it's present
          # - "Final Answer" if it's present
          # - End of string
          def parse_action_input
            /(?<=Action Input:)(?<action_input>.*?)(?=Observation|Final Answer|\z)/m =~ output

            @action_input = action_input&.strip
          end

          # If the whole output contains only keywords, the thought is empty
          # Match everything before "Action:" or "Final Answer:" and remove
          # everything before and including "Thought: " if it's present
          def parse_thought
            return if 'Thought: Action:' == output.to_s.strip

            /^(?<thought>.*?)(?=Action:|Final Answer:)/m =~ output

            @thought = thought&.sub(/.*Thought:/m, '')&.strip
          end

          # Match the first occurrence of "Final Answer: " and capture everything
          def parse_final_answer
            /Final Answer:(?<final_answer>.+)/m =~ output

            @final_answer = final_answer&.strip
          end

          # if response doesn't follow expected format, it usually means it's
          # a final answer (although there is a risk of hallucination). Such
          # response is treated as final response instead of returning "I
          # don't know"
          def final_answer_from_unformatted_response
            return if action.present? || action_input.present? || thought.present? || final_answer.present?

            answer = output.to_s.strip.sub(/\AThought:\s*/, '')
            answer = answer.sub(/\AAction: DirectAnswer\s*/, '')
            answer = answer.sub(/\AAction:\s*/, '')

            return if answer.empty?

            @final_answer = answer
          end

          def duo_chat_feature_setting
            ::Ai::FeatureSetting.find_by_feature(:duo_chat)
          end
        end
      end
    end
  end
end
