# frozen_string_literal: true

module Gitlab
  module Llm
    module VertexAi
      module ModelConfigurations
        class CodeCompletion < Base
          NAME = 'code-gecko'
          MAX_OUTPUT_TOKENS = 64

          def payload(content)
            {
              instances: [
                {
                  content_above_cursor: content[:content_above_cursor],
                  content_below_cursor: content[:content_below_cursor]
                }
              ],
              parameters: Configuration.payload_parameters(maxOutputTokens: MAX_OUTPUT_TOKENS)
            }
          end

          def as_json(opts = nil)
            super.merge(Configuration.payload_parameters(maxOutputTokens: MAX_OUTPUT_TOKENS))
          end
        end
      end
    end
  end
end
