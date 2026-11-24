# frozen_string_literal: true

module Gitlab
  module Llm
    module VertexAi
      module ModelConfigurations
        class Text < Base
          NAME = ::Gitlab::Llm::Concerns::AvailableModels::VERTEX_MODEL_TEXT

          def payload(content)
            {
              instances: [
                {
                  content: content
                }
              ],
              parameters: Configuration.payload_parameters
            }
          end

          def as_json(opts = nil)
            super.merge(Configuration.payload_parameters)
          end
        end
      end
    end
  end
end
