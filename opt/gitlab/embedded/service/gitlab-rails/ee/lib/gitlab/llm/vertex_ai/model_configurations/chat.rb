# frozen_string_literal: true

module Gitlab
  module Llm
    module VertexAi
      module ModelConfigurations
        class Chat < Base
          NAME = ::Gitlab::Llm::Concerns::AvailableModels::VERTEX_MODEL_CHAT

          def payload(content)
            {
              instances: [
                {
                  messages: content
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
