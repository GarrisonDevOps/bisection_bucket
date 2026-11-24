# frozen_string_literal: true

module Gitlab
  module Llm
    module AiGateway
      module Completions
        class SummarizeDuoWorkflow < Base
          extend ::Gitlab::Utils::Override

          override :inputs
          def inputs
            options.slice(:logs)
          end

          private

          # The AI Gateway prompt uses unit_primitive: duo_agent_platform, not a dedicated
          # unit primitive, so we must override the default (which would use ai_action as the UP).
          override :unit_primitive_name
          def unit_primitive_name
            :duo_agent_platform
          end
        end
      end
    end
  end
end
