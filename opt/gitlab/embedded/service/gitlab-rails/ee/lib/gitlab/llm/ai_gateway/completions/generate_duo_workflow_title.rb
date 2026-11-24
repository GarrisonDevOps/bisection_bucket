# frozen_string_literal: true

module Gitlab
  module Llm
    module AiGateway
      module Completions
        class GenerateDuoWorkflowTitle < Base
          extend ::Gitlab::Utils::Override

          override :inputs
          def inputs
            options.slice(:context, :definition)
          end

          override :prompt_name
          def prompt_name
            'generate_session_title'
          end

          override :root_namespace
          def root_namespace
            resource.try(:root_ancestor)
          end

          private

          override :unit_primitive_name
          def unit_primitive_name
            :duo_agent_platform
          end
        end
      end
    end
  end
end
