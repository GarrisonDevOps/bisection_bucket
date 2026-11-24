# frozen_string_literal: true

module Gitlab
  module Llm
    module AiGateway
      module Completions
        class UpdateDescriptionFromDecision < Base
          extend ::Gitlab::Utils::Override

          override :inputs
          def inputs
            options.slice(:title, :description, :question, :options, :answer, :rationale)
          end

          override :root_namespace
          def root_namespace
            resource.try(:root_ancestor)
          end

          override :namespace_id
          def namespace_id
            resource.try(:namespace_id)
          end

          override :project_id
          def project_id
            resource.try(:project_id)
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
