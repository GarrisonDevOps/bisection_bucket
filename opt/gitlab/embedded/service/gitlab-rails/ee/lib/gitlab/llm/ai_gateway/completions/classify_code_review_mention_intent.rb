# frozen_string_literal: true

module Gitlab
  module Llm
    module AiGateway
      module Completions
        class ClassifyCodeReviewMentionIntent < Base
          extend ::Gitlab::Utils::Override

          override :inputs
          def inputs
            { message: options[:message] }.merge(options[:intent_context].to_h)
          end

          private

          override :prompt_version
          def prompt_version
            '^2.0.0' if options[:intent_context]
          end

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
