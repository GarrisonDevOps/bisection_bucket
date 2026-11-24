# frozen_string_literal: true

module EE
  module Gitlab
    module WebHooks
      module DuoFlowCallback
        extend ::Gitlab::Utils::Override

        private

        override :duo_agent_platform_available?
        def duo_agent_platform_available?(container)
          ::Ai::DuoWorkflow.duo_agent_platform_available?(container)
        end
      end
    end
  end
end
