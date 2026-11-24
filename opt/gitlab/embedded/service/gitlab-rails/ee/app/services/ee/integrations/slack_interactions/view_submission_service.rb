# frozen_string_literal: true

module EE
  module Integrations
    module SlackInteractions
      module ViewSubmissionService
        extend ::Gitlab::Utils::Override

        EE_HANDLERS = {
          ::Integrations::SlackInteractions::DuoFeedbackModal::CALLBACK_ID =>
            ::Integrations::SlackInteractions::DuoFeedbackModalSubmitService
        }.freeze

        private

        override :handlers
        def handlers
          super.merge(EE_HANDLERS)
        end
      end
    end
  end
end
