# frozen_string_literal: true

module CloudConnector
  module StatusChecks
    module Probes
      module FoundationalFlows
        class AllowFlowExecutionProbe < BaseProbe
          extend ::Gitlab::Utils::Override

          validate :check_setting_enabled

          private

          override :success_message
          def success_message
            _('The allow flow execution setting is enabled.')
          end

          def check_setting_enabled
            return if ::Gitlab::CurrentSettings.duo_remote_flows_enabled

            errors.add(:base, _('The allow flow execution setting is disabled.'))
          end
        end
      end
    end
  end
end
