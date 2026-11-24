# frozen_string_literal: true

module CloudConnector
  module StatusChecks
    module Probes
      module FoundationalFlows
        class AllowFoundationalFlowsProbe < BaseProbe
          extend ::Gitlab::Utils::Override

          validate :check_setting_enabled

          private

          override :success_message
          def success_message
            _('The allow foundational flows setting is enabled.')
          end

          def check_setting_enabled
            return if ::Gitlab::CurrentSettings.duo_foundational_flows_enabled

            errors.add(:base, _('The allow foundational flows setting is disabled.'))
          end
        end
      end
    end
  end
end
