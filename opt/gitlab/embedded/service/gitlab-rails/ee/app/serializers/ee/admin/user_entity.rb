# frozen_string_literal: true

module EE
  module Admin
    module UserEntity
      extend ActiveSupport::Concern

      prepended do
        expose :oncall_schedules,
          with: ::IncidentManagement::OncallScheduleEntity,
          if: ->(_user, _) { can?(current_user, :read_incident_management_oncall_schedule, :global) }
        expose :escalation_policies,
          with: ::IncidentManagement::EscalationPolicyEntity,
          if: ->(_user, _) { can?(current_user, :read_incident_management_escalation_policy, :global) }
      end
    end
  end
end
