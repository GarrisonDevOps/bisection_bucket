# frozen_string_literal: true

module Projects
  module ComplianceStandards
    class AdherencePolicy < BasePolicy
      condition(:has_access_to_adherence_on_group) do
        Ability.allowed?(@user, :read_compliance_adherence_report, @subject.project.namespace)
      end

      condition(:has_access_to_adherence_on_project) do
        Ability.allowed?(@user, :read_compliance_adherence_report, @subject.project)
      end

      rule { has_access_to_adherence_on_group | has_access_to_adherence_on_project }.policy do
        enable :read_compliance_adherence_report
      end
    end
  end
end
