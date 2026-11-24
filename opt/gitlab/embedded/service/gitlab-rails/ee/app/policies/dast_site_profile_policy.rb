# frozen_string_literal: true

class DastSiteProfilePolicy < BasePolicy
  delegate { @subject.project }

  # Profiles with secret variables (passwords, request headers) require
  # maintainer access to modify. Changing the target URL on a profile
  # that holds secrets can exfiltrate those secrets via CI pipeline
  # execution, so we restrict mutation to users who already have
  # broad project access.
  # See https://gitlab.com/gitlab-org/gitlab/-/issues/517659
  condition(:has_secret_variables, scope: :subject) do
    @subject.secret_variables.exists?
  end

  rule { has_secret_variables & ~can?(:admin_project) }.policy do
    prevent :create_on_demand_dast_scan
  end
end
