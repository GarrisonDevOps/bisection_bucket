# frozen_string_literal: true

module ComplianceManagement
  class PiplUserPolicy < BasePolicy
    condition(:enforce_pipl_compliance) do
      ::Gitlab::CurrentSettings.enforce_pipl_compliance?
    end

    rule { admin & enforce_pipl_compliance }.policy do
      enable :block_pipl_user
      enable :delete_pipl_user
    end
  end
end
