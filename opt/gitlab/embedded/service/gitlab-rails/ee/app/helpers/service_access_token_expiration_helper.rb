# frozen_string_literal: true

module ServiceAccessTokenExpirationHelper
  def can_change_service_access_tokens_expiration?(current_user, group)
    group&.root? && can?(current_user, :admin_service_accounts, group)
  end
end
