# frozen_string_literal: true

module EE
  module PersonalAccessTokenPolicy # rubocop:disable Gitlab/BoundedContexts -- Existing policy with EE extension.
    extend ActiveSupport::Concern

    prepended do
      condition(:is_enterprise_user_manager) do
        user && subject.user.managed_by_group?(subject.user.enterprise_group) &&
          can?(:update_enterprise_user, subject.user.enterprise_group)
      end
      condition(:group_credentials_inventory_available) do
        ::Gitlab::Saas.feature_available?(:group_credentials_inventory)
      end

      rule { is_enterprise_user_manager & group_credentials_inventory_available }.policy do
        enable :revoke_personal_access_token
        enable :rotate_personal_access_token
      end
    end
  end
end
