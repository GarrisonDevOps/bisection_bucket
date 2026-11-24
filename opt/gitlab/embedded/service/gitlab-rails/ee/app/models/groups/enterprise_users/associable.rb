# frozen_string_literal: true

module Groups # rubocop:disable Gitlab/BoundedContexts -- Already existing module where other enterprise users code lives.
  module EnterpriseUsers
    module Associable
      include ::Gitlab::Utils::StrongMemoize

      private

      def user_eligible_or_already_enterprise_user?
        return true if user.enterprise_user?
        return false unless enterprise_group_eligible?

        user_matches_the_enterprise_user_definition_for_the_group?(enterprise_group)
      end

      def user_email_pages_domain
        PagesDomain.verified.find_by_domain_case_insensitive(user.email_domain)
      end
      strong_memoize_attr :user_email_pages_domain

      def enterprise_group
        user_email_pages_domain&.root_group
      end

      def enterprise_group_eligible?
        enterprise_group.present?
      end

      def user_was_created_2021_02_01_or_later?
        user.created_at >= Date.new(2021, 2, 1)
      end

      def user_has_saml_or_scim_identity_tied_to_group?(local_group)
        local_group.saml_provider&.identities&.for_user(user)&.exists? ||
          local_group.scim_identities.for_user(user).exists?
      end

      def user_provisioned_by_group?(local_group)
        user.provisioned_by_group_id == local_group.id
      end

      def user_group_member_and_group_subscription_was_purchased_or_renewed_2021_02_01_or_later?(local_group)
        local_group.member?(user) && local_group.paid? &&
          local_group.gitlab_subscription.start_date >= Date.new(2021, 2, 1)
      end

      # The "Enterprise User" definition: https://handbook.gitlab.com/handbook/support/workflows/gitlab-com_overview/#enterprise-users
      #
      # Only include human users to avoid claiming service accounts, project bots, and other user types
      # as enterprise users, even when they have a custom email address matching the domain.
      # See https://gitlab.com/gitlab-org/gitlab/-/issues/451032
      def user_matches_the_enterprise_user_definition_for_the_group?(local_group)
        user.human? && local_group.owner_of_email?(user.email) &&
          (
            user_was_created_2021_02_01_or_later? ||
            user_has_saml_or_scim_identity_tied_to_group?(local_group) ||
            user_provisioned_by_group?(local_group) ||
            user_group_member_and_group_subscription_was_purchased_or_renewed_2021_02_01_or_later?(local_group)
          )
      end
    end
  end
end
