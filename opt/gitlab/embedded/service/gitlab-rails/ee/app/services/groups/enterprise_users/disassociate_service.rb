# frozen_string_literal: true

module Groups
  module EnterpriseUsers
    class DisassociateService < BaseService
      include Groups::EnterpriseUsers::Associable

      def initialize(user:)
        @user = user
        @group = @user.user_detail.enterprise_group
      end

      def execute
        return error('The user is not an enterprise user') unless group

        if user_matches_the_enterprise_user_definition_for_the_group?(group)
          return error('The user matches the "Enterprise User" definition for the group')
        end

        # Allows the raising of persistent failure and enables it to be retried when called from inside sidekiq.
        # see https://gitlab.com/gitlab-org/gitlab/-/merge_requests/130735#note_1550114699
        disassociate_user_personal_access_tokens_from_group
        @user.user_detail.update!(enterprise_group_id: nil, enterprise_group_associated_at: nil)

        log_info(message: 'Disassociated the user from the enterprise group')

        success
      end

      private

      def disassociate_user_personal_access_tokens_from_group
        user.personal_access_tokens.each_batch(of: 100) do |personal_access_tokens_batch|
          personal_access_tokens_batch.update_all(group_id: nil)
        end
      end
    end
  end
end
