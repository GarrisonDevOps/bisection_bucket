# frozen_string_literal: true

module Groups
  module EnterpriseUsers
    class AssociateWorker
      include ApplicationWorker
      include Groups::EnterpriseUsers::Associable

      idempotent!
      feature_category :user_management
      data_consistency :sticky
      concurrency_limit -> { 100 }

      def perform(user_id)
        @user = User.find_by_id(user_id)
        return unless user
        return unless enterprise_group_eligible?

        Groups::EnterpriseUsers::AssociateService.new(group: enterprise_group, user: user).execute
      end

      private

      attr_reader :user
    end
  end
end
