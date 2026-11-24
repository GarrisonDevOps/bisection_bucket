# frozen_string_literal: true

# rubocop:disable Scalability/IdempotentWorker -- Worker triggers email so cannot be considered idempotent.
module Members
  module Groups
    class BaseMembershipsExportWorker
      include ApplicationWorker

      sidekiq_options retry: true
      feature_category :compliance_management
      data_consistency :sticky

      def perform(group_id, current_user_id)
        @group = ::Group.find_by_id(group_id)
        @current_user = ::User.find_by_id(current_user_id)
        @response = process_import

        send_email if @response.success?
      end

      private

      def send_email
        Notify.memberships_export_email(
          csv_data: @response.payload,
          requested_by: @current_user,
          group: @group
        ).deliver_later
      end
    end
  end
end
# rubocop:enable Scalability/IdempotentWorker
