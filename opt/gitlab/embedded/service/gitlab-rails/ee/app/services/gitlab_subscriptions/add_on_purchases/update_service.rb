# frozen_string_literal: true

module GitlabSubscriptions
  module AddOnPurchases
    class UpdateService < ::GitlabSubscriptions::AddOnPurchases::BaseService
      extend ::Gitlab::Utils::Override

      def initialize(namespace, add_on, params = {})
        @add_on_purchase = params[:add_on_purchase]

        super
      end

      override :execute
      def execute
        return error_response unless add_on_purchase

        if update_add_on_purchase
          perform_after_update_actions

          successful_response
        else
          error_response
        end
      end

      private

      # rubocop: disable CodeReuse/ActiveRecord
      override :add_on_purchase
      def add_on_purchase
        @add_on_purchase ||= GitlabSubscriptions::AddOnPurchase.find_by(
          namespace: namespace,
          subscription_add_on_uid: add_on.id
        )
      end
      # rubocop: enable CodeReuse/ActiveRecord

      def update_add_on_purchase
        attributes = {
          add_on: add_on,
          quantity: quantity,
          started_at: started_at,
          expires_on: expires_on,
          purchase_xid: purchase_xid,
          trial: trial
        }.compact

        add_on_purchase.update(attributes)
      end

      def perform_after_update_actions
        GitlabSubscriptions::AddOnPurchases::RefreshUserAssignmentsWorker.perform_async(
          add_on_purchase.namespace_id
        )
      end

      override :error_response
      def error_response
        if add_on_purchase.nil?
          ServiceResponse.error(
            message: "Add-on purchase for #{add_on_human_reference} does not exist, create a new record instead"
          )
        else
          super
        end
      end
    end
  end
end
