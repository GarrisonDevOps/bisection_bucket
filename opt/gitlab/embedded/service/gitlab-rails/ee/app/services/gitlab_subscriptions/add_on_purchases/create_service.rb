# frozen_string_literal: true

module GitlabSubscriptions
  module AddOnPurchases
    class CreateService < ::GitlabSubscriptions::AddOnPurchases::BaseService
      extend ::Gitlab::Utils::Override

      override :execute
      def execute
        return root_namespace_error if ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions) && !namespace&.root?

        add_on_purchase.save ? successful_response : error_response
      end

      private

      def root_namespace_error
        message = namespace.present? ? "Namespace #{namespace.name} is not a root namespace" : 'No namespace given'

        ServiceResponse.error(message: message)
      end

      override :successful_response
      def successful_response
        # The in-app trial add on calls from GitLab via in-app trial create actions
        # query the add on purchase immediately after this update that initiates from CustomersDot.
        # in-app trials that invoke this area via POST to CustomersDot:
        # - GitlabSubscriptions::TrialsController#create
        # Stick to the primary database in order to make those requests aware that
        # an up to date replica or a primary database must be used to fetch the data.
        # Note: If changing the CustomersDot operation for creating add on purchases this may mean this sticking
        # needs to move or change as well.
        # It must be before the area where the actual add on purchase is committed to the database from
        # a CustomersDot API call.
        ::Namespace.sticking.stick(:namespace, namespace.id) if namespace.present? # self-managed doesn't have namespace

        super
      end

      override :add_on_purchase
      def add_on_purchase
        @add_on_purchase ||= GitlabSubscriptions::AddOnPurchase.new(
          namespace: namespace,
          organization_id: namespace&.organization_id || Organizations::Organization.first.id,
          add_on: add_on,
          quantity: quantity,
          started_at: started_at,
          expires_on: expires_on,
          purchase_xid: purchase_xid,
          trial: trial.presence || false
        )
      end

      override :error_response
      def error_response
        if add_on_purchase.errors.of_kind?(:subscription_add_on_uid, :taken)
          ServiceResponse.error(
            message: "Add-on purchase for #{add_on_human_reference} already exists, update the existing record"
          )
        else
          super
        end
      end
    end
  end
end
