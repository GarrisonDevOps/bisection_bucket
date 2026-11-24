# frozen_string_literal: true

module GitlabSubscriptions
  module AddOnPurchases
    module GitlabCom
      class UpdateService < ::GitlabSubscriptions::AddOnPurchases::UpdateService
        # This service is used inside a transaction in the provision service for add-on purchases for SaaS
        # Enqueueing workers is not supported and we want to enqueue the worker after the commit of the transaction
        override :perform_after_update_actions
        def perform_after_update_actions; end
      end
    end
  end
end
