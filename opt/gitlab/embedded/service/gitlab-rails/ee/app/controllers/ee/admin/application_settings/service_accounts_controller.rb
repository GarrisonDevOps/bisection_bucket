# frozen_string_literal: true

module EE
  module Admin
    module ApplicationSettings
      module ServiceAccountsController
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override

        private

        override :authorize_admin_service_accounts!
        def authorize_admin_service_accounts!
          return render_404 if ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)

          super
        end
      end
    end
  end
end
