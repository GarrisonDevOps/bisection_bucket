# frozen_string_literal: true

module EE
  module Oauth
    module AuthorizationsController
      extend ::Gitlab::Utils::Override

      private

      override :skip_dynamic_application_name_stamp?
      def skip_dynamic_application_name_stamp?
        ::Gitlab::Saas.feature_available?(:skip_dynamic_oauth_app_user_stamp)
      end
    end
  end
end
