# frozen_string_literal: true

module EE
  module UserSettings
    module PersonalAccessTokensController
      extend ::Gitlab::Utils::Override

      override :check_personal_access_tokens_enabled
      def check_personal_access_tokens_enabled
        super

        return unless current_user.enterprise_user? && current_user.enterprise_group.disable_personal_access_tokens?

        render_404
      end
    end
  end
end
