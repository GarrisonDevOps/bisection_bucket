# frozen_string_literal: true

module GitlabSubscriptions
  module Duo
    class CodeReviewEnabledByDefaultAlertComponent < ViewComponent::Base
      def initialize(current_user:, group:)
        @current_user = current_user
        @group = group
      end

      private

      attr_reader :current_user, :group

      def render?
        current_user.present? &&
          group.present? &&
          Ability.allowed?(current_user, :admin_group, group) && # rubocop:disable Gitlab/Authz/PermissionCheck -- existing check
          group.namespace_settings&.enable_duo_code_review_by_default_enabled?
      end
    end
  end
end
