# frozen_string_literal: true

module EE
  module Autocomplete # rubocop:disable Gitlab/BoundedContexts -- FOSS finder is not bounded to a context
    module UsersFinder
      extend ::Gitlab::Utils::Override
      include ::Gitlab::Utils::StrongMemoize

      private

      override :project_users
      def project_users
        users = super

        if project.ai_review_merge_request_allowed?(current_user)
          duo_code_review_bot = ::Users::Internal.in_organization(project.organization_id).duo_code_review_bot
          users = users.union_with_user(duo_code_review_bot)
        end

        users
      end
    end
  end
end
