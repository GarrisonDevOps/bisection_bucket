# frozen_string_literal: true

# This finder will return all the members as the FOSS version as well as
# the Duo Code Review bot if the current user has access to the Duo Code Review
# features
module EE
  module Autocomplete # rubocop:disable Gitlab/BoundedContexts -- FOSS finder is not bounded to a context
    module GroupUsersFinder
      extend ::Gitlab::Utils::Override

      override :execute
      def execute
        scope = super

        if group.ai_review_merge_request_allowed?(current_user)
          duo_code_review_bot = ::Users::Internal.in_organization(group.organization_id).duo_code_review_bot
          scope = scope.union_with_user(duo_code_review_bot)
        end

        scope
      end
    end
  end
end
