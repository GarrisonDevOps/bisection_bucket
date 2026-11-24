# frozen_string_literal: true

module EE
  module Projects
    module ParticipantsService
      extend ::Gitlab::Utils::Override

      private

      override :project_members_relation
      def project_members_relation
        scope = super

        if project.ai_review_merge_request_allowed?(current_user)
          duo_code_review_bot = ::Users::Internal.in_organization(project.organization_id).duo_code_review_bot
          scope = scope.union_with_user(duo_code_review_bot)
        end

        scope
      end
    end
  end
end
