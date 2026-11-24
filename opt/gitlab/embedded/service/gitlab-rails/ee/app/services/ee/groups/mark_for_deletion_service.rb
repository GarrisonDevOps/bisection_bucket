# frozen_string_literal: true

module EE
  module Groups
    module MarkForDeletionService
      extend ::Gitlab::Utils::Override
      include SecurityOrchestrationHelper

      override :post_success
      def post_success
        super

        ::GitlabSubscriptions::FreeGroupUpgradeLinkCache.invalidate(current_user.id)
        # The indexed `active` field folds in deletion scheduling and is ancestor-aware,
        # so every descendant's document goes stale too.
        ::Search::Elastic::GroupActiveStateWorker.perform_async(resource.id)
      end

      private

      override :preconditions_checks
      def preconditions_checks
        result = super
        return result if result.error?
        return linked_as_security_policy_project_error if includes_security_policy_projects?

        ServiceResponse.success
      end

      def includes_security_policy_projects?
        policy_configurations_within_group(resource).exists?
      end

      def linked_as_security_policy_project_error
        ServiceResponse.error(
          message: s_('SecurityOrchestration|Group cannot be deleted because it has projects ' \
            'that are linked as a security policy project'))
      end
    end
  end
end
