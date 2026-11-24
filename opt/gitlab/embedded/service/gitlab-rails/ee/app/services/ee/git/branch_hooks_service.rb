# frozen_string_literal: true

module EE
  module Git
    module BranchHooksService
      extend ::Gitlab::Utils::Override

      private

      override :pipeline_options
      def pipeline_options
        mirror_update = project.mirror? &&
          project.repository.up_to_date_with_upstream?(branch_name)

        super.merge(mirror_update: mirror_update)
      end

      override :branch_change_hooks
      def branch_change_hooks
        super
        enqueue_daily_foundational_flow
      end

      def enqueue_daily_foundational_flow
        return unless default_branch?
        return unless updating_branch?
        return unless current_user&.human?
        return unless ::Feature.enabled?(:sdlc_context_agent_trigger, project)
        return unless project.project_setting.duo_vulnerability_context_analysis_enabled

        ::Ai::DailyFlowOnPushWorker.perform_async(project.id, current_user.id)
      end
    end
  end
end
