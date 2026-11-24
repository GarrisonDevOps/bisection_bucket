# frozen_string_literal: true

module EE
  module QuickActions
    module InterpretService
      extend ActiveSupport::Concern
      extend ::Gitlab::Utils::Override

      # We use "prepended" here instead of including Gitlab::QuickActions::Dsl,
      # as doing so would clear any existing command definitions.
      prepended do
        # rubocop: disable Cop/InjectEnterpriseEditionModule
        include EE::Gitlab::QuickActions::EpicActions
        include EE::Gitlab::QuickActions::IssueActions
        include EE::Gitlab::QuickActions::IssueAndMergeRequestActions
        include EE::Gitlab::QuickActions::MergeRequestActions
        include EE::Gitlab::QuickActions::RelateActions
        include EE::Gitlab::QuickActions::WorkItemActions
        include EE::Gitlab::QuickActions::AmazonQActions
        # rubocop: enable Cop/InjectEnterpriseEditionModule
      end

      # Quick actions that are safe for AI workflows because they
      # only set attributes that Duo can already set via dedicated API parameters.
      # Actions that dangerously change state or trigger side effects (e.g. /merge, /close,
      # /approve) are intentionally excluded and remain blocked.
      ALLOWED_AI_QUICK_ACTIONS = %i[
        label unlabel relabel
        milestone remove_milestone
        assign unassign reassign
        request_review unassign_reviewer reassign_reviewer
        title
        due remove_due_date
        estimate remove_estimate
        spend remove_time_spent
        weight clear_weight
        health_status clear_health_status
        iteration remove_iteration
        status
        draft ready
      ].freeze

      private

      override :allowed_ai_quick_action?
      def allowed_ai_quick_action?(name)
        definition = self.class.definition_by_name(name)
        return super unless definition

        ALLOWED_AI_QUICK_ACTIONS.include?(definition.name)
      end

      # AI service accounts also write notes outside an API request (for example a flow's
      # final reply), where no scope validator is passed, so the allowlist applies to them
      # by author.
      override :skip_quick_actions_check?
      def skip_quick_actions_check?(commands)
        super && !current_user.composite_ai_service_account?
      end
    end
  end
end
