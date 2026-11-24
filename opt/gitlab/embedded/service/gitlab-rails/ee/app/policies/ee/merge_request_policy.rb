# frozen_string_literal: true

module EE
  module MergeRequestPolicy
    extend ActiveSupport::Concern
    extend ::Gitlab::Utils::Override

    prepended do
      condition(:external_status_checks_enabled) do
        @subject.target_project&.licensed_feature_available?(:external_status_checks)
      end

      condition(:read_only, scope: :subject) { read_only? }
      condition(:approval_rules_editable) { approval_rules_editable? }

      condition(:merge_request_group_approver, score: 140) do
        next false unless @user

        project = @subject.target_project

        # A branch can match more than one protected branch record (e.g. protected
        # at both the project and group level), and the matching approval rule may
        # be attached to any of them. We must therefore check all matching records,
        # but collect their IDs and run a single query in `group_access?` instead of
        # querying once per record, which would introduce an N+1.
        protected_branch_ids = project.all_protected_branches
          .select { |protected_branch| protected_branch.matches?(@subject.target_branch) }
          .map(&:id)

        group_access?(project, protected_branch_ids)
      end

      condition(:approval_rules_licence_enabled, scope: :subject) do
        @subject.target_project.licensed_feature_available?(:coverage_check_approval_rule) ||
          @subject.target_project.licensed_feature_available?(:report_approver_rules)
      end

      condition(:role_enables_admin_merge_request) do
        ::Authz::CustomAbility.allowed?(@user, :admin_merge_request, subject&.project)
      end

      condition(:target_project_internal) do
        @subject.target_project&.internal?
      end

      condition(:user_allowed_to_read_target_project_merge_requests) do
        can?(:read_merge_request, @subject.target_project)
      end

      condition(:generate_commit_message_enabled) do
        subject.project.project_setting.duo_features_enabled?
      end

      condition(:user_allowed_to_use_generate_commit_message) do
        @user.allowed_to_use?(:generate_commit_message, licensed_feature: :generate_commit_message)
      end

      condition(:summarize_review_enabled) do
        subject.project.project_setting.duo_features_enabled? &&
          ::Feature.enabled?(:summarize_my_code_review, @user) &&
          ::Gitlab::Llm::FeatureAuthorizer.new(
            container: @subject.project,
            feature_name: :summarize_review,
            user: @user,
            licensed_feature: :summarize_review
          ).allowed?
      end

      def read_only?
        @subject.target_project&.namespace&.read_only?
      end

      def group_access?(project, protected_branch_ids)
        return false unless @user
        return false if protected_branch_ids.empty?

        # Only the target project's own approval rules apply. A group-level protected branch is
        # shared across all projects in the group, so scope the lookup by project explicitly
        # rather than relying on the shared protected branch alone.
        ::ApprovalProjectRule
          .for_project(project.id)
          .with_protected_branches(protected_branch_ids)
          .for_groups(
            @user.group_members.with_at_least_access_level(::Gitlab::Access::PLANNER).select(:source_id)
          ).exists?
      end

      def approval_rules_editable?
        can?(:update_merge_request) && @subject.approval_rules_editable_by?(@user)
      end

      rule { approval_rules_editable }.policy do
        enable :update_approvers
        enable :create_approval_rule
        enable :update_approval_rule
        enable :delete_approval_rule
      end

      rule { ~approval_rules_editable }.policy do
        prevent :update_approvers
        prevent :create_approval_rule
        prevent :update_approval_rule
        prevent :delete_approval_rule
      end

      # Approval rule groups can include users who aren't project members.
      rule { merge_request_group_approver }.policy do
        enable :approve_merge_request
        enable :create_merge_request_review
      end

      rule do
        target_project_internal &
          ~external_user &
          user_allowed_to_read_target_project_merge_requests
      end.enable :read_external_status_check_response

      rule { ~external_status_checks_enabled }.policy do
        prevent :provide_status_check_response
        prevent :read_external_status_check_response
        prevent :retry_failed_status_checks
      end

      rule { read_only }.policy do
        prevent :update_merge_request
        prevent :create_merge_request_review
      end

      rule { approval_rules_licence_enabled }.enable :create_merge_request_approval_rules

      rule { role_enables_admin_merge_request }.policy do
        enable :approve_merge_request
        enable :create_merge_request_review
      end

      rule do
        generate_commit_message_enabled &
          user_allowed_to_use_generate_commit_message
      end.enable :access_generate_commit_message

      rule do
        summarize_review_enabled & can?(:read_merge_request)
      end.enable :access_summarize_review
    end
  end
end
