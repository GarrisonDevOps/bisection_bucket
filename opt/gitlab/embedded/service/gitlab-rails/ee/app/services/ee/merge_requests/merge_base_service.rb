# frozen_string_literal: true

module EE
  module MergeRequests
    module MergeBaseService
      extend ::Gitlab::Utils::Override

      override :error_check!
      def error_check!
        check_free_user_cap_over_limit! # order matters here, this needs to come before size check for storage limits
        check_size_limit
        check_blocking_mrs
        check_jira_issue_enforcement
        check_merge_train_enforcement!
      end

      override :hooks_validation_pass?
      def hooks_validation_pass?(merge_request, validate_squash_message: false)
        # handle_merge_error needs this. We should move that to a separate
        # object instead of relying on the order of method calls.
        @merge_request = merge_request # rubocop:disable Gitlab/ModuleWithInstanceVariables

        hooks_error = hooks_validation_error(merge_request, validate_squash_message: validate_squash_message)

        return true unless hooks_error

        handle_merge_error(log_message: hooks_error, save_message_on_model: true)

        false
      rescue PushRule::MatchError => e
        handle_merge_error(log_message: e.message, save_message_on_model: true)
        false
      end

      override :hooks_validation_error
      def hooks_validation_error(merge_request, validate_squash_message: false)
        if project.merge_requests_ff_only_enabled
          return squash_message_validation_error if validate_squash_message

          return
        end

        return unless push_rule

        commit_message = params[:commit_message] || merge_request.default_merge_commit_message
        author_email = ::Gitlab::Git::User.verified_commit_email_or_primary_email(current_user)

        if !push_rule.commit_message_allowed?(commit_message)
          "Commit message does not follow the pattern '#{push_rule.commit_message_regex}'"
        elsif push_rule.commit_message_blocked?(commit_message)
          "Commit message contains the forbidden pattern '#{push_rule.commit_message_negative_regex}'"
        elsif !push_rule.author_email_allowed?(author_email)
          "Author's commit email '#{author_email}' does not follow the pattern '#{push_rule.author_email_regex}'"
        elsif validate_squash_message
          squash_message_validation_error
        elsif !push_rule.non_dco_commit_allowed?(commit_message)
          "Commit message must contain a DCO signoff"
        end
      end

      private

      def push_rule
        strong_memoize(:push_rule) do
          merge_request.project.predefined_push_rule if project.feature_available?(:push_rules)
        end
      end

      def squash_message_validation_error
        return unless push_rule

        squash_commit_message = params[:squash_commit_message] || merge_request.default_squash_commit_message

        if !push_rule.commit_message_allowed?(squash_commit_message)
          "Squash commit message does not follow the pattern '#{push_rule.commit_message_regex}'"
        elsif push_rule.commit_message_blocked?(squash_commit_message)
          "Squash commit message contains the forbidden pattern '#{push_rule.commit_message_negative_regex}'"
        end
      end

      def check_free_user_cap_over_limit!
        ::Namespaces::FreeUserCap::Enforcement.new(merge_request.project.root_ancestor)
                                              .git_check_over_limit!(::MergeRequests::MergeService::MergeError)
      end

      def check_size_limit
        if size_checker.above_size_limit?
          raise ::MergeRequests::MergeService::MergeError, size_checker.error_message.merge_error
        end
      end

      def size_checker
        merge_request.target_project.repository_size_checker
      end

      # This was introduced into the main mergeability framework in:
      # https://gitlab.com/gitlab-org/gitlab/-/merge_requests/90184
      # To remove: https://gitlab.com/gitlab-org/gitlab/-/issues/432220
      def check_blocking_mrs
        return unless merge_request.merge_blocked_by_other_mrs?

        raise ::MergeRequests::MergeService::MergeError, _('Other merge requests block this MR')
      end

      def check_jira_issue_enforcement
        return unless merge_request.project.prevent_merge_without_jira_issue?
        return if has_jira_issue_keys?

        raise ::MergeRequests::MergeService::MergeError, _('To merge, either the title or description must reference a Jira issue.')
      end

      # Reject a direct merge when the project enforces merge trains. Only the merge train's own
      # merge (MergeTrains::RefreshMergeRequestService#merge!) is allowed, via the internal
      # `merging_via_merge_train` param that no external entry point sets.
      def check_merge_train_enforcement!
        return if params[:merging_via_merge_train]
        return unless merge_request.target_project.merge_train_enforced_for?(current_user)

        raise ::MergeRequests::MergeService::MergeError,
          _('This project requires merge requests to go through the merge train. ' \
            'Set auto_merge to true to add this merge request to the train instead.')
      end

      # This was introduced into the main megreability framework in:
      # https://gitlab.com/gitlab-org/gitlab/-/merge_requests/136685
      # To remove: https://gitlab.com/gitlab-org/gitlab/-/issues/432220
      def has_jira_issue_keys?
        return unless merge_request.project.jira_integration.try(:active?)

        Atlassian::JiraIssueKeyExtractor.has_keys?(
          merge_request.title,
          merge_request.description,
          custom_regex: merge_request.project.jira_integration.reference_pattern
        )
      end
    end
  end
end
