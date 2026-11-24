# frozen_string_literal: true

module Gitlab
  module Duo
    module CodeReview
      module Messages
        module_function

        def automatic_error
          s_(
            "DuoCodeReview|GitLab Duo Code Review was not automatically added. " \
              "Contact your administrator to verify your account has access to this feature."
          )
        end

        def manual_error
          s_(
            "DuoCodeReview|You don't have access to GitLab Duo Code Review. " \
              "Contact your administrator to verify your account has access to this feature."
          )
        end

        def merge_request_not_found_error
          s_(
            "DuoCodeReview|Can't access the merge request. When SAML single sign-on is enabled on a group or its " \
              "parent, Duo Code Reviews can't be requested from the API. Request a review from the GitLab UI instead."
          )
        end

        def progress_note_not_found_error
          s_(
            "DuoCodeReview|Can't create the progress note. This can happen if the Duo Code Review bot does not " \
              "have permission to create notes on the merge request."
          )
        end

        def generic_error
          s_(
            "DuoCodeReview|I have encountered some problems while I was reviewing. Please try again later."
          )
        end

        def review_in_progress
          s_("DuoCodeReview|I'm already reviewing this merge request. I'll post my feedback when I'm done.")
        end

        def nothing_to_review
          s_("DuoCodeReview|:wave: There's nothing for me to review.")
        end

        def nothing_to_comment
          s_("DuoCodeReview|I finished my review and found nothing to comment on. Nice work! :tada:")
        end

        def invalid_review_output
          s_(
            "DuoCodeReview|:warning: Something went wrong while I was processing the review results. " \
              "Please request a new review."
          )
        end

        def could_not_start_workflow_error
          s_(
            "DuoCodeReview|:warning: Something went wrong while requesting a review from GitLab Duo. " \
              "Please request a new review."
          )
        end

        def exception_when_starting_workflow_error
          message_with_error_code(
            "DCR5000",
            s_(
              "DuoCodeReview|:warning: Something went wrong while starting Code Review Flow. " \
                "Please try again later."
            )
          )
        end

        def foundational_flow_not_enabled_error
          message_with_error_code(
            "DCR4000",
            s_(
              "DuoCodeReview|:warning: Code Review Flow is not enabled. " \
                "Contact your group administrator to enable the foundational flow in the top-level group."
            )
          )
        end

        def missing_service_account_error
          message_with_error_code(
            "DCR4001",
            s_(
              "DuoCodeReview|:warning: Code Review Flow is enabled " \
                "but the service account needs to be verified. Contact your administrator."
            )
          )
        end

        def usage_quota_exceeded_error
          message_with_error_code(
            "DCR4002",
            s_(
              "DuoCodeReview|:warning: No GitLab Credits remain for this billing period. " \
                "To continue using Code Review Flow, contact your administrator."
            )
          )
        end

        def insufficient_workload_permissions_error(user)
          message_with_error_code(
            "DCR4003",
            s_(
              "DuoCodeReview|:warning: %{user_reference}, you don't have permission to create a pipeline for " \
                "Code Review Flow in this project. Contact your administrator to update your permissions."
            ),
            user_reference: user.to_reference
          )
        end

        def namespace_missing_error(user)
          docs_url = Rails.application.routes.url_helpers.help_page_url(
            'user/profile/preferences.md',
            anchor: 'set-a-default-gitlab-duo-namespace'
          )

          message_with_error_code(
            "DCR4004",
            s_(
              "DuoCodeReview|:warning: %{user_reference}, you need to set a default GitLab Duo namespace " \
                "to use Code Review Flow in this project. " \
                "Please set a default GitLab Duo namespace in your [preferences](%{docs_url})."
            ),
            user_reference: user.to_reference,
            docs_url: docs_url
          )
        end

        def invalid_token_error
          message_with_error_code(
            "DCR4005",
            s_(
              "DuoCodeReview|:warning: Code Review Flow could not obtain the required " \
                "authentication tokens to connect to the GitLab AI Gateway and API. " \
                "Please request a new review. If the issue persists, contact your administrator."
            )
          )
        end

        def feature_unavailable_error
          message_with_error_code(
            "DCR4007",
            s_(
              "DuoCodeReview|:warning: Code Review Flow is not available for this project. " \
                "Contact your administrator to verify that the flow is enabled " \
                "and the required configuration is in place."
            )
          )
        end

        def workload_creation_error
          message_with_error_code(
            "DCR4008",
            s_(
              "DuoCodeReview|:warning: Code Review Flow could not create the required CI/CD pipeline. " \
                "Please request a new review. If the problem persists, contact your administrator."
            )
          )
        end

        def source_ref_not_found_error
          message_with_error_code(
            "DCR4009",
            s_(
              "DuoCodeReview|:warning: Code Review Flow could not retrieve the source branch for this merge request. " \
                "Please request a new review."
            )
          )
        end

        def usage_billing_forbidden_error
          message_with_error_code(
            "DCR4010",
            s_(
              "DuoCodeReview|:warning: Usage billing is not available for this account. " \
                "To continue using Code Review Flow, contact your administrator."
            )
          )
        end

        def timeout_error
          s_(
            "DuoCodeReview|:warning: Something went wrong and the review request was stopped. " \
              "Please request a new review."
          )
        end

        def publish_comments_exhausted_error
          message_with_error_code(
            "DCR5001",
            s_(
              "DuoCodeReview|:warning: Code Review Flow completed the review but could not post the review comments. " \
                "Please request a new review to try again."
            )
          )
        end

        def comments_not_posted_message(summary)
          prefix = s_(
            "DuoCodeReview|I found issues to comment on but was unable to post the inline " \
              "comments due to line number mismatches. My review found:"
          )
          "#{prefix}\n\n#{summary}"
        end

        def no_new_comments_message(summary)
          prefix = s_(
            "DuoCodeReview|I reviewed the changes since my last review and found no new issues. " \
              "Previous findings:"
          )
          "#{prefix}\n\n#{summary}"
        end

        def could_not_generate_summary_error
          s_("DuoCodeReview|:warning: Something went wrong while GitLab Duo was generating a code review summary.")
        end

        def no_eligible_runner_error(tag: ::Ai::DuoWorkflows::Workflow::WORKLOAD_TAG)
          message_with_error_code(
            "DCR4011",
            s_(
              "DuoCodeReview|:warning: Code Review Flow could not start because the project has no runner " \
                "available. It needs an instance runner or a top-level group runner with the `%{tag}` tag " \
                "and a Docker-compatible executor."
            ),
            tag: tag
          )
        end

        def namespace_ci_minutes_used_up_error
          message_with_error_code(
            "DCR4012",
            s_(
              "DuoCodeReview|:warning: Code Review Flow could not start because the namespace has run out of " \
                "compute minutes. Ask someone with billing access to add compute minutes before trying again."
            )
          )
        end

        def flow_chain_limit_error
          s_(
            "DuoCodeReview|:warning: Code Review Flow was not started because the flow that requested " \
              "this review is not allowed to start it. To get a review, request it yourself."
          )
        end

        def message_with_error_code(error_code, message, placeholders = {})
          error_code_url = Rails.application.routes.url_helpers.help_page_url(
            'user/duo_agent_platform/flows/foundational_flows/code_review/troubleshooting.md',
            anchor: "error-#{error_code.downcase}"
          )

          error_info = format(
            s_(
              "DuoCodeReview|Error code: [%{error_code}](%{error_code_url})"
            ),
            error_code_url: error_code_url,
            error_code: error_code
          )

          error_message = "#{message}\n\n#{error_info}"

          format(error_message, **placeholders)
        end
      end
    end
  end
end
