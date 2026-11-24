# frozen_string_literal: true

module Types
  module Analytics
    module AiUsage
      class AiUsageEventTypeEnum < BaseEnum
        graphql_name 'AiUsageEventType'
        description 'Type of AI usage event'

        DEPRECATION_POSTFIX = "Old data only."

        def self.declare_event(event_name, description)
          description += " #{DEPRECATION_POSTFIX}" if Gitlab::Tracking::AiTracking.deprecated_event?(event_name)

          value event_name.upcase, description: description, value: event_name
        end

        declare_event('code_suggestions_requested', "Code Suggestion was requested.")
        declare_event('code_suggestion_shown_in_ide', "Code Suggestion was shown in IDE.")
        declare_event('code_suggestion_accepted_in_ide', "Code Suggestion was accepted in IDE.")
        declare_event('code_suggestion_rejected_in_ide', "Code Suggestion was rejected in IDE.")
        declare_event('code_suggestion_direct_access_token_refresh', "Code Suggestion token was refreshed.")
        declare_event('request_duo_chat_response', "Duo Chat response was requested.")
        declare_event('tool_succeeded_duo_chat', "Duo Chat tool call succeeded.")
        declare_event('tool_failed_duo_chat', "Duo Chat tool call failed.")
        declare_event('report_duo_chat_token_usage', "Duo Chat agent turn reported its token usage per model.")
        declare_event('complete_duo_chat_response', "Duo Chat response was completed, with an answer or an error.")
        declare_event('troubleshoot_job', "Troubleshoot job feature was used.")
        declare_event('agent_platform_session_created', "Agent platform session was created.")
        declare_event('agent_platform_session_started', "Agent platform session was started.")
        declare_event('agent_platform_session_finished', "Agent platform session was finished.")
        declare_event('agent_platform_session_dropped', "Agent platform session was dropped.")
        declare_event('agent_platform_session_stopped', "Agent platform session was stopped.")
        declare_event('agent_platform_session_resumed', "Agent platform session was resumed.")
        declare_event('agent_platform_session_input_required', "Agent platform session paused to wait for user input.")
        declare_event('report_agent_platform_token_usage',
          "Agent platform session checkpoint reported its token usage per model.")
        declare_event('encounter_duo_code_review_error_during_review', "Duo Code Review encountered an error.")
        declare_event('find_no_issues_duo_code_review_after_review',
          "Duo Code Review found no issues after review.")
        declare_event('find_nothing_to_review_duo_code_review_on_mr',
          "Duo Code Review found nothing to review on MR.")
        declare_event('post_comment_duo_code_review_on_diff', "Duo Code Review posted a diff comment.")
        declare_event('react_thumbs_up_on_duo_code_review_comment',
          "User gave thumbs-up reaction to Duo Code Review comment.")
        declare_event('react_thumbs_down_on_duo_code_review_comment',
          "User gave thumbs-down reaction to Duo Code Review comment.")
        declare_event('request_review_duo_code_review_on_mr_by_author', "MR author requested Duo Code Review.")
        declare_event('request_review_duo_code_review_on_mr_by_non_author',
          "Non-author requested Duo Code Review on MR.")
        declare_event('excluded_files_from_duo_code_review', "Files were excluded from Duo Code Review.")
        declare_event('publish_duo_code_review_comments', "Duo Code Review comments were published.")
        declare_event('create_duo_suggested_reviewers', "Duo suggested reviewers for a merge request.")
        declare_event('assign_duo_suggested_reviewer',
          "Duo suggested reviewers were added as reviewers to a merge request.")
        declare_event('approve_merge_request_duo_code_review', "Duo Code Review approved a merge request.")
        declare_event('duo_workflow_workload_completed', "Duo Workflow workload was completed.")
        declare_event('fix_pipeline_suggestion_applied', "Fix pipeline suggestion was applied.")
        declare_event('fix_pipeline_suggestion_posted', "Fix pipeline suggestion was posted.")
        declare_event('start_mcp_tool_call', "MCP tool call was started.")
        declare_event('finish_mcp_tool_call', "MCP tool call was finished.")
        declare_event('view_duo_agentic_subscription_expired_empty_state',
          "Duo Agent Platform subscription expired empty state was viewed.")
        declare_event('click_duo_agentic_subscription_expired_upgrade',
          "User clicked upgrade on Duo Agent Platform subscription expired state.")
        declare_event('click_duo_agentic_subscription_expired_learn_more',
          "User clicked learn more on Duo Agent Platform subscription expired state.")
        declare_event('restore_ai_catalog_item', "AI Catalog item version was restored as new latest version.")
        declare_event('summarize_review', "A merge request review summary was requested with GitLab Duo.")
        declare_event('summarize_new_merge_request', "Merge request summary was generated.")
        declare_event('generate_merge_commit_message', "Merge commit message was generated for a merge request.")
        declare_event('ai_duo_messaging_feedback_submitted',
          "Feedback was submitted on a Duo agent response in a messaging surface.")
        declare_event('request_duo_vulnerability_resolution',
          "An AI vulnerability resolution was requested with GitLab Duo.")
        declare_event('explain_vulnerability', "An AI explanation of a vulnerability was requested with GitLab Duo.")
        declare_event('resolve_feature_discovery_search', "Feature discovery search was resolved.")
        declare_event('trigger_slack_duo', "Duo agent was triggered from a Slack mention.")
        declare_event('fix_code', "Code fix was requested with the GitLab Duo Chat /fix command.")
        declare_event('refactor_code', "Code refactor was requested with the GitLab Duo Chat /refactor command.")
        declare_event('write_tests', "Test generation was requested with the GitLab Duo Chat /tests command.")
        declare_event('explain_code', "Code explanation was requested with the GitLab Duo Chat /explain command.")
      end
    end
  end
end
