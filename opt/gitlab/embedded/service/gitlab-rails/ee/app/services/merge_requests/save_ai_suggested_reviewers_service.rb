# frozen_string_literal: true

module MergeRequests
  class SaveAiSuggestedReviewersService
    include Gitlab::Utils::StrongMemoize
    include Gitlab::InternalEventsTracking

    def initialize(merge_request:, suggestions: [])
      @merge_request = merge_request
      @suggestions = Array(suggestions)
    end

    def execute
      return missing_user_error if missing_users?

      records = build_records

      ::MergeRequests::AiSuggestedReviewer.transaction do
        lock_merge_request
        ::MergeRequests::AiSuggestedReviewer.for_merge_request(merge_request).delete_all

        ::MergeRequests::AiSuggestedReviewer.bulk_insert!(records) if records.any?
      end

      ::GraphqlTriggers.merge_request_ai_suggested_reviewers_updated(merge_request)
      track_suggestions_created(records.size) if records.any?

      ServiceResponse.success
    rescue ActiveRecord::RecordInvalid => e
      ServiceResponse.error(message: e.record.errors.full_messages)
    rescue ActiveRecord::RecordNotUnique
      ServiceResponse.error(
        message: [s_('AiSuggestedReviewers|Each user can only be suggested once per merge request')]
      )
    end

    private

    attr_reader :merge_request, :suggestions

    def track_suggestions_created(count)
      track_internal_event(
        'create_duo_suggested_reviewers',
        project: merge_request.project,
        user: merge_request.author,
        additional_properties: {
          property: merge_request.id.to_s,
          value: count
        }
      )
    end

    def missing_users?
      user_ids = unique_suggestions.map { |suggestion| suggestion[:user_id].to_i }.uniq

      ::User.id_in(user_ids).count != user_ids.size
    end

    def missing_user_error
      ServiceResponse.error(message: [s_('AiSuggestedReviewers|A suggested user does not exist')])
    end

    def lock_merge_request
      lock_key = ::MergeRequests::AiSuggestedReviewer.connection.quote("ai_suggested_reviewers:#{merge_request.id}")

      ::MergeRequests::AiSuggestedReviewer.connection.execute("SELECT pg_advisory_xact_lock(hashtext(#{lock_key}))")
    end

    def build_records
      timestamp = Time.current

      unique_suggestions.map do |suggestion|
        ::MergeRequests::AiSuggestedReviewer.new(
          project_id: merge_request.project_id,
          merge_request_id: merge_request.id,
          user_id: suggestion[:user_id],
          reason: suggestion[:reason],
          **resolve_approval_rule_ids(suggestion[:approval_rule_id], suggestion[:approval_rule_type]),
          created_at: timestamp,
          updated_at: timestamp
        )
      end
    end

    def unique_suggestions
      suggestions.map(&:symbolize_keys).uniq { |suggestion| suggestion[:user_id] }
    end

    def resolve_approval_rule_ids(approval_rule_id, approval_rule_type)
      empty_result = { approval_merge_request_rule_id: nil, approval_project_rule_id: nil }
      return empty_result if approval_rule_id.blank?

      rule = wrapped_approval_rules_by_key[approval_rule_lookup_key(approval_rule_id, approval_rule_type)]

      return empty_result unless rule

      case rule
      when ApprovalMergeRequestRule
        { approval_merge_request_rule_id: rule.id, approval_project_rule_id: nil }
      when ApprovalProjectRule
        { approval_merge_request_rule_id: nil, approval_project_rule_id: rule.id }
      else
        empty_result
      end
    end

    def approval_rule_lookup_key(approval_rule_id, approval_rule_type)
      klass = approval_rule_type.to_s == 'project_rule' ? ApprovalProjectRule.name : ApprovalMergeRequestRule.name

      [klass, approval_rule_id.to_i]
    end

    def wrapped_approval_rules_by_key
      merge_request.approval_state.wrapped_approval_rules.each_with_object({}) do |wrapped_rule, hash|
        rule = wrapped_rule.approval_rule
        hash[[rule.class.name, rule.id]] = rule
      end
    end
    strong_memoize_attr :wrapped_approval_rules_by_key
  end
end
