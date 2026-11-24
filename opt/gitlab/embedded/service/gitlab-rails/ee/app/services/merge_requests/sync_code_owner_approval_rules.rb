# frozen_string_literal: true

module MergeRequests
  class SyncCodeOwnerApprovalRules
    include Gitlab::Utils::StrongMemoize

    AlreadyMergedError = Class.new(StandardError)

    def initialize(merge_request, params = {})
      @merge_request = merge_request
      @previous_diff = params[:previous_diff]
      @expire_unapproved_key = params[:expire_unapproved_key].presence
    end

    def execute
      return already_merged if merge_request.merged?

      rules_by_pattern_and_section = existing_rules.index_by { |rule| [rule.name, rule.section] }

      matched_rule_ids =
        code_owner_entries.filter_map do |entry|
          rule = rules_by_pattern_and_section.fetch([entry.pattern, entry.section]) do
            create_rule(entry)
          end

          rule.users = entry.users
          rule.groups = entry.groups
          rule.role_approvers = entry.roles
          rule.approvals_required = entry.approvals_required

          # Users and groups are written when assigned, so an unchanged rule has nothing to save.
          rule.save if !skip_unchanged_saves? || rule.changed?

          rule.id
        end

      delete_outdated_code_owner_rules(matched_rule_ids)

      expire_unapproved_key! if expire_unapproved_key
    end

    private

    attr_reader :merge_request, :previous_diff, :expire_unapproved_key

    def existing_rules
      rules = merge_request.approval_rules.matching_pattern(patterns)
      rules = rules.preload_users_and_groups if skip_unchanged_saves?
      rules
    end

    def skip_unchanged_saves?
      Feature.enabled?(:code_owner_rules_sync_skip_unchanged_saves, merge_request.target_project)
    end
    strong_memoize_attr :skip_unchanged_saves?

    def create_rule(entry)
      ApprovalMergeRequestRule.find_or_create_code_owner_rule(merge_request, entry)
    end

    def delete_outdated_code_owner_rules(matched_rule_ids)
      merge_request.approval_rules.not_matching_id(matched_rule_ids).delete_all
    end

    def patterns
      @patterns ||= code_owner_entries.map(&:pattern)
    end

    def code_owner_entries
      @code_owner_entries ||= Gitlab::CodeOwners
                                .entries_for_merge_request(merge_request, merge_request_diff: previous_diff)
    end

    def already_merged
      Gitlab::ErrorTracking.track_exception(
        AlreadyMergedError.new('MR already merged before code owner approval rules were synced'),
        merge_request_id: merge_request.id,
        merge_request_iid: merge_request.iid,
        project_id: merge_request.project_id
      )
      nil
    end

    def expire_unapproved_key!
      merge_request.approval_state.expire_unapproved_key!
      GraphqlTriggers.merge_request_merge_status_updated(merge_request)
      GraphqlTriggers.merge_request_approval_state_updated(merge_request)
    end
  end
end
