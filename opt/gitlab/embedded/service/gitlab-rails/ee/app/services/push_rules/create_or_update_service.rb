# frozen_string_literal: true

module PushRules
  class CreateOrUpdateService < BaseService
    ALLOWED_FIELDS = %i[
      deny_delete_tag
      commit_message_regex
      commit_message_negative_regex
      branch_name_regex
      author_email_regex
      member_check
      file_name_regex
      max_file_size
      prevent_secrets
    ].freeze

    def execute
      if push_rule.update(processed_params)
        audit_changes(push_rule)

        ServiceResponse.success(payload: { push_rule: returned_push_rule })
      else
        error_message = push_rule.errors.full_messages.to_sentence
        ServiceResponse.error(message: error_message, payload: { push_rule: push_rule })
      end
    end

    private

    def push_rule
      if group_container?
        group_push_rule
      elsif organization_container?
        OrganizationPushRuleFinder.new(container).execute || OrganizationPushRule.new(organization_id: container.id)
      else
        container.push_rule || container.build_push_rule
      end
    end

    def group_push_rule
      GroupPushRuleFinder.new(group).execute || group.build_group_push_rule
    end

    def processed_params
      if organization_container? || group_container?
        filtered_params
      else
        params
      end
    end

    def filtered_params
      filtered_fields = [:reject_unsigned_commits, :commit_committer_check, :commit_committer_name_check,
        :reject_non_dco_commits].select { |field| push_rule.available?(field) }.concat(ALLOWED_FIELDS)

      params.slice(*filtered_fields)
    end

    def audit_changes(push_rule)
      ::Repositories::GroupPushRulesChangesAuditor.new(current_user, push_rule).execute if group_container?
      ::Repositories::ProjectPushRulesChangesAuditor.new(current_user, push_rule).execute if project_container?
    end

    def returned_push_rule
      return group_push_rule if group_container?
      return push_rule unless organization_container?

      OrganizationPushRuleFinder.new(container).execute
    end
  end
end
