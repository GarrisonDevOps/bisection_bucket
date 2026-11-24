# frozen_string_literal: true

module PushRules
  class CreatePredefinedRuleService < BaseContainerService
    def execute(override_push_rule: false)
      return unless project.feature_available?(:push_rules)
      return unless predefined_push_rule.present?

      log_info(predefined_push_rule)

      push_rule = if project.group
                    container.build_push_rule(
                      predefined_push_rule.dup.attributes.except('id', 'organization_id', 'group_id')
                    )
                  else
                    container.build_push_rule(
                      predefined_push_rule.dup.attributes.except('id', 'organization_id')
                    )
                  end

      override_push_rule(push_rule) if override_push_rule

      project.push_rule = push_rule
      project.project_setting.update(push_rule: push_rule)
    end

    private

    def predefined_push_rule
      if project.group
        project.group.predefined_push_rule
      else
        OrganizationPushRuleFinder.new(project.organization).execute
      end
    end

    def override_push_rule(push_rule)
      push_rule.commit_message_regex = nil
      push_rule.commit_message_negative_regex = nil
      push_rule.branch_name_regex = nil
    end
  end
end
