# frozen_string_literal: true

module FeatureFlagIssues
  class CreateService < IssuableLinks::CreateService
    extend ::Gitlab::Utils::Override
    include Gitlab::Utils::StrongMemoize

    override :previous_related_issuables
    def previous_related_issuables
      issuable.issues.to_a
    end
    strong_memoize_attr :previous_related_issuables

    override :linkable_issuables
    def linkable_issuables
      Ability.issues_readable_by_user(referenced_issuables, current_user)
    end
    strong_memoize_attr :linkable_issuables

    def relate_issuables(referenced_issue)
      attrs = { feature_flag_id: issuable.id, issue: referenced_issue }
      ::FeatureFlagIssue.create(attrs)
    end
  end
end
