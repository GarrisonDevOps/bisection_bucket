# frozen_string_literal: true

module Vulnerabilities
  class ExternalIssueLink < ::SecApplicationRecord
    # Jira API limits reconcileIssues to 50 items max
    # https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issue-search/#api-rest-api-3-search-jql-get
    RECONCILE_ISSUE_LIMIT = 50

    self.table_name = 'vulnerability_external_issue_links'

    belongs_to :author, class_name: 'User'
    belongs_to :vulnerability
    belongs_to :finding, foreign_key: :vulnerability_occurrence_id, class_name: 'Vulnerabilities::Finding',
      optional: true, inverse_of: :external_issue_links

    # Not a `has_one through:`, which would join `projects` (gitlab_main) with
    # `vulnerabilities` (gitlab_sec) in a single query and raise a cross-schema
    # error. The gPAT boundary preloader cannot reflect on a delegate, so it
    # skips preloading and falls back to a per-record project query.
    delegate :project, to: :vulnerability, allow_nil: true

    declarative_enum LinkTypeEnum
    declarative_enum ExternalTypeEnum

    validates :vulnerability, :external_issue_key, :external_type, :external_project_key, presence: true
    validates :external_issue_key, uniqueness: { scope: [:vulnerability_id, :external_type, :external_project_key], message: N_('has already been linked to another vulnerability') }
    validates :vulnerability_id,
      uniqueness: {
        conditions: -> { where(link_type: 'created') },
        message: N_('already has a "created" issue link')
      },
      if: :created?

    scope :created_for_vulnerability, ->(vulnerability) { where(vulnerability: vulnerability, link_type: 'created') }
    scope :by_vulnerability, ->(values) { where(vulnerability_id: values) }
    scope :by_finding, ->(finding_ids) { where(vulnerability_occurrence_id: finding_ids) }

    class << self
      def jira_issue_keys_for_vulnerabilities(vulnerability_ids)
        where(vulnerability_id: vulnerability_ids)
          .jira
          .limit(RECONCILE_ISSUE_LIMIT)
          .pluck(:external_issue_key)
      end
    end
  end
end
