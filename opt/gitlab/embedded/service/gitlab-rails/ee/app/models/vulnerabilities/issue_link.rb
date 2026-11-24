# frozen_string_literal: true

module Vulnerabilities
  class IssueLink < ::SecApplicationRecord
    self.table_name = 'vulnerability_issue_links'

    after_commit :trigger_vulnerability_webhook_event, on: :create

    belongs_to :vulnerability
    belongs_to :finding, foreign_key: :vulnerability_occurrence_id, class_name: 'Vulnerabilities::Finding',
      optional: true, inverse_of: false
    belongs_to :issue

    has_one :author, through: :issue, class_name: 'User'

    enum :link_type, { related: 1, created: 2 } # 'related' is the default value

    validates :vulnerability, :issue, presence: true
    validates :issue_id, uniqueness: { scope: :vulnerability_id, message: N_('has already been linked to another vulnerability') }
    validates :vulnerability_id,
      uniqueness: {
        conditions: -> { where(link_type: 'created') },
        message: N_('already has a "created" issue link')
      },
      if: :created?

    scope :by_link_type, ->(link_type) { link_type ? where(link_type: link_type.downcase) : all }
    scope :for_issue, ->(issue) { where(issue_id: issue) }
    scope :with_associations, -> { preload(:issue, vulnerability: [:project]) }
    scope :with_issues, -> { includes(:issue) }
    scope :by_vulnerability, ->(values) { where(vulnerability_id: values) }

    private

    def trigger_vulnerability_webhook_event
      vulnerability.trigger_webhook_event
    end
  end
end
