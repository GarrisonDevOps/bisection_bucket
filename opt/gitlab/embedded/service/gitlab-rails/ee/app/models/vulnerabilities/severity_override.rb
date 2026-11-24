# frozen_string_literal: true

module Vulnerabilities
  class SeverityOverride < ::SecApplicationRecord
    self.table_name = 'vulnerability_severity_overrides'

    belongs_to :vulnerability, class_name: 'Vulnerability', inverse_of: :severity_overrides
    belongs_to :author, class_name: 'User', inverse_of: :vulnerability_severity_overrides
    belongs_to :project, optional: false
    belongs_to :vulnerability_occurrence, optional: true, class_name: 'Vulnerabilities::Finding'
    belongs_to :security_policy, class_name: 'Security::Policy', optional: true

    validates :vulnerability, :project, :original_severity, :new_severity, presence: true
    validates :author, presence: true, on: :create
    validates :original_severity, presence: true,
      inclusion: { in: ::Enums::Vulnerability.severity_levels.keys }
    validates :new_severity, presence: true,
      inclusion: { in: ::Enums::Vulnerability.severity_levels.keys }
    validate :original_and_new_severity_differ?

    enum :original_severity, ::Enums::Vulnerability.severity_levels, prefix: true
    enum :new_severity, ::Enums::Vulnerability.severity_levels, prefix: true

    scope :latest, -> do
      joins(<<~SQL)
        JOIN LATERAL(
          SELECT
            *
          FROM
            vulnerability_severity_overrides vso
          WHERE
            vso.vulnerability_id = vulnerability_severity_overrides.vulnerability_id
          ORDER BY id DESC
          LIMIT 1
        ) AS vso ON vso.id = vulnerability_severity_overrides.id
      SQL
    end

    scope :by_vulnerability, ->(values) { where(vulnerability_id: values) }
    scope :with_author, -> { includes(:author) }
    scope :triggered_by_policy, -> { where(triggered_by_policy: true) }
    scope :manual, -> { where(triggered_by_policy: false) }

    def author_data
      return unless author

      @author_data ||=
        {
          author: {
            name: author.name,
            web_url: Gitlab::Routing.url_helpers.user_path(username: author.username)
          }
        }
    end

    private

    def original_and_new_severity_differ?
      return unless original_severity.present? && new_severity.present?
      return if original_severity != new_severity

      errors.add(:new_severity, "must not be the same as original severity")
    end
  end
end
