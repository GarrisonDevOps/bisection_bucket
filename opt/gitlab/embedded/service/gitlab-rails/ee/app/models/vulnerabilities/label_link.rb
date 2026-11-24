# frozen_string_literal: true

module Vulnerabilities
  # Links a label to a vulnerability. Labels live in the main database and vulnerabilities in the Sec database,
  # so the polymorphic `label_links` table can't be used.
  #
  # `project_id` has a loose foreign key to `projects`. `label_id` deliberately has no foreign key: label promotion
  # destroys the merged labels in the same transaction that moves their links, so a loose foreign key would delete
  # the links before they could be moved. Workers keep the links correct when labels are promoted, transferred or
  # deleted.
  class LabelLink < ::SecApplicationRecord
    self.table_name = 'vulnerability_label_links'
    self.primary_key = %i[vulnerability_id label_id]

    belongs_to :vulnerability, inverse_of: :label_links, optional: false
    belongs_to :label, optional: false
    belongs_to :project, optional: false

    validates :label_id, uniqueness: { scope: :vulnerability_id }
    validate :project_matches_vulnerability

    populate_sharding_key :project_id, source: :vulnerability

    private

    def project_matches_vulnerability
      return if vulnerability.nil? || project_id == vulnerability.project_id

      errors.add(:project_id, 'must match the vulnerability project')
    end
  end
end
