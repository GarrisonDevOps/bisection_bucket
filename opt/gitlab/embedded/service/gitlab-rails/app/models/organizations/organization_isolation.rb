# frozen_string_literal: true

module Organizations
  class OrganizationIsolation < IsolationRecord
    belongs_to :organization, class_name: 'Organizations::Organization', inverse_of: :isolated_record

    validates :organization, presence: true

    def self.isolated_organization?(organization_id)
      exists?(organization_id: organization_id, isolated: true)
    end
  end
end
