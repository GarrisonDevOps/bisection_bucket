# frozen_string_literal: true

module Cd
  class ApplicationLink < ApplicationRecord
    self.table_name = 'cd_application_links'

    belongs_to :application, class_name: 'Cd::Application', inverse_of: :application_links, optional: false
    belongs_to :organization, class_name: '::Organizations::Organization', optional: false

    populate_sharding_key :organization_id, source: :application

    validates :name, presence: true, length: { maximum: 255 }
    validates :url, presence: true, length: { maximum: 2048 },
      addressable_url: { schemes: %w[http https] },
      uniqueness: { scope: :application_id }
    validates :link_type, presence: true
    validate :application_belongs_to_organization

    enum :link_type, {
      runbook: 0,
      dashboard: 1,
      docs: 2,
      repository: 3,
      chat: 4,
      issue_tracker: 5,
      on_call: 6,
      change_request: 7,
      other: 8
    }

    private

    def application_belongs_to_organization
      return if application.blank? || organization_id.blank?
      return if application.organization_id == organization_id

      errors.add(:application, _('must belong to the same organization.'))
    end
  end
end
