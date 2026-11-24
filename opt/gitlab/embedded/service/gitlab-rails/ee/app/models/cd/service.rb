# frozen_string_literal: true

module Cd
  class Service < ApplicationRecord
    include Gitlab::SQL::Pattern

    self.table_name = 'cd_services'

    belongs_to :application, class_name: 'Cd::Application', inverse_of: :services, optional: false
    belongs_to :organization, class_name: '::Organizations::Organization', optional: false
    has_many :artifact_sources, class_name: 'Cd::ArtifactSource', inverse_of: :service
    # Ordered worst-to-best severity (see Cd::ServiceEnvironmentHealth.ordered_by_severity), so
    # consumers that only need the worst observed health can take the first record instead of
    # fetching and reducing the full connection themselves.
    has_many :service_environment_healths, -> { ordered_by_severity },
      class_name: 'Cd::ServiceEnvironmentHealth', inverse_of: :service

    populate_sharding_key :organization_id, source: :application

    scope :in_organization, ->(organization) { where(organization_id: organization) }
    scope :search, ->(query) { fuzzy_search(query, [:name, :description]) }
    scope :with_name, ->(name) { where(name: name) }

    validates :name, presence: true, length: { maximum: 255 }, uniqueness: { scope: :application_id },
      format: { with: Gitlab::Regex.cd_name_regex, message: Gitlab::Regex.cd_name_regex_message }
    validates :description, length: { maximum: 2000 }
  end
end
