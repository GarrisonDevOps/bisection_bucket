# frozen_string_literal: true

module Cd
  class Environment < ApplicationRecord
    include Gitlab::SQL::Pattern

    self.table_name = 'cd_environments'

    belongs_to :organization, class_name: '::Organizations::Organization', optional: false
    has_many :environment_driver_bindings, class_name: 'Cd::EnvironmentDriverBinding', inverse_of: :environment
    has_many :rollout_environments, class_name: 'Cd::RolloutEnvironment', inverse_of: :environment
    has_many :service_environment_healths, class_name: 'Cd::ServiceEnvironmentHealth', inverse_of: :environment

    validates :name, presence: true, length: { maximum: 255 }, uniqueness: { scope: :organization_id },
      format: { with: Gitlab::Regex.cd_name_regex, message: Gitlab::Regex.cd_name_regex_message }
    validates :description, length: { maximum: 1024 }
    validates :tier, presence: true

    enum :tier, { development: 0, qa: 1, staging: 2, production: 3 }

    scope :for_organization, ->(organization_id) { where(organization_id: organization_id) }
    scope :in_organization, ->(organization) { where(organization_id: organization) }
    scope :with_tier, ->(tier) { where(tier: tier) }
    scope :with_name, ->(name) { where(name: name) }
    scope :for_application, ->(application_id) {
      where(id: ::Cd::ServiceEnvironmentHealth.environment_ids_for_application(application_id))
    }
    scope :order_by_name_asc, -> { order(name: :asc) }
    scope :preload_environment_driver_bindings, -> { preload(:environment_driver_bindings) }
    scope :search, ->(query) { fuzzy_search(query, [:name, :description]) }

    scope :with_worst_health, ->(healths, organization:) {
      where(id: ::Cd::ServiceEnvironmentHealth.environment_ids_with_worst_health(healths, organization: organization))
    }

    scope :deploying, ->(organization:) {
      where(id: ::Cd::RolloutEnvironment.in_progress.in_organization(organization).select(:environment_id))
    }

    scope :with_status, ->(status, organization:) {
      case status
      when 'healthy' then with_worst_health('healthy', organization: organization)
      # failed folds into degraded: the UX has no Failed tab.
      when 'degraded' then with_worst_health(%w[degraded failed], organization: organization)
      when 'deploying' then deploying(organization: organization)
      else none
      end
    }
  end
end
