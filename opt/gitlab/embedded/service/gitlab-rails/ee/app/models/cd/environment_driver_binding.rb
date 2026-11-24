# frozen_string_literal: true

module Cd
  class EnvironmentDriverBinding < ApplicationRecord
    self.table_name = 'cd_environment_driver_bindings'

    belongs_to :environment, class_name: 'Cd::Environment', inverse_of: :environment_driver_bindings,
      optional: false
    belongs_to :organization, class_name: '::Organizations::Organization', optional: false
    has_many :rollout_environments, class_name: 'Cd::RolloutEnvironment', inverse_of: :driver_binding

    populate_sharding_key :organization_id, source: :environment

    before_validation :assign_next_version, on: :create
    before_update :prevent_modification

    scope :ordered, -> { order(version: :desc) }
    scope :for_environment, ->(environment_id) { where(environment_id: environment_id) }

    validates :driver_ref, presence: true, length: { maximum: 255 }
    validates :version, presence: true, numericality: { only_integer: true, greater_than: 0 },
      uniqueness: { scope: :environment_id }
    validates :driver_config, json_schema: { filename: 'cd_environment_driver_config', size_limit: 64.kilobytes }
    validate :driver_config_matches_driver_schema, if: -> { driver_ref.present? }

    private

    def assign_next_version
      self.version = (self.class.for_environment(environment_id).maximum(:version) || 0) + 1
    end

    def prevent_modification
      raise ActiveRecord::ReadOnlyRecord, "#{self.class.name} is append-only and cannot be modified"
    end

    def driver_config_matches_driver_schema
      driver = ::Cd::DeployDrivers::Registry.find(driver_ref)

      return errors.add(:driver_ref, _('is not a recognized deploy driver.')) unless driver

      JSONSchemer.schema(driver.environment_schema).validate(driver_config).each do |error|
        errors.add(:driver_config, error['error'])
      end
    end
  end
end
