# frozen_string_literal: true

module Cd
  class ApplicationFlowDefinition < ApplicationRecord
    include FileStoreMounter

    self.table_name = 'cd_application_flow_definitions'

    DEFINITION_SIZE_LIMIT = 1.megabyte

    belongs_to :application, class_name: 'Cd::Application', inverse_of: :application_flow_definitions, optional: false

    mount_file_store_uploader Cd::ApplicationFlowDefinitionUploader

    populate_sharding_key :organization_id do
      application&.organization_id
    end

    before_validation :assign_next_version, on: :create
    before_update :prevent_modification

    validates :version, presence: true,
      numericality: { only_integer: true, greater_than: 0 },
      uniqueness: { scope: :application_id }
    validates :definition, presence: true, length: { maximum: DEFINITION_SIZE_LIMIT }
    validate :application_belongs_to_organization
    validate :definition_is_valid_yaml, if: -> { definition.present? }
    validate :definition_matches_flow_schema, if: -> { definition.present? && errors[:definition].empty? }

    scope :for_application, ->(application_id) { where(application_id: application_id) }
    scope :ordered, -> { order(version: :desc) }

    def definition
      return @definition if defined?(@definition)

      @definition = file.read&.force_encoding(Encoding::UTF_8)
    end

    def definition=(content)
      prevent_modification if persisted?

      @definition = content

      self.file = CarrierWaveStringFile.new(content) if content
    end

    def revert_to_previous_version
      previous = versions.where(version: ...version).ordered.first
      return unless previous

      self.class.create!(
        application_id: application_id,
        organization_id: organization_id,
        definition: previous.definition
      )
    end

    private

    def versions
      self.class.for_application(application_id)
    end

    def assign_next_version
      self.version = (versions.maximum(:version) || 0) + 1
    end

    def prevent_modification
      raise ActiveRecord::ReadOnlyRecord, "#{self.class.name} is append-only and cannot be modified"
    end

    def application_belongs_to_organization
      return if application.blank? || organization_id.blank?
      return if application.organization_id == organization_id

      errors.add(:application, _('must belong to the same organization.'))
    end

    def definition_is_valid_yaml
      parsed_definition
    rescue Psych::Exception => e
      errors.add(:definition, format(_('is not valid YAML: %{message}'), message: e.message))
    end

    # Reuses the document parsed by definition_is_valid_yaml, which this validation
    # only runs after, to avoid parsing (and rescuing) the same YAML twice.
    def definition_matches_flow_schema
      ::Cd::DeployDrivers::FlowDefinitionValidator.new(
        document: parsed_definition, drivers: registered_drivers, organization_id: organization_id
      ).errors.each { |message| errors.add(:definition, message) }
    end

    def parsed_definition
      @parsed_definition ||= YAML.safe_load(definition)
    end

    def registered_drivers
      ::Cd::DeployDrivers::Registry.driver_refs.filter_map { |ref| ::Cd::DeployDrivers::Registry.find(ref) }
    end
  end
end
