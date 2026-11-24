# frozen_string_literal: true

module Ai
  module Catalog
    class ItemVersion < ApplicationRecord
      AGENT_SCHEMA_VERSION = 1
      AGENT_REFERENCED_FLOW_SCHEMA_VERSION = 1
      FLOW_SCHEMA_VERSION = 2
      THIRD_PARTY_FLOW_SCHEMA_VERSION = 1
      SKILL_SCHEMA_VERSION = 1
      DEFINITION_ACCESSOR_PREFIX = 'def_'

      VERSION_BUMP_MAJOR = :major
      VERSION_BUMP_MINOR = :minor
      VERSION_BUMP_PATCH = :patch
      VERSION_BUMP_OPTIONS = [VERSION_BUMP_MAJOR, VERSION_BUMP_MINOR, VERSION_BUMP_PATCH].freeze
      DEPRECATION_ATTRIBUTES = %w[deprecated].freeze
      DEFINITION_SIZE_LIMIT = 80.kilobytes
      # Separate YAML limit lets errors state a size that matches what authors wrote, as it's stored at roughly double.
      YAML_DEFINITION_SIZE_LIMIT = DEFINITION_SIZE_LIMIT / 2
      # How many `mcp_servers` the agent create and update mutations accept. A read takes a
      # stored list as is: versions saved before the cap may hold more.
      MCP_SERVERS_LIMIT = 20

      self.table_name = "ai_catalog_item_versions"

      attr_accessor :dws_flow_config_validated

      validates :definition, :schema_version, :version, presence: true

      validates :version, length: { maximum: 50 }
      validates :version, uniqueness: { scope: :item }
      validates :version, format: { with: /\A\d+\.\d+\.\d+\z/ }
      validates :definition,
        format: { without: Gitlab::Unicode::DANGEROUS_CHARS, message: 'contains disallowed characters' },
        if: :definition_changed?

      validate :validate_yaml_definition_size, if: :definition_changed?
      validate :validate_json_schema
      validate :validate_readonly
      validate :require_dws_flow_config_validation

      belongs_to :item, class_name: 'Ai::Catalog::Item',
        foreign_key: :ai_catalog_item_id, inverse_of: :versions, optional: false
      belongs_to :organization, class_name: 'Organizations::Organization'
      belongs_to :created_by, class_name: 'User'

      has_many :dependencies, class_name: 'Ai::Catalog::ItemVersionDependency', inverse_of: :ai_catalog_item_version

      has_one :project, through: :item

      before_create :populate_organization

      delegate :flow?, to: :item

      scope :created_after, ->(created_after) { where(created_at: created_after..) }
      scope :for_public_items, -> { joins(:item).where(item: { visibility: :public }) }
      scope :in_organization, ->(organization) { where(organization: organization) }
      scope :not_deprecated, -> { where(deprecated: false) }
      scope :order_by_id_desc, -> { order(id: :desc) }
      scope :released, -> { where.not(release_date: nil) }

      scope :with_items, -> { includes(:item) }
      scope :with_organization, -> { includes(:organization) }
      scope :for_item_version_pairs, ->(item_version_pairs) {
        where([:ai_catalog_item_id, :version] => item_version_pairs)
      }

      def self.flow_config_from(definition)
        definition&.except('yaml_definition', :yaml_definition)
      end

      def self.yaml_definition_too_large?(yaml)
        yaml.is_a?(String) && yaml.bytesize > YAML_DEFINITION_SIZE_LIMIT
      end

      # Same measure as the JsonSchemaValidator size_limit in validate_json_schema.
      def self.definition_too_large?(definition)
        Gitlab::Json.dump(definition).bytesize > DEFINITION_SIZE_LIMIT
      end

      def self.yaml_size_error_message
        format(s_('AICatalog|YAML is too large. Maximum size is %{size}'),
          size: ActiveSupport::NumberHelper.number_to_human_size(YAML_DEFINITION_SIZE_LIMIT))
      end

      def self.definition_size_error_message
        format(s_('AICatalog|Definition is too large. Maximum size is %{size}'),
          size: ActiveSupport::NumberHelper.number_to_human_size(DEFINITION_SIZE_LIMIT))
      end

      def flow_config
        self.class.flow_config_from(definition)
      end

      def human_version
        return if version.nil?

        human_version = "v#{version}"
        return human_version if released?

        "#{human_version}-draft"
      end

      def released?
        release_date.present?
      end

      def draft?
        !released?
      end

      def version_bump(bump_level)
        return if version.nil?
        raise ArgumentError, "unknown bump_level: #{bump_level}" unless bump_level.in?(VERSION_BUMP_OPTIONS)

        old_version = Gitlab::VersionInfo.parse(version)

        new_version = case bump_level.to_sym
                      when VERSION_BUMP_MAJOR
                        [old_version.major + 1, 0, 0]
                      when VERSION_BUMP_MINOR
                        [old_version.major, old_version.minor + 1, 0]
                      when VERSION_BUMP_PATCH
                        [old_version.major, old_version.minor, old_version.patch + 1]
                      end

        Gitlab::VersionInfo.new(*new_version).to_s
      end

      private

      def respond_to_missing?(name, include_private)
        name.starts_with?(DEFINITION_ACCESSOR_PREFIX) || super
      end

      def method_missing(method_name, *args, &block)
        return super unless method_name.starts_with?(DEFINITION_ACCESSOR_PREFIX)

        definition[method_name.to_s.delete_prefix(DEFINITION_ACCESSOR_PREFIX)]
      end

      def validate_yaml_definition_size
        return unless yaml_definition_too_large?

        errors.add(:definition, self.class.yaml_size_error_message)
      end

      def yaml_definition_too_large?
        definition.is_a?(Hash) && self.class.yaml_definition_too_large?(definition['yaml_definition'])
      end

      def validate_json_schema
        return errors.add(:definition, s_('AICatalog|unable to validate definition')) unless item && schema_version
        return if definition_changed? && yaml_definition_too_large?

        JsonSchemaValidator.new({
          attributes: :definition,
          base_directory: %w[app validators json_schemas ai_catalog],
          filename: json_schema_filename,
          size_limit: DEFINITION_SIZE_LIMIT,
          detail_errors: true
        }).validate(self)
      end

      def json_schema_filename
        "#{item.item_type}_v#{schema_version}"
      end

      def validate_readonly
        return unless release_date_was.present? && changed?
        return if changed == DEPRECATION_ATTRIBUTES

        errors.add(:base, s_('AICatalog|can\'t be changed because it is released'))
      end

      def require_dws_flow_config_validation
        return unless item
        return unless new_record? || definition_changed?
        return if dws_flow_config_validated

        if item.custom_flow?
          errors.add(:base, s_('AICatalog|Flow definition must be validated by Duo Workflow Service before saving'))
        elsif item.custom_agent?
          errors.add(:base, s_('AICatalog|Agent definition must be validated by Duo Workflow Service before saving'))
        end
      end

      def populate_organization
        self.organization ||= item.organization
      end
    end
  end
end
