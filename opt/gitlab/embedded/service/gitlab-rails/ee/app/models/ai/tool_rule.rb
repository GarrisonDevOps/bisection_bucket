# frozen_string_literal: true

module Ai
  class ToolRule < ApplicationRecord
    self.table_name = 'ai_tool_rules'

    WEB_SURFACES = %w[web ambient].freeze

    belongs_to :namespace
    belongs_to :project, optional: true

    ACCESS_LEVELS = {
      ::Ai::ToolRules::Permissions::ALLOW => 0,
      ::Ai::ToolRules::Permissions::ASK => 1,
      ::Ai::ToolRules::Permissions::DENY => 2
    }.freeze

    BACKGROUND_ACCESS_LEVELS = ACCESS_LEVELS.except(::Ai::ToolRules::Permissions::ASK).freeze

    enum :web_access, ACCESS_LEVELS, prefix: true
    enum :local_access, ACCESS_LEVELS, prefix: true
    enum :background_access, BACKGROUND_ACCESS_LEVELS, prefix: true

    validates :tool_name,
      presence: true,
      inclusion: {
        in: ->(rule) {
          Ai::ToolRules::Registry.rulable_tool_names(
            mcp_tools: rule.governed_mcp_tools, first_party_tools: rule.governed_first_party_tools
          )
        },
        message: "%{value} is not a known tool name"
      },
      uniqueness: { scope: [:namespace_id, :project_id] }

    validates :tool_arguments, json_schema: { filename: 'ai_tool_rule_tool_arguments', size_limit: 64.kilobytes },
      allow_nil: true
    validates :namespace, presence: true

    validate :validate_access_permissions_present
    validate :project_belongs_to_namespace, if: -> { project_id.present? }
    validate :project_rule_not_looser_than_namespace, if: -> { project_id.present? }

    before_validation :set_tool_source

    scope :for_namespace, ->(namespace_id) { where(namespace_id: namespace_id, project_id: nil) }
    scope :for_project, ->(project_id) { where(project_id: project_id) }
    scope :within_namespace, ->(namespace_id) { where(namespace_id: namespace_id) }
    scope :for_namespace_and_projects, ->(namespace_id, project_ids) do
      where(namespace_id: namespace_id, project_id: [nil, *project_ids])
    end
    scope :for_tool_names, ->(tool_names) { where(tool_name: tool_names) }

    def self.projects_for(rules)
      project_ids = rules.filter_map(&:project_id).uniq
      return [] if project_ids.empty?

      ::Project.id_in(project_ids).includes(:namespace).to_a
    end

    def self.find_or_initialize_for_namespace(namespace_id:, tool_name:, project_id: nil)
      find_or_initialize_by(namespace_id: namespace_id, tool_name: tool_name, project_id: project_id)
    end

    def access_for(surface)
      return background_access if surface.to_s == ::Ai::ToolRules::GovernanceSurface::BACKGROUND.to_s

      WEB_SURFACES.include?(surface.to_s) ? web_access : local_access
    end

    def governed_mcp_tools
      ::Ai::ToolRules::GovernedMcpTools.for(namespace)
    end

    def governed_first_party_tools
      ::Ai::ToolRules::FirstPartyTools.for(namespace)
    end

    private

    def validate_access_permissions_present
      return if web_access.present? || local_access.present? || background_access.present?

      errors.add(:base, 'must have at least one of web_access, local_access, or background_access set')
    end

    def set_tool_source
      return if tool_name.blank?

      self.tool_source ||= Ai::ToolRules::Registry.source_for(
        tool_name, mcp_tools: governed_mcp_tools, first_party_tools: governed_first_party_tools
      )
    end

    def project_belongs_to_namespace
      return unless project && namespace

      return if project.root_namespace.id == namespace.id

      errors.add(:project, 'must belong to the namespace')
    end

    def project_rule_not_looser_than_namespace
      return unless project && namespace

      namespace_rule = ::Ai::ToolRule.for_namespace(namespace_id).find_by(tool_name: tool_name)
      validate_background_access_strictness(namespace_rule)
      return unless namespace_rule

      validate_web_access_strictness(namespace_rule)
      validate_local_access_strictness(namespace_rule)
    end

    def validate_web_access_strictness(namespace_rule)
      return unless web_access && namespace_rule.web_access
      return unless self.class.web_accesses[web_access] < self.class.web_accesses[namespace_rule.web_access]

      errors.add(:web_access, "cannot be less restrictive than the namespace rule (#{namespace_rule.web_access})")
    end

    def validate_local_access_strictness(namespace_rule)
      return unless local_access && namespace_rule.local_access
      return unless self.class.local_accesses[local_access] < self.class.local_accesses[namespace_rule.local_access]

      errors.add(:local_access, "cannot be less restrictive than the namespace rule (#{namespace_rule.local_access})")
    end

    # A group with no background value still binds projects through its fail-closed default.
    #
    # @param namespace_rule [Ai::ToolRule, nil]
    # @return [void]
    def validate_background_access_strictness(namespace_rule)
      return unless background_access

      rule_floor = namespace_rule&.background_access
      # A row saved before the opt-in can still be edited on other surfaces; enforcement ignores its value.
      return unless rule_floor || new_record? || will_save_change_to_background_access?

      floor = rule_floor || (::Ai::ToolRules::Permissions::DENY if fail_closed_denies_tool?)
      return unless floor

      levels = self.class.background_accesses
      return unless levels[background_access] < levels[floor]

      errors.add(:background_access,
        "cannot be less restrictive than the namespace #{rule_floor ? 'rule' : 'default'} (#{floor})")
    end

    # @return [Boolean] whether the namespace's fail-closed default denies this tool
    def fail_closed_denies_tool?
      ::Ai::ToolRules::GovernanceSurface.background_fail_closed?(namespace) &&
        ::Ai::ToolRules::GovernanceSurface.fail_closed_denies?(
          tool_name, mcp_tools: governed_mcp_tools, first_party_tools: governed_first_party_tools
        )
    end
  end
end
