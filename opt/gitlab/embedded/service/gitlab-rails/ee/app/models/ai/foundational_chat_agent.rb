# frozen_string_literal: true

module Ai
  class FoundationalChatAgent
    include ActiveRecord::FixedItemsModel::Model
    include GlobalID::Identification
    include Ai::FoundationalChatAgentsDefinitions
    include ::Gitlab::Utils::StrongMemoize

    CHAT_REFERENCES = %w[chat agentic_chat].freeze

    attribute :reference, :string
    attribute :name, :string
    attribute :description, :string
    attribute :version, :string
    attribute :flow_version, :string
    attribute :global_catalog_id, :integer
    attribute :avatar, :string
    attribute :ultimate_only, :boolean, default: false
    attribute :selectable_in_chat, :boolean, default: true
    attribute :item_type, :integer # Maps to the Ai::Catalog::Item.item_type types
    attribute :visibility, :integer
    attribute :verification_level, :integer
    attribute :tools, default: []
    attribute :suggested_questions, default: []
    # Nil means Ai::Catalog::CodingEnvironment::DEFAULT, as for an undeclared flow.
    attribute :coding_environment, :string
    # What web chat grants every agent.
    attribute :agent_privileges, default: [
      ::Ai::DuoWorkflows::Workflow::AgentPrivileges::READ_ONLY_GITLAB,
      ::Ai::DuoWorkflows::Workflow::AgentPrivileges::READ_WRITE_GITLAB,
      ::Ai::DuoWorkflows::Workflow::AgentPrivileges::START_FLOWS
    ].freeze
    attribute :pre_approved_agent_privileges, default: [
      ::Ai::DuoWorkflows::Workflow::AgentPrivileges::READ_ONLY_GITLAB
    ].freeze

    validates :name, :reference, :description, presence: true
    validates :coding_environment, inclusion: { in: ::Ai::Catalog::CodingEnvironment::VALUES.keys }, allow_nil: true

    strong_memoize_attr def system_prompt
      prompt_file = File.join(Ai::FoundationalChatAgentsDefinitions::SYSTEM_PROMPTS_PATH, "#{reference}.md")

      return unless File.exist?(prompt_file)

      File.read(prompt_file)
    end

    def built_in_tools
      ::Ai::Catalog::BuiltInTool.where(name: tools.map(&:to_s))
    end

    def item_type
      Ai::Catalog::Item.item_types.key(super)
    end

    def visibility
      Ai::Catalog::Item.visibilities.key(super)
    end

    def reference_with_version
      return reference if version.blank?

      "#{reference}/#{version}"
    end

    def workflow_definition
      reference_with_version
    end

    def to_global_id
      reference_with_version.sub('/', '-')
    end

    def duo_chat?
      CHAT_REFERENCES.include?(reference)
    end

    def licensed_for?(namespace)
      !ultimate_only || namespace.licensed_feature_available?(:ai_features)
    end

    # Whether the Duo settings page lists the agent for the namespace: the Orbit agent needs the Knowledge
    # Graph service, Ultimate-only agents the license.
    def listed_for?(namespace, user = nil)
      return false if reference == 'orbit_agent' && !::Analytics::KnowledgeGraph.enabled_for?(user)

      licensed_for?(namespace)
    end

    class << self
      # Generates a SQL VALUES clause for use in UNION queries.
      # Column overrides allow injecting dynamic values not stored in ITEMS
      # (e.g. organization_id which varies per request).
      def to_sql(columns_with_types:, column_overrides: {})
        values = raw_items.map do |item|
          values_with_cast = columns_with_types.map do |column, type|
            value = column_overrides.key?(column) ? column_overrides[column] : item[column]

            "#{ApplicationRecord.connection.quote(value)}::#{type}"
          end

          "(#{values_with_cast.join(', ')})"
        end

        quoted_column_names = columns_with_types.keys.map do |column|
          ApplicationRecord.connection.quote_column_name(column)
        end

        <<~SQL
          SELECT #{quoted_column_names.join(',')} FROM (VALUES #{values.join(', ')})
          AS fixed_items_table(#{quoted_column_names.join(', ')})
        SQL
      end

      def only_duo_chat_agent
        # The first agent must always Duo Chat Agent, this is covered through tests.
        # Duo chat has to be the first so it shows first in the UI
        all.select { |i| CHAT_REFERENCES.include?(i.reference) }
      end

      def except_duo_chat_agent
        # The first agent must always Duo Chat Agent, this is covered through tests.
        # Duo chat has to be the first so it shows first in the UI
        all.select { |i| CHAT_REFERENCES.exclude?(i.reference) }
      end

      def count
        all.size
      end

      def foundational_workflow_definition?(definition)
        all.any? { |agent| agent.workflow_definition == definition }
      end

      # Exact, unlike with_workflow_definition, which also matches a version that does not exist.
      def find_by_workflow_definition(definition)
        all.find { |agent| agent.workflow_definition == definition }
      end

      def mcp_workhorse_session?(workflow_definition, user)
        foundational_workflow_definition?(workflow_definition) &&
          ::Ai::Catalog::CodingEnvironment.default_runtime_for(workflow_definition) == :workhorse &&
          Feature.enabled?(:mcp_duo_agent_sessions_on_workhorse, user)
      end

      def reference_from_workflow_definition(definition)
        definition.split("/")[0]
      end

      def workflow_definitions
        all.map(&:workflow_definition)
      end

      def any_agents_with_reference?(definition)
        !!where(reference: definition).first
      end

      def with_workflow_definition(definition)
        return if definition.nil?

        where(reference: reference_from_workflow_definition(definition)).first
      end

      def ultimate_only_references
        all.select(&:ultimate_only).map(&:reference).to_set
      end

      def find_by_reference(reference)
        find_by(reference: reference)
      end

      def for_catalog_item(catalog_id)
        return if catalog_id.nil?

        find_by(global_catalog_id: catalog_id)
      end
    end
  end
end
