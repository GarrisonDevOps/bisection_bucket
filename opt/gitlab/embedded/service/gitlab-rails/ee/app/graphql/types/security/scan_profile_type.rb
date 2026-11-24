# frozen_string_literal: true

module Types
  module Security
    # rubocop:disable Graphql/AuthorizeTypes -- Authorization occurs at parent level
    class ScanProfileType < BaseObject
      graphql_name 'ScanProfileType'
      description 'A scan profile.'

      REMEDIATION_TRIGGER_TYPE = 'sbom_ingested'

      def self.authorization_scopes
        super + [:ai_workflows]
      end

      field :created_at,
        type: GraphQL::Types::ISO8601DateTime,
        null: false,
        description: 'Timestamp of when the scan profile was created.',
        scopes: [:api, :read_api, :ai_workflows]

      field :description,
        type: GraphQL::Types::String,
        null: false,
        description: 'Description of the security scan profile.',
        scopes: [:api, :read_api, :ai_workflows]

      field :gitlab_recommended,
        type: GraphQL::Types::Boolean,
        null: false,
        description: 'Indicates whether the scan profile is a default profile.',
        scopes: [:api, :read_api, :ai_workflows]

      field :id,
        type: ::Types::GlobalIDType[::Security::ScanProfile],
        null: true,
        resolver_method: :resolve_id,
        description: 'Global ID of the security scan profile.',
        scopes: [:api, :read_api, :ai_workflows]

      field :name,
        type: GraphQL::Types::String,
        null: false,
        description: 'Name of the security scan profile.',
        scopes: [:api, :read_api, :ai_workflows]

      field :scan_type,
        type: Types::Security::ScanProfileTypeEnum,
        null: false,
        description: 'Scan profile type.',
        scopes: [:api, :read_api, :ai_workflows]

      field :triggers,
        type: [Types::Security::ScanProfileTriggerTypeEnum],
        null: false,
        description: 'Trigger types for the scan profile.',
        experiment: { milestone: '18.10' },
        scopes: [:api, :read_api, :ai_workflows]

      field :updated_at,
        type: GraphQL::Types::ISO8601DateTime,
        null: false,
        description: 'Timestamp of when the scan profile was last updated.',
        scopes: [:api, :read_api, :ai_workflows]

      field :configuration, GraphQL::Types::JSON, # rubocop:disable Graphql/JSONType -- Schema and structure have not been decided yet.
        null: false,
        description: 'Configuration object of the scan profile.',
        experiment: { milestone: '19.2' },
        scopes: [:api, :read_api, :ai_workflows]

      field :trigger_settings, [::Types::Security::ScanProfiles::TriggerSettingType],
        null: false,
        description: 'Trigger settings, including effective configuration, for the scan profile.',
        experiment: { milestone: '19.3' },
        scopes: [:api, :read_api, :ai_workflows], method: :scan_profile_triggers

      field :project_count, GraphQL::Types::Int,
        null: false,
        experiment: { milestone: '19.5' },
        description: 'Number of projects the scan profile is attached to, excluding archived projects.',
        scopes: [:api, :read_api, :ai_workflows]

      def resolve_id
        object.persisted? ? object.to_global_id : ::Gitlab::GlobalId.build(object, id: object.preset_key)
      end

      def triggers
        object.scan_profile_triggers.map(&:trigger_type)
      end

      def configuration
        return {} unless object.scan_profile_triggers.any? { |t| t.trigger_type == REMEDIATION_TRIGGER_TYPE }

        object.effective_configuration_for(REMEDIATION_TRIGGER_TYPE)
      end

      def project_count
        return 0 unless object.persisted?

        ::BatchLoader::GraphQL.for(object.id).batch(default_value: 0) do |ids, loader|
          counts = ::Security::ScanProfile.project_counts_by_id(ids)
          counts.each { |id, count| loader.call(id, count) }
        end
      end
    end
    # rubocop:enable Graphql/AuthorizeTypes
  end
end
