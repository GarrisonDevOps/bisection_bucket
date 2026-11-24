# frozen_string_literal: true

module Types
  module Ai
    module DuoWorkflows
      # rubocop: disable Graphql/AuthorizeTypes -- served to anyone who can read the parent object on purpose:
      # the payload says an agent posted it and userPermissions.readDuoWorkflow says whether the
      # viewer may open the session.
      class AgentPresenceType < Types::BaseObject
        graphql_name 'DuoWorkflowAgentPresence'
        description 'Agent attribution for an object, such as a note, created by a GitLab Duo Agent Platform session.'
        present_using ::Ai::DuoWorkflows::AgentPresencePresenter

        authorize_granular_token skip_reason: :parent_authorizes

        FIELD_SCOPES = [:api, :read_api, :ai_features, :ai_workflows].freeze

        def self.authorization_scopes
          FIELD_SCOPES
        end

        field :session_id, Types::GlobalIDType[::Ai::DuoWorkflows::Workflow],
          scopes: FIELD_SCOPES,
          null: false,
          description: 'Global ID of the session that created the object.'

        # rubocop:disable GraphQL/ExtractType -- kept flat to match DuoWorkflow.agentName
        field :agent_name, GraphQL::Types::String,
          scopes: FIELD_SCOPES,
          null: true,
          description: 'Name of the agent that ran the session.'

        field :agent_catalog_web_path, GraphQL::Types::String,
          scopes: FIELD_SCOPES,
          null: true,
          description: 'Web path of the agent in the AI Catalog. Null when the agent has no catalog profile.'
        # rubocop:enable GraphQL/ExtractType

        # rubocop:disable GraphQL/ExtractType -- flat session-origin fields, as on DuoWorkflow
        field :source_type, Types::Ai::DuoWorkflows::WorkflowSourceTypeEnum,
          scopes: FIELD_SCOPES,
          null: true,
          description: 'Type of source that initiated the session.'

        field :source_link, GraphQL::Types::String,
          scopes: FIELD_SCOPES,
          null: true,
          authorize: :read_duo_workflow,
          description: 'URL or deep link to the location where the session was triggered from. ' \
            'Null unless the current user can read the session.'
        # rubocop:enable GraphQL/ExtractType

        field :trigger_source, Types::Ai::DuoWorkflows::WorkflowTriggerSourceEnum,
          scopes: FIELD_SCOPES,
          null: true,
          description: 'Kind of initiator that started the session.'

        field :flow_trigger, ::Types::Ai::FlowTriggerType,
          scopes: FIELD_SCOPES,
          null: true,
          description: 'Flow trigger (automation) that started the session. Event-based sessions also have a ' \
            'trigger, so use `triggerSource` to detect scheduled sessions. Null when the trigger was deleted ' \
            'or the current user cannot read it.',
          experiment: { milestone: '19.6' }

        field :user, ::Types::UserType,
          scopes: FIELD_SCOPES,
          null: true,
          description: 'User the session ran as. For triggered sessions, the account the trigger runs with.'

        field :user_permissions, Types::PermissionTypes::Ai::DuoWorkflows::AgentPresence,
          scopes: FIELD_SCOPES,
          null: false,
          method: :itself,
          description: 'Permissions for the current user on the session.'
      end
      # rubocop: enable Graphql/AuthorizeTypes
    end
  end
end
