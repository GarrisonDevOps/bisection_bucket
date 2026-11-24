# frozen_string_literal: true

module EE
  module Resolvers
    module GroupsResolver # rubocop:disable Gitlab/BoundedContexts -- EE extension of CE GroupsResolver
      extend ActiveSupport::Concern
      extend ::Gitlab::Utils::Override

      prepended do
        argument :with_knowledge_graph_enabled, GraphQL::Types::Boolean,
          required: false,
          default_value: false,
          experiment: { milestone: '18.10' },
          description: 'Return only groups with Knowledge Graph enabled.'

        argument :with_duo_agent_platform_enabled, GraphQL::Types::Boolean,
          required: false,
          default_value: false,
          experiment: { milestone: '19.6' },
          description: 'Return only groups whose top-level group has Duo Agent Platform turned on. ' \
            'On GitLab Self-Managed and GitLab Dedicated, returns no groups when Duo Agent Platform ' \
            'is turned off for the instance.'
      end
    end
  end
end
