# frozen_string_literal: true

module Resolvers
  module ComplianceManagement
    module ComplianceFramework
      class FrameworksNeedingAttentionResolver < BaseResolver
        include Gitlab::Graphql::Authorize::AuthorizeResource

        alias_method :group, :object

        type [::Types::ComplianceManagement::ComplianceFramework::FrameworksNeedingAttentionType],
          null: true
        description 'Frameworks that need attention (no projects or no requirements).'

        authorize :read_compliance_dashboard
        authorizes_object!

        def resolve(**_args)
          return unless group

          root_group = group.root_ancestor

          frameworks = root_group.compliance_management_frameworks.needing_attention_for_group(group)

          offset_pagination(frameworks)
        end
      end
    end
  end
end
