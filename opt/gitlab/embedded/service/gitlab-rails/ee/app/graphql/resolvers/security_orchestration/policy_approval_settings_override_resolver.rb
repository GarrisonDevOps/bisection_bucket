# frozen_string_literal: true

module Resolvers
  module SecurityOrchestration # rubocop:disable Gitlab/BoundedContexts -- Existing module
    class PolicyApprovalSettingsOverrideResolver < BaseResolver
      include Gitlab::Graphql::Authorize::AuthorizeResource

      type ::Types::SecurityOrchestration::PolicyApprovalSettingsOverrideType, null: true

      authorizes_object!
      authorize :read_security_resource

      description 'Approval settings overridden by policies for the merge request.'

      def resolve(**_args)
        object.policies_overriding_approval_settings.map do |policy, settings|
          { name: policy.name, edit_path: policy.edit_path, settings: settings }
        end
      end
    end
  end
end
