# frozen_string_literal: true

module Mutations
  module Security
    class UpdateTrackedContextQuota < BaseMutation
      graphql_name 'SecurityUpdateTrackedContextQuota'
      description 'Updates the tracked security context quota for an organization.'

      authorize :update_organization
      authorize_granular_token permissions: :update_organization, boundary: :instance, boundary_type: :instance

      argument :organization_id, ::Types::GlobalIDType[::Organizations::Organization],
        required: true,
        description: 'Organization to update the quota for.'

      argument :quota, GraphQL::Types::Int,
        required: true,
        description: 'New tracked security context quota limit for the organization.'

      field :quota_info, ::Types::Security::TrackedContextQuotaType,
        null: true,
        description: 'Updated tracked security context quota information.'

      def resolve(organization_id:, quota:)
        organization = authorized_find!(id: organization_id)

        if ::Security::VAC.disabled?(organization)
          raise_resource_not_available_error!(
            'Vulnerabilities Across Contexts is not enabled for this organization.'
          )
        end

        quota_service = ::Security::TrackedContextQuotaService.new(organization)
        setting = quota_service.organization_setting
        previous_quota = setting.security_tracked_context_quota

        unless setting.update(security_tracked_context_quota: quota)
          return { quota_info: nil, errors: setting.errors.full_messages }
        end

        audit_quota_change(organization, previous_quota, quota) unless previous_quota == quota

        { quota_info: quota_service.quota_info, errors: [] }
      end

      private

      def audit_quota_change(organization, previous_quota, quota)
        ::Gitlab::Audit::Auditor.audit(
          name: 'security_tracked_context_quota_updated',
          author: current_user,
          scope: ::Gitlab::Audit::InstanceScope.new,
          target: organization,
          message: "Changed the tracked security context quota for organization '#{organization.name}' " \
            "from #{previous_quota.nil? ? 'the default' : previous_quota} to #{quota}"
        )
      end
    end
  end
end
