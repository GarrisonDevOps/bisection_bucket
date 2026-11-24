# frozen_string_literal: true

module Mutations
  module Security
    module ScanProfiles
      class Delete < BaseMutation
        graphql_name 'SecurityScanProfileDelete'

        include Gitlab::InternalEventsTracking

        AUDIT_EVENT_NAME = 'security_scan_profile_delete'

        authorize :delete_security_scan_profiles
        authorize_granular_token permissions: :delete_security_scan_profiles, boundary_argument: :id,
          boundary: :namespace, boundary_type: :group

        argument :id, ::Types::GlobalIDType[::Security::ScanProfile],
          required: true,
          description: 'Global ID of the scan profile to delete.'

        field :deleted_scan_profile_id, ::Types::GlobalIDType[::Security::ScanProfile],
          null: true,
          description: 'Global ID of the deleted scan profile.'

        def resolve(id:)
          profile = authorized_find!(id: id)
          raise_resource_not_available_error! if profile.deleted?

          namespace = profile.namespace

          return not_deletable_error if profile.gitlab_recommended?

          profile.destroy
          audit_deletion(profile)

          # rubocop:disable CodeReuse/Worker -- Hard delete and join-record cleanup run asynchronously
          ::Security::ScanProfiles::DeleteScanProfilesWorker.perform_async([profile.id], namespace.id)
          # rubocop:enable CodeReuse/Worker

          track_internal_event('delete_scan_profile', user: current_user, namespace: namespace)

          { deleted_scan_profile_id: profile.to_global_id, errors: [] }
        end

        private

        def audit_deletion(profile)
          ::Gitlab::Audit::Auditor.audit(
            name: AUDIT_EVENT_NAME,
            author: current_user,
            scope: profile.namespace,
            target: profile,
            message: "Deleted security scan profile '#{profile.name}'",
            additional_details: {
              organization_id: profile.namespace.organization_id,
              profile_id: profile.id,
              scan_type: profile.scan_type,
              trigger_types: profile.scan_profile_triggers.map(&:trigger_type)
            }
          )
        end

        def not_deletable_error
          # GitLab-recommended profiles are system-managed and cannot be deleted.
          {
            deleted_scan_profile_id: nil,
            errors: [s_('SecurityScanProfile|Cannot delete a GitLab-recommended scan profile.')]
          }
        end

        def find_object(id:)
          GitlabSchema.object_from_id(id)
        end
      end
    end
  end
end
