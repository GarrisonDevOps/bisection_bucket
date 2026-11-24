# frozen_string_literal: true

module Mutations
  module Security
    module ScanProfiles
      class Attach < BaseMutation
        graphql_name 'SecurityScanProfileAttach'

        include Gitlab::InternalEventsTracking
        include Mutations::Security::ScanProfiles::SharedScopeResolution

        description "Attaches a security scan profile to projects and groups. " \
          "All projects and groups must belong to the same top-level group. " \
          "Maximum of #{MAX_IDS} project and group IDs combined."

        argument :security_scan_profile_id, Types::GlobalIDType[::Security::ScanProfile],
          required: true,
          description: 'Security scan profile ID to attach. For a default profile, use its identifier. ' \
            'For example, `gid://gitlab/Security::ScanProfile/sast`.',
          prepare: ->(global_id, _ctx) { global_id.model_id }

        argument :project_ids, [Types::GlobalIDType[::Project]],
          required: false,
          default_value: [],
          description: 'Project IDs to attach the profile to.',
          prepare: ->(global_ids, _ctx) { global_ids.map(&:model_id) }

        argument :group_ids, [Types::GlobalIDType[::Group]],
          required: false,
          default_value: [],
          description: 'Group IDs to attach the profile to. Applies the profile to all subgroups and projects ' \
            'in the specified group. Errors for these projects are not returned.',
          prepare: ->(global_ids, _ctx) { global_ids.map(&:model_id) }

        argument :mode, Types::Security::ScanProfileAttachModeEnum,
          required: false,
          default_value: :set,
          replace_null_with_default: true,
          description: 'How to attach the profile relative to existing profiles of the same scan type. ' \
            'Defaults to `SET`.'

        def self.authorization_scopes
          super + [:ai_workflows]
        end

        def resolve(security_scan_profile_id:, project_ids:, group_ids:, mode:)
          validate_id_limit!(project_ids, group_ids)

          root_namespace = shared_root_namespace!(project_ids, group_ids)

          authorized_projects = load_and_authorize_projects!(project_ids)
          authorized_groups = load_and_authorize_groups!(group_ids)
          profile_result = resolve_profile!(security_scan_profile_id, root_namespace)
          return { errors: [profile_result.message] } if profile_result.error?

          profile = profile_result.payload[:scan_profile]

          mode_error = ::Security::ScanProfiles::ProjectAttachService.unsupported_mode_error(profile, mode)
          return { errors: [mode_error] } if mode_error

          result = attach_to_projects(profile, authorized_projects, mode)
          schedule_group_workers(authorized_groups, profile, mode)

          track_internal_event(
            "attach_scan_profile",
            user: current_user,
            namespace: root_namespace
          )

          { errors: result[:errors] }
        end

        private

        def resolve_profile!(security_scan_profile_id, root_namespace)
          result =  ::Security::ScanProfiles::FindOrCreateService.execute(
            namespace: root_namespace,
            identifier: security_scan_profile_id
          )

          # A custom profile holding the preset's name is fixable by the user, so report it.
          return result if result.success? || result.reason == :name_taken

          raise_resource_not_available_error!
        end

        def attach_to_projects(profile, projects, mode)
          return { errors: [] } if projects.empty?

          ::Security::ScanProfiles::ProjectAttachService.execute(
            profile: profile,
            projects: projects,
            current_user: current_user,
            mode: mode
          )
        end

        def schedule_group_workers(groups, profile, mode)
          return if groups.empty?

          operation_id = create_background_operation(groups.size, profile)
          # rubocop:disable CodeReuse/Worker -- This should schedule async workers
          ::Security::ScanProfiles::AttachWorker.bulk_perform_async_with_contexts(
            groups,
            arguments_proc: ->(group) do
              [group.id, profile.id, current_user.id, operation_id, true, { 'mode' => mode.to_s }]
            end,
            context_proc: ->(group) { { namespace: group, user: current_user } }
          )
          # rubocop:enable CodeReuse/Worker
        end

        def create_background_operation(groups_count, profile)
          Gitlab::BackgroundOperations::RedisStore.create_operation(
            operation_type: 'profile_attach',
            user_id: current_user.id,
            total_items: groups_count,
            parameters: { profile_id: profile.id }
          )
        end
      end
    end
  end
end
