# frozen_string_literal: true

module Mutations
  module Security
    module ScanProfiles
      class Detach < BaseMutation
        graphql_name 'SecurityScanProfileDetach'

        include Gitlab::InternalEventsTracking
        include Mutations::Security::ScanProfiles::SharedScopeResolution

        description "Detaches a security scan profile from projects and groups. " \
          "All projects and groups must belong to the same top-level group. " \
          "Maximum of #{MAX_IDS} project and group IDs combined."

        argument :security_scan_profile_id, Types::GlobalIDType[::Security::ScanProfile],
          required: true,
          description: 'Security scan profile ID to detach. Must be the ID of a profile, ' \
            'or the identifier of a default profile, such as `gid://gitlab/Security::ScanProfile/sast`.',
          prepare: ->(global_id, _ctx) { global_id.model_id }

        argument :project_ids, [Types::GlobalIDType[::Project]],
          required: false,
          default_value: [],
          description: 'Project IDs to detach the profile from.',
          prepare: ->(global_ids, _ctx) { global_ids.map(&:model_id) }

        argument :group_ids, [Types::GlobalIDType[::Group]],
          required: false,
          default_value: [],
          description: 'Group IDs to detach the profile from. Detaches the profile from all subgroups and projects ' \
            'in the specified group. Errors for these projects are not returned.',
          prepare: ->(global_ids, _ctx) { global_ids.map(&:model_id) }

        def resolve(security_scan_profile_id:, project_ids:, group_ids:)
          validate_id_limit!(project_ids, group_ids)

          root_namespace = shared_root_namespace!(project_ids, group_ids)

          authorized_projects = load_and_authorize_projects!(project_ids)
          authorized_groups = load_and_authorize_groups!(group_ids)
          profile = find_profile(security_scan_profile_id, root_namespace)
          return { errors: [] } unless profile

          result = detach_from_projects(profile, authorized_projects)
          schedule_group_workers(authorized_groups, profile)

          track_internal_event(
            "detach_scan_profile",
            user: current_user,
            namespace: root_namespace
          )

          { errors: result[:errors] }
        end

        private

        def find_profile(security_scan_profile_id, root_namespace)
          if ::Security::DefaultScanProfiles.virtual_identifier?(security_scan_profile_id)
            return find_saved_preset(security_scan_profile_id, root_namespace)
          end

          profile = ::Security::ScanProfile.not_deleted.by_namespace(root_namespace).id_in(security_scan_profile_id).first
          return profile if profile.present?

          raise_resource_not_available_error!
        end

        def find_saved_preset(preset_key, root_namespace)
          default_profile = ::Security::DefaultScanProfiles.find_by_preset_key(preset_key)
          raise_resource_not_available_error! unless default_profile

          ::Security::ScanProfile
            .not_deleted
            .by_namespace(root_namespace)
            .by_type(default_profile.scan_type)
            .by_name(default_profile.name)
            .by_gitlab_recommended
            .first
        end

        def detach_from_projects(profile, projects)
          return { errors: [] } if projects.empty?

          ::Security::ScanProfiles::ProjectDetachService.execute(
            profile: profile,
            projects: projects,
            current_user: current_user
          )
        end

        def schedule_group_workers(groups, profile)
          return if groups.empty?

          operation_id = create_background_operation(groups.size, profile)

          # rubocop:disable CodeReuse/Worker -- This should schedule async workers
          ::Security::ScanProfiles::DetachWorker.bulk_perform_async_with_contexts(
            groups,
            arguments_proc: ->(group) { [group.id, profile.id, current_user.id, operation_id, true] },
            context_proc: ->(group) { { namespace: group, user: current_user } }
          )
          # rubocop:enable CodeReuse/Worker
        end

        def create_background_operation(groups_count, profile)
          Gitlab::BackgroundOperations::RedisStore.create_operation(
            operation_type: 'profile_detach',
            user_id: current_user.id,
            total_items: groups_count,
            parameters: { profile_id: profile.id }
          )
        end
      end
    end
  end
end
