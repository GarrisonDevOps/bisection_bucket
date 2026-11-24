# frozen_string_literal: true

module API
  module Entities
    class GroupDetail < Group
      expose :require_sha_for_merge, documentation: { type: 'Boolean' }
      expose :lock_require_sha_for_merge, documentation: { type: 'Boolean' }
      expose :require_two_factor_authentication_from_ancestor?,
        as: :require_two_factor_authentication_from_ancestor,
        documentation: {
          type: 'Boolean',
          desc: 'Whether an ancestor group requires all users to set up two-factor authentication. ' \
            'Members of this group must then set it up even when require_two_factor_authentication is false. ' \
            '[Introduced](https://gitlab.com/gitlab-org/gitlab/-/issues/352728) in GitLab 19.6.'
        }

      expose :shared_with_groups, documentation: { is_array: true, type: 'Hash' } do |group, options|
        SharedGroupWithGroup.represent(group.shared_with_group_links_visible_to_user(options[:current_user]))
      end
      expose :runners_token, if: ->(_, options) {
        options[:user_can_admin_group]
      }, documentation: { type: 'String', example: 'b8bc4a7a29eb76ea83cf79e4908c2b' }
      expose :enabled_git_access_protocol, if: ->(group, options) {
        group.root? && options[:user_can_admin_group]
      }, documentation: { type: 'String', example: 'ssh' }
      expose :prevent_sharing_groups_outside_hierarchy,
        if: ->(group) { group.root? && group.namespace_settings.present? },
        documentation: {
          type: 'Boolean',
          desc: 'If `true`, groups in this namespace cannot be shared with groups outside the namespace. ' \
            'Returned only for top-level groups.'
        }
      expose :step_up_auth_required_oauth_provider,
        documentation: {
          type: 'String',
          desc: 'OAuth provider required for step-up authentication.'
        },
        if: ->(group, options) {
          ::Feature.enabled?(:omniauth_step_up_auth_for_namespace, group) &&
            group.namespace_settings.present? &&
            options[:user_can_admin_group]
        } do |group|
        group.namespace_settings.step_up_auth_required_oauth_provider
      end

      expose :projects,
        if: ->(_, options) { options[:with_projects] },
        using: ::API::Entities::Project, documentation: { is_array: true } do |group, options|
        projects = GroupProjectsFinder.new(
          group: group,
          current_user: options[:current_user],
          options: { exclude_shared: true, limit: projects_limit }
        ).execute

        Entities::Project.prepare_relation(projects, options)
      end

      expose :shared_projects,
        if: ->(_, options) { options[:with_projects] },
        using: ::API::Entities::Project, documentation: { is_array: true } do |group, options|
        projects = GroupProjectsFinder.new(
          group: group,
          current_user: options[:current_user],
          options: { only_shared: true, limit: projects_limit }
        ).execute

        Entities::Project.prepare_relation(projects, options)
      end

      def projects_limit
        GroupProjectsFinder::DEFAULT_PROJECTS_LIMIT
      end
    end
  end
end

API::Entities::GroupDetail.prepend_mod_with('API::Entities::GroupDetail')
