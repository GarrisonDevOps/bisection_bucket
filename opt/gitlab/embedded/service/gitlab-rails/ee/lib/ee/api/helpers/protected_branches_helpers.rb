# frozen_string_literal: true

module EE
  module API
    module Helpers
      module ProtectedBranchesHelpers
        extend ActiveSupport::Concern

        prepended do
          params :shared_params do
            optional :user_id, type: Integer, desc: 'ID of a user', documentation: { example: 1 }
            optional :group_id, type: Integer, desc: 'ID of a group', documentation: { example: 1 }
            optional :member_role_id, type: Integer, desc: 'ID of a custom member role', documentation: { example: 1, format: 'int64' }
            optional :id, type: Integer, desc: 'ID of a project', documentation: { example: 40 }
            optional :_destroy, type: Grape::API::Boolean, desc: 'Delete the object when true'
          end

          params :optional_params_ee do
            # rubocop:disable API/AccessLevelStringType -- Introduced before the cop
            optional :unprotect_access_level,
              type: Integer,
              values: ::ProtectedBranch::UnprotectAccessLevel.allowed_access_levels,
              desc: 'Access level allowed to unprotect. Defaults to `40` (Maintainer role). Does not support custom roles. Use `allowed_to_unprotect` with `member_role_id` instead.'
            # rubocop:enable API/AccessLevelStringType

            optional :allowed_to_push, type: Array[JSON],
              desc: 'Array of users, groups, deploy keys, custom roles, or access levels allowed to push to protected branches. ' \
                'Each element is a hash of the form `{user_id: integer}`, `{group_id: integer}`, `{deploy_key_id: integer}`, ' \
                '`{member_role_id: integer}`, or `{access_level: integer}`. ' \
                '`user_id`, `group_id`, and `access_level` are Premium and Ultimate only. `member_role_id` is Ultimate only. ' \
                'Group protected branches accept only `access_level` and `member_role_id`. ' \
                'To change an existing element, include its `id`. To delete it, include its `id` and set `_destroy` to `true`. ' \
                '`deploy_key_id` [introduced](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/166598) in GitLab 17.5. ' \
                '`member_role_id` [introduced](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/241819) in GitLab 19.2.' do
              optional :access_level, type: Integer, desc: 'Access level allowed to push', values: ::ProtectedBranch::PushAccessLevel.allowed_access_levels # rubocop:disable API/AccessLevelStringType -- Introduced before the cop

              optional :deploy_key_id, type: Integer, desc: 'Deploy key allowed to push', documentation: { example: 1 }
              use :shared_params
            end

            optional :allowed_to_merge, type: Array[JSON],
              desc: 'Array of users, groups, custom roles, or access levels allowed to merge protected branches. ' \
                'Each element is a hash of the form `{user_id: integer}`, `{group_id: integer}`, ' \
                '`{member_role_id: integer}`, or `{access_level: integer}`. ' \
                '`user_id`, `group_id`, and `access_level` are Premium and Ultimate only. `member_role_id` is Ultimate only. ' \
                'Group protected branches accept only `access_level` and `member_role_id`. ' \
                'To change an existing element, include its `id`. To delete it, include its `id` and set `_destroy` to `true`. ' \
                '`member_role_id` [introduced](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/241819) in GitLab 19.2.' do
              optional :access_level, type: Integer, desc: 'Access level allowed to merge', values: ::ProtectedBranch::MergeAccessLevel.allowed_access_levels # rubocop:disable API/AccessLevelStringType -- Introduced before the cop

              use :shared_params
            end

            optional :allowed_to_unprotect, type: Array[JSON],
              desc: 'Array of users, groups, custom roles, or access levels allowed to unprotect protected branches. ' \
                'Each element is a hash of the form `{user_id: integer}`, `{group_id: integer}`, ' \
                '`{member_role_id: integer}`, or `{access_level: integer}`. ' \
                '`user_id`, `group_id`, and `access_level` are Premium and Ultimate only. `member_role_id` is Ultimate only. ' \
                'Group protected branches accept only `access_level` and `member_role_id`. ' \
                'Access level `0` (No access) is not available for this field. ' \
                'To change an existing element, include its `id`. To delete it, include its `id` and set `_destroy` to `true`. ' \
                '`member_role_id` [introduced](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/241819) in GitLab 19.2.' do
              optional :access_level, type: Integer, desc: 'Access level allowed to unprotect', values: ::ProtectedBranch::UnprotectAccessLevel.allowed_access_levels # rubocop:disable API/AccessLevelStringType -- Introduced before the cop

              use :shared_params
            end

            optional :code_owner_approval_required, type: Grape::API::Boolean, desc: 'If `true`, prevents pushes to this branch if it matches an item in the `CODEOWNERS` file. Default is `false`. Premium and Ultimate only.'
          end
        end
      end
    end
  end
end
