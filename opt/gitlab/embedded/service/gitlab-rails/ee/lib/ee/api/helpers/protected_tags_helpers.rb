# frozen_string_literal: true

module EE
  module API
    module Helpers
      module ProtectedTagsHelpers
        extend ActiveSupport::Concern

        prepended do
          params :optional_params_ee do
            optional :allowed_to_create, type: Array[JSON],
              desc: 'Array of users, groups, deploy keys, or access levels allowed to create protected tags. Each ' \
                'element is a hash with one of `user_id`, `group_id`, `deploy_key_id`, or `access_level`. ' \
                '`user_id`, `group_id`, and `access_level` are Premium and Ultimate only. `deploy_key_id` ' \
                '[introduced](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/166866) in GitLab 17.5.' do
              # rubocop:disable API/AccessLevelStringType -- Introduced before the cop
              optional :access_level, type: Integer, desc: 'ID of an access level',
                values: ::ProtectedTag::CreateAccessLevel.allowed_access_levels
              # rubocop:enable API/AccessLevelStringType
              optional :user_id, type: Integer, desc: 'ID of a user'
              optional :group_id, type: Integer, desc: 'ID of a group'
              optional :deploy_key_id, type: Integer, desc: 'ID of a deploy key'
            end
          end
        end
      end
    end
  end
end
