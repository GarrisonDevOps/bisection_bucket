# frozen_string_literal: true

module API
  module Entities
    class UserWithAdmin < UserPublic
      expose :admin?, as: :is_admin
      expose :note
      expose :namespace_id
      expose :provisioned_by_project_id,
        documentation: {
          type: 'Integer',
          desc: 'ID of the project that provisioned the user. ' \
            '[Introduced](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/248245) in GitLab 19.3.'
        }
      expose :created_by, with: UserBasic,
        documentation: { type: 'API::Entities::UserBasic',
                         desc: 'User who created the account, when an administrator created it or it is a ' \
                           'project bot user. `null` if the user registered the account themselves.' }
    end
  end
end

API::Entities::UserWithAdmin.prepend_mod_with('API::Entities::UserWithAdmin')
