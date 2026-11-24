# frozen_string_literal: true

module Mutations
  module Users
    module PersonalAccessTokens
      class Revoke < BaseMutation
        graphql_name 'PersonalAccessTokenRevoke'
        description 'Revokes a specified personal access token.'

        authorize :revoke_personal_access_token

        authorize_granular_token permissions: :revoke_personal_access_token,
          boundary: :user,
          boundary_type: :user

        argument :id, ::Types::GlobalIDType[::PersonalAccessToken],
          required: true,
          description: 'Global ID of the personal access token that will be revoked.'

        def resolve(id:)
          token = authorized_find!(id: id)

          result = ::PersonalAccessTokens::RevokeService.new(current_user, token: token).execute
          result.success? ? { errors: [] } : { errors: [result.message] }
        end
      end
    end
  end
end
