# frozen_string_literal: true

module API
  module Manage
    class Groups < ::API::Base
      feature_category :system_access

      include PaginationParams

      before do
        not_found! unless ::Gitlab::Saas.feature_available?(:group_credentials_inventory)

        authenticate!
        authorize! :admin_group, user_group
      end

      helpers ::API::Helpers::PersonalAccessTokensHelpers

      helpers do
        def users
          user_group.enterprise_users.or(user_group.service_accounts)
        end

        def ssh_keys_finder_params
          declared(params, include_missing: false).merge({ users: users, key_type: 'ssh' })
        end

        def sort_order
          params[:sort] || 'created_asc'
        end

        def bot_resource(token)
          member = token.user.members.first

          return unless member

          member.source
        end

        def validate_bot_tokens(token, bot_resource)
          unless token.user.project_bot?
            forbidden!("Cannot revoke resource access token: Token does not belong to bot user")
          end

          return unless bot_resource&.root_ancestor != user_group

          forbidden!("Cannot access resource access token: Token belongs to a resource outside group's hierarchy")
        end
      end

      params do
        requires :id, types: [String, Integer], desc: 'ID or URL-encoded path of the group.'
      end
      namespace 'groups/:id/manage' do
        params do
          requires :id, type: String, desc: 'ID or URL-encoded path of the group.'
        end

        resources :personal_access_tokens do
          params do
            use :access_token_params
            use :pagination
          end

          desc 'List all personal access tokens for a group' do
            detail 'Lists all personal access tokens associated with enterprise users in a top-level group. For ' \
              'tokens created with granular scopes, the response also includes a `granular_scopes` attribute. The ' \
              '`last_used_ips` attribute was ' \
              '[introduced](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/250307) in GitLab 19.4. The ' \
              '`granular_scopes` attribute was [introduced](https://gitlab.com/gitlab-org/gitlab/-/issues/634390) in ' \
              'GitLab 19.6. This feature was introduced in GitLab 17.8.'
            tags ['group_credentials_inventory']
          end
          route_setting :tier, :ultimate
          route_setting :authorization, permissions: :read_personal_access_token, boundary_type: :group,
            assignable_when: [:saas]
          get do
            tokens = PersonalAccessTokensFinder.new(
              declared(
                params,
                include_missing: false).merge(
                  {
                    group: user_group,
                    user_types: [:human, :service_account],
                    impersonation: false,
                    sort: sort_order
                  }
                )
            ).execute.preload_users.preload_last_used_ips
            paginated_tokens = paginate(tokens, skip_default_order: true)

            present paginated_tokens, with: Entities::PersonalAccessToken,
              **granular_scopes_options_for(paginated_tokens)
          end

          desc 'Revoke a personal access token for an enterprise user' do
            detail 'Revokes a specified personal access token for an enterprise user.'
            tags ['group_credentials_inventory']
            success code: 204
            failure [
              { code: 400, message: 'Bad Request' }
            ]
          end
          params do
            requires :pat_id, type: Integer, desc: 'ID of the personal access token.'
          end

          route_setting :tier, :ultimate
          route_setting :authorization, permissions: :revoke_personal_access_token, boundary_type: :group,
            assignable_when: [:saas]
          delete ':pat_id' do
            token = find_token(params[:pat_id])

            forbidden! unless users.include? token.user

            revoke_token(token, group: user_group)
          end

          desc 'Rotate a personal access token for an enterprise user' do
            detail 'Rotates a specified personal access token for an enterprise user associated with the top-level ' \
              'group. This revokes the previous token and creates a token that expires after one week. Rotating a ' \
              'token with granular scopes returns those scopes in a `granular_scopes` attribute on the new token. ' \
              'The `last_used_ips` attribute was ' \
              '[introduced](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/250307) in GitLab 19.4. The ' \
              '`granular_scopes` attribute was [introduced](https://gitlab.com/gitlab-org/gitlab/-/issues/632314) in ' \
              'GitLab 19.5.'
            tags ['group_credentials_inventory']
            success Entities::PersonalAccessTokenWithToken
          end
          params do
            requires :pat_id, type: Integer, desc: 'ID of the personal access token.'
            optional :expires_at,
              type: Date,
              desc: 'Date when the access token expires. If omitted, the new token expires one week after rotation ' \
                'when [token expiry is ' \
                'enforced](https://docs.gitlab.com/user/profile/personal_access_tokens/#access-token-expiration), ' \
                'and does not expire otherwise. When expiry is enforced, the date must be no more than one year ' \
                'after rotation.',
              documentation: { example: '2021-01-31' }
          end
          route_setting :tier, :ultimate
          route_setting :authorization, permissions: :rotate_personal_access_token, boundary_type: :group,
            assignable_when: [:saas]
          post ':pat_id/rotate' do
            token = find_token(params[:pat_id])

            # Since this ability is PAT policy it does not check whether token user belongs to
            # group, hence we need to include this check at API level separately
            if users.include?(token.user) && Ability.allowed?(current_user, :rotate_personal_access_token, token)
              new_token = rotate_token(token, declared_params)

              present new_token, with: Entities::PersonalAccessTokenWithToken,
                **granular_scopes_options_for([new_token])
            else
              forbidden!
            end
          end
        end

        resources :resource_access_tokens do
          params do
            use :access_token_params
            use :pagination
          end

          desc 'List all group and project access tokens for a group' do
            detail 'Lists all group and project access tokens associated with a top-level-group. This feature was ' \
              'introduced in GitLab 17.10.'
            tags ['group_credentials_inventory']
          end
          # rubocop:disable CodeReuse/ActiveRecord -- Specific to this endpoint
          route_setting :tier, :ultimate
          route_setting :authorization, permissions: :read_resource_access_token, boundary_type: :group,
            assignable_when: [:saas]
          get do
            tokens =
              PersonalAccessTokensFinder.new(
                declared(params, include_missing: false)
                .merge({ group: user_group, user_types: [:project_bot], impersonation: false, sort: sort_order })
              ).execute.includes(user: [:members, { user_detail: :bot_namespace }]).preload_last_used_ips

            present paginate(tokens, skip_default_order: true), with: Entities::ResourceAccessToken
          end
          # rubocop:enable CodeReuse/ActiveRecord

          desc 'Revoke a group or project access token for a group' do
            detail 'Revokes a specified group or project access token associated with a top-level group.'
            tags ['group_credentials_inventory']
            success code: 204
            failure [
              { code: 400, message: 'Bad Request' }
            ]
          end
          params do
            requires :prat_id, type: Integer, desc: 'ID of the resource access token.'
            optional :expires_at,
              type: Date,
              desc: 'Date when the access token expires. If omitted, the new token expires one week after rotation ' \
                'when [token expiry is ' \
                'enforced](https://docs.gitlab.com/user/profile/personal_access_tokens/#access-token-expiration), ' \
                'and does not expire otherwise. When expiry is enforced, the date must be no more than one year ' \
                'after rotation.',
              documentation: { example: '2021-01-31' }
          end
          route_setting :tier, :ultimate
          route_setting :authorization, permissions: :delete_resource_access_token, boundary_type: :group,
            assignable_when: [:saas]
          delete ':prat_id' do
            token = find_token(params[:prat_id])
            bot_resource = bot_resource(token)
            validate_bot_tokens(token, bot_resource)

            service = ::ResourceAccessTokens::RevokeService
              .new(current_user, bot_resource, token).execute

            service.success? ? no_content! : bad_request!(service.message)
          end

          desc 'Rotate a group or project access token for a group' do
            detail 'Rotates a specified group or project access token associated with a top-level group. This ' \
              'revokes the previous token and creates a new token.'
            tags ['group_credentials_inventory']
            success code: 204
            failure [
              { code: 400, message: 'Bad Request' }
            ]
          end
          params do
            requires :prat_id, type: Integer, desc: 'ID of the resource access token.'
            optional :expires_at,
              type: Date,
              desc: 'Date when the access token expires. If omitted, the new token expires one week after rotation ' \
                'when [token expiry is ' \
                'enforced](https://docs.gitlab.com/user/profile/personal_access_tokens/#access-token-expiration), ' \
                'and does not expire otherwise. When expiry is enforced, the date must be no more than one year ' \
                'after rotation.',
              documentation: { example: '2021-01-31' }
          end
          route_setting :tier, :ultimate
          route_setting :authorization, permissions: :rotate_resource_access_token, boundary_type: :group,
            assignable_when: [:saas]
          post ':prat_id/rotate' do
            resource_accessible = Ability.allowed?(current_user, :manage_resource_access_tokens, user_group)
            forbidden! unless resource_accessible

            token = find_token(params[:prat_id])

            bot_resource = bot_resource(token)
            validate_bot_tokens(token, bot_resource)

            new_token = rotate_token_for_resource(token, bot_resource, declared_params)

            present new_token, with: Entities::ResourceAccessTokenWithToken
          end
        end

        resources :ssh_keys do
          params do
            optional :created_before, type: DateTime, desc: 'Return SSH keys created on or before the specified time.',
              documentation: { example: '2022-01-01T00:00:00Z' }
            optional :created_after, type: DateTime, desc: 'Return SSH keys created on or after the specified time.',
              documentation: { example: '2021-01-01T00:00:00Z' }
            optional :expires_before, type: DateTime, desc: 'Return SSH keys that expire on or before the specified ' \
                                                        'time.',
              documentation: { example: '2022-01-01T00:00:00Z' }
            optional :expires_after, type: DateTime, desc: 'Return SSH keys that expire on or after the specified ' \
                                                       'time.',
              documentation: { example: '2021-01-01T00:00:00Z' }
            use :pagination
          end

          desc 'List all SSH keys for a group' do
            detail 'Lists all SSH public keys associated with enterprise users in a top-level-group. This feature ' \
              'was introduced in GitLab 17.9.'
            tags ['group_credentials_inventory']
            success Entities::SshKeyWithUserId
            is_array true
          end
          route_setting :tier, :ultimate
          route_setting :authorization, permissions: :read_ssh_key, boundary_type: :group, assignable_when: [:saas]
          get feature_category: :system_access do
            ssh_keys = ::KeysFinder.new(ssh_keys_finder_params).execute.preload_users

            present paginate(ssh_keys), with: Entities::SshKeyWithUserId
          end

          desc 'Delete an SSH key for an enterprise user' do
            detail 'Deletes a specified SSH public key for an enterprise user associated with the top-level group.'
            tags ['group_credentials_inventory']
            success code: 204
            failure [
              { code: 400, message: 'Bad Request' }
            ]
          end
          params do
            requires :key_id, type: Integer, desc: 'ID of the SSH key.'
          end
          route_setting :tier, :ultimate
          route_setting :authorization, permissions: :delete_user_ssh_key, boundary_type: :group,
            assignable_when: [:saas]
          delete ':key_id' do
            key = ::KeysFinder.new(ssh_keys_finder_params).find_by_id(params[:key_id])

            not_found!('Key') unless key

            destroy_conditionally!(key) do |key|
              destroy_service = ::Keys::DestroyService.new(current_user)
              destroy_service.execute(key)
            end
          end
        end
      end
    end
  end
end
