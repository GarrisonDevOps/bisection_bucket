# frozen_string_literal: true

module API
  class GroupHooks < ::API::Base
    include ::API::PaginationParams

    group_hooks_tags = %w[hooks]
    feature_category :webhooks
    urgency :low

    before { authenticate! }

    helpers ::API::Helpers::WebHooksHelpers

    helpers do
      def hook_scope
        user_group.hooks
      end

      def hook_container
        user_group
      end

      # The subject the endpoints mounted from API::Hooks authorize against.
      def hook_authorization_subject
        user_group
      end

      params :group_hook_properties do
        optional :name, type: String, desc: 'Name of the group webhook. [Introduced](https://gitlab.com/gitlab-org/gitlab/-/issues/460887) in GitLab 17.1.'
        optional :description, type: String, desc: 'Description of the group webhook. [Introduced](https://gitlab.com/gitlab-org/gitlab/-/issues/460887) in GitLab 17.1.'
        optional :push_events, type: Boolean, desc: 'If `true`, triggers the group webhook on push events.'
        optional :push_events_branch_filter, type: String, desc: 'Filter push events by branch name.'
        optional :issues_events, type: Boolean, desc: 'If `true`, triggers the group webhook on issue events.'
        optional :confidential_issues_events, type: Boolean, desc: 'If `true`, triggers the group webhook on confidential issue events.'
        optional :merge_requests_events, type: Boolean, desc: 'If `true`, triggers the group webhook on merge request events.'
        optional :tag_push_events, type: Boolean, desc: 'If `true`, triggers the group webhook on tag push events.'
        optional :note_events, type: Boolean, desc: 'If `true`, triggers the group webhook on note events.'
        optional :confidential_note_events, type: Boolean, desc: 'If `true`, triggers the group webhook on confidential note events.'
        optional :job_events, type: Boolean, desc: 'If `true`, triggers the group webhook on job events.'
        optional :pipeline_events, type: Boolean, desc: 'If `true`, triggers the group webhook on pipeline events.'
        optional :project_events, type: Boolean, desc: 'If `true`, triggers the group webhook on project events.'
        optional :wiki_page_events, type: Boolean, desc: 'If `true`, triggers the group webhook on wiki page events.'
        optional :deployment_events, type: Boolean, desc: 'If `true`, triggers the group webhook on deployment events.'
        optional :feature_flag_events, type: Boolean, desc: 'If `true`, triggers the group webhook on feature flag events.'
        optional :releases_events, type: Boolean, desc: 'If `true`, triggers the group webhook on release events.'
        optional :milestone_events, type: Boolean, desc: 'If `true`, triggers the group webhook on milestone events.'
        optional :subgroup_events, type: Boolean, desc: 'If `true`, triggers the group webhook on subgroup events.'
        optional :emoji_events, type: Boolean, desc: 'If `true`, triggers the group webhook on emoji events.'
        optional :resource_access_token_events, type: Boolean, desc: 'If `true`, triggers the group webhook on group and project access token expiry events.'
        optional :member_events, type: Boolean, desc: 'If `true`, triggers the group webhook on member events.'
        optional :vulnerability_events, type: Boolean, desc: 'If `true`, triggers the group webhook on vulnerability events.'
        optional :enable_ssl_verification, type: Boolean, desc: 'If `true`, verifies the SSL certificate when the group webhook is triggered.'
        optional :token, type: String, desc: 'Secret token used to validate received payloads. Not returned in the response, and changing the webhook URL resets it.'
        optional :signing_token, type: String,
          desc: 'HMAC signing token used to compute the `webhook-signature` header. Must be in `whsec_<base64>` format encoding a 32-byte key, and is not returned in the response. [Introduced](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/231325) in GitLab 19.0.'
        optional :custom_webhook_template, type: String, desc: 'Custom template for the group webhook request payload.'
        optional :branch_filter_strategy, type: String, values: WebHook.branch_filter_strategies.keys,
          desc: 'Filter push events by branch. Defaults to `wildcard`.'
        optional :duo_flow_callback_enabled, type: Boolean,
          desc: "If `true`, allows Duo Agent Platform flows to send lifecycle and progress events to this group webhook. A flow must reference the webhook's ID as `callback_hook_id` when it starts. [Introduced](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/249149) in GitLab 19.4 [with a feature flag](https://docs.gitlab.com/administration/feature_flags/) named `duo_flow_callback_hooks`. Disabled by default."
        use :url_variables
        use :custom_headers
      end
    end

    params do
      requires :id, types: [String, Integer], desc: 'ID or URL-encoded path of the group.'
    end
    resource :groups, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
      desc 'List all group hooks' do
        detail 'Lists all group hooks.'
        success ::API::Entities::GroupHook
        is_array true
        tags group_hooks_tags
      end
      params do
        use :pagination
      end
      route_setting :tier, :premium
      route_setting :authorization, permissions: :read_webhook, boundary_type: :group
      get ":id/hooks" do
        authorize! :read_webhook, user_group

        present paginate(user_group.hooks), with: ::API::Entities::GroupHook
      end

      desc 'Create a group hook' do
        detail 'Creates a hook for a specified group. This endpoint has a rate limit of 10 requests per ' \
          'minute for each authenticated user for a given group. On GitLab Self-Managed and GitLab Dedicated, ' \
          'an administrator can change this limit in the application settings. Setting ' \
          '`duo_flow_callback_enabled` to `false` is always accepted.'
        success ::API::Entities::GroupHook
        failure [
          { code: 400, message: 'Validation error' },
          { code: 404, message: 'Not found' },
          { code: 422, message: 'Unprocessable entity' },
          { code: 429, message: 'Too many requests' }
        ]
        tags group_hooks_tags
      end
      params do
        use :requires_url
        use :group_hook_properties
      end
      route_setting :tier, :premium
      route_setting :authorization, permissions: :create_webhook, boundary_type: :group
      post ":id/hooks" do
        authorize! :create_webhook, user_group

        check_rate_limit!(:group_hooks_create, scope: { group: user_group, user: current_user })

        hook_params = create_hook_params

        result = WebHooks::CreateService.new(current_user).execute(hook_params, hook_scope)

        if result[:status] == :success
          present result[:hook], with: ::API::Entities::GroupHook
        else
          error!(result.message, result.http_status || 422)
        end
      end

      params do
        requires :hook_id, type: Integer, desc: 'ID of the group webhook.'
      end
      namespace ":id/hooks/:hook_id/" do
        desc 'Retrieve a group hook' do
          detail 'Retrieves a specified group hook.'
          success ::API::Entities::GroupHook
          failure [
            { code: 404, message: 'Not found' }
          ]
          tags group_hooks_tags
        end
        params do
          requires :hook_id, type: Integer, desc: 'ID of the group webhook.'
        end
        route_setting :tier, :premium
        route_setting :authorization, permissions: :read_webhook, boundary_type: :group
        get do
          authorize! :read_webhook, user_group

          hook = find_hook

          present hook, with: ::API::Entities::GroupHook
        end

        desc 'Update a group hook' do
          detail 'Updates a hook for a specified group. Setting `duo_flow_callback_enabled` to `false` is always ' \
            'accepted.'
          success ::API::Entities::GroupHook
          failure [
            { code: 400, message: 'Validation error' },
            { code: 404, message: 'Not found' },
            { code: 422, message: 'Unprocessable entity' }
          ]
          tags group_hooks_tags
        end
        params do
          requires :hook_id, type: Integer, desc: 'ID of the group webhook.'
          use :optional_url
          use :group_hook_properties
        end
        route_setting :tier, :premium
        route_setting :authorization, permissions: :update_webhook, boundary_type: :group
        put do
          authorize! :update_webhook, user_group

          update_hook(entity: ::API::Entities::GroupHook)
        end

        desc 'Delete a group hook' do
          detail 'Deletes a hook from a group. This is an idempotent method and can be called multiple times. Either the hook is available or not.'
          success code: 204
          failure [
            { code: 404, message: 'Not found' }
          ]
          tags group_hooks_tags
        end
        params do
          requires :hook_id, type: Integer, desc: 'ID of the group webhook.'
        end
        route_setting :tier, :premium
        route_setting :authorization, permissions: :delete_webhook, boundary_type: :group
        delete do
          authorize! :delete_webhook, user_group

          hook = find_hook

          destroy_conditionally!(hook) do
            WebHooks::DestroyService.new(current_user).execute(hook)
          end
        end

        mount ::API::Hooks::Events, with: { boundary_type: :group, tier: :premium }
      end
      namespace ':id/hooks' do
        mount ::API::Hooks::UrlVariables, with: { boundary_type: :group, tier: :premium }
        mount ::API::Hooks::CustomHeaders, with: { boundary_type: :group, tier: :premium }
        mount ::API::Hooks::TriggerTest, with: {
          entity: GroupHook,
          boundary_type: :group,
          tier: :premium
        }
        mount ::API::Hooks::ResendHook, with: { boundary_type: :group, tier: :premium }
      end
    end
  end
end
