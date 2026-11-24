# frozen_string_literal: true

module API
  module Hooks
    # rubocop: disable API/Base -- It is important that this re-usable module is not a Grape Instance, since it will be re-mounted.
    class CustomHeaders < ::Grape::API
      params do
        requires :hook_id, type: Integer, desc: 'ID of the hook.'
        requires :key, type: String, desc: 'Name of the custom header.',
          limit: WebHook::MAX_CUSTOM_HEADER_NAME_LENGTH
      end
      namespace ':hook_id/custom_headers' do
        desc 'Update a custom header' do
          detail 'Updates a custom header for a specified webhook. This feature was introduced in GitLab 17.1.'
          success code: 204
          tags ['hooks']
        end
        params do
          requires :value, type: String, desc: 'Value of the custom header.'
        end
        given configuration[:tier] do
          route_setting :tier, configuration[:tier]
        end
        route_setting :authorization, permissions: :update_webhook_custom_header,
          boundary_type: configuration[:boundary_type]
        put ":key" do
          authorize! :update_webhook_custom_header, hook_authorization_subject

          hook = find_hook
          key = params.delete(:key)
          value = params.delete(:value)
          custom_headers = hook.custom_headers.merge(key => value)

          result = ::WebHooks::UpdateService.new(current_user).execute(hook, custom_headers: custom_headers)
          error!('Illegal key or value', 422) unless result.success?

          status :no_content
        end

        desc 'Delete a custom header' do
          detail 'Deletes a custom header from a specified webhook. This feature was introduced in GitLab 17.1.'
          tags ['hooks']
        end
        given configuration[:tier] do
          route_setting :tier, configuration[:tier]
        end
        route_setting :authorization, permissions: :delete_webhook_custom_header,
          boundary_type: configuration[:boundary_type]
        delete ":key" do
          authorize! :delete_webhook_custom_header, hook_authorization_subject

          hook = find_hook
          key = params.delete(:key)
          not_found!('Custom header') unless hook.custom_headers.key?(key)

          vars = hook.custom_headers.reject { |k, _| k == key }

          result = ::WebHooks::UpdateService.new(current_user).execute(hook, custom_headers: vars)
          error!('Could not unset custom header', 422) unless result.success?

          status :no_content
        end
      end
    end
    # rubocop: enable API/Base
  end
end
