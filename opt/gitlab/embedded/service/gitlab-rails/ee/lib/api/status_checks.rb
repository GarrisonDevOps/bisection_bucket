# frozen_string_literal: true

module API
  class StatusChecks < ::API::Base
    include PaginationParams

    feature_category :security_policy_management

    before do
      authenticate!
      check_feature_enabled!
    end

    helpers do
      def check_feature_enabled!
        unauthorized! unless user_project.licensed_feature_available?(:external_status_checks)
      end
    end

    resource :projects, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
      params do
        requires :id, types: [String, Integer], desc: 'ID or URL-encoded path of the project.'
      end
      segment ':id/external_status_checks' do
        desc 'Create external status check service' do
          detail 'Creates an external status check service for a specified project. External status checks send ' \
            'information about all applicable merge requests to the defined external service, including ' \
            'confidential merge requests.'
          success code: 201, model: ::API::Entities::ExternalStatusCheck
          tags ['external_status_checks']
        end
        params do
          requires :name, type: String, desc: 'Display name of the external status check service.', documentation: { example: 'QA' }
          optional :shared_secret, type: String, desc: 'HMAC secret for the external status check.', documentation: { example: 'hmac-sha256' }
          requires :external_url,
            type: String,
            desc: 'URL of the external status check service.',
            documentation: { example: 'https://www.example.com' }
          optional :protected_branch_ids,
            type: Array[Integer],
            coerce_with: ::API::Validations::Types::CommaSeparatedToIntegerArray.coerce,
            desc: 'IDs of protected branches to scope the rule by.', documentation: { is_array: true }
        end
        route_setting :tier, :ultimate
        route_setting :authorization, permissions: :create_external_status_check_service, boundary_type: :project
        post do
          authorize! :create_external_status_check, user_project

          response = ::ExternalStatusChecks::CreateService.new(
            container: user_project,
            current_user: current_user,
            params: declared_params(include_missing: false)
          ).execute

          if response.success?
            present response.payload[:external_status_check], with: ::API::Entities::ExternalStatusCheck
          else
            render_api_error!(response.payload[:errors], response.http_status)
          end
        end
        desc 'Retrieve project external status check services' do
          detail 'Retrieves information on external status check services for a project.'
          success ::API::Entities::ExternalStatusCheck
          tags ['external_status_checks']
          is_array true
        end
        params do
          use :pagination
        end
        route_setting :tier, :ultimate
        route_setting :authorization, permissions: :read_external_status_check_service, boundary_type: :project
        get do
          unauthorized! unless Ability.allowed?(current_user, :read_external_status_check, user_project)

          present paginate(user_project.external_status_checks), with: ::API::Entities::ExternalStatusCheck
        end

        params do
          requires :check_id, type: Integer, desc: 'The ID of the external status check'
        end
        segment ':check_id' do
          desc 'Update external status check service' do
            detail 'Updates an existing external status check for a project.'
            success ::API::Entities::ExternalStatusCheck
            tags ['external_status_checks']
          end
          params do
            requires :check_id,
              as: :id,
              type: Integer,
              desc: 'ID of the external status check.',
              documentation: { example: 1 }
            optional :name, type: String, desc: 'Display name of the external status check service.', documentation: { example: 'QA' }
            optional :shared_secret, type: String, desc: 'HMAC secret for the external status check.', documentation: { example: 'hmac-sha256' }
            optional :external_url,
              type: String,
              desc: 'URL of the external status check service.',
              documentation: { example: 'https://www.example.com' }
            optional :protected_branch_ids,
              type: Array[Integer],
              coerce_with: ::API::Validations::Types::CommaSeparatedToIntegerArray.coerce,
              desc: 'IDs of protected branches to scope the rule by.', documentation: { is_array: true }
          end
          route_setting :tier, :ultimate
          route_setting :authorization, permissions: :update_external_status_check_service, boundary_type: :project
          put do
            response = ::ExternalStatusChecks::UpdateService.new(
              container: user_project,
              current_user: current_user,
              params: declared_params(include_missing: false)
            ).execute

            if response.success?
              present response.payload[:external_status_check], with: ::API::Entities::ExternalStatusCheck
            else
              render_api_error!(response.payload[:errors], response.http_status)
            end
          end

          desc 'Delete external status check service' do
            detail 'Deletes a specified external status check service for a project.'
            success code: 204
            tags ['external_status_checks']
          end
          params do
            requires :check_id, as: :id, type: Integer, desc: 'ID of the external status check.'
          end
          route_setting :tier, :ultimate
          route_setting :authorization, permissions: :delete_external_status_check_service, boundary_type: :project
          delete do
            service = ::ExternalStatusChecks::DestroyService.new(
              container: user_project,
              current_user: current_user,
              params: declared_params(include_missing: false)
            )

            external_status_check = service.external_status_check
            authorize! :delete_external_status_check, external_status_check

            destroy_conditionally!(external_status_check) do
              response = service.execute

              render_api_error!(response.payload[:errors], response.http_status) if response.error?
            end
          end
        end
      end

      params do
        requires :id, types: [String, Integer], desc: 'ID or URL-encoded path of the project.'
        requires :merge_request_iid, type: Integer, desc: 'Internal ID of the merge request.'
      end
      segment ':id/merge_requests/:merge_request_iid' do
        desc 'Update status of an external status check' do
          detail 'Updates the status of an external status check for a specified merge request, informing GitLab ' \
            'that a merge request has passed a check by an external service. To set the status of an external check, ' \
            'the personal access token used must belong to a user with the Developer, Maintainer, or Owner role on ' \
            'the target project of the merge request. Any user with permission to approve the merge request can use ' \
            'this operation.'
          success Entities::MergeRequests::StatusCheckResponse
          tags ['external_status_checks']
        end
        params do
          requires :id, type: String, desc: 'ID or URL-encoded path of the project.', documentation: { example: '1' }
          requires :merge_request_iid,
            type: Integer,
            desc: 'Internal ID of the merge request.',
            documentation: { example: 1 }
          requires :external_status_check_id,
            type: Integer,
            desc: 'ID of the external status check.',
            documentation: { example: 1 }
          requires :sha,
            type: String,
            desc: 'SHA at `HEAD` of the source branch.',
            documentation: { example: '5957a570eee0ac4580ec027fb874ad7514d1e576' }
          requires :status,
            type: String,
            desc: 'Status of the check.',
            values: %w[passed failed pending],
            documentation: { example: 'passed' }
        end
        route_setting :tier, :ultimate
        route_setting :authorization, permissions: :update_external_status_check, boundary_type: :project
        post 'status_check_responses' do
          merge_request = find_merge_request_with_access(params[:merge_request_iid], :approve_merge_request)
          status_check = merge_request.project.external_status_checks.find(params[:external_status_check_id])

          not_found! unless status_check
          check_sha_param!(params, merge_request)

          result = ::MergeRequests::StatusCheckResponses::CreateService.new(
            project: merge_request.project,
            current_user: current_user,
            params: {
              external_status_check: status_check,
              sha: params[:sha],
              status: params[:status]
            }
          ).execute(merge_request)

          if result.success?
            present result[:status_check_response], with: Entities::MergeRequests::StatusCheckResponse, current_user: current_user
          else
            render_api_error!(result[:errors], result.reason)
          end
        end

        segment 'status_checks' do
          desc 'List all status checks for a merge request' do
            detail 'Lists all external status check services for a specified merge request and their status.'
            success Entities::MergeRequests::StatusCheck
            tags ['external_status_checks']
            is_array true
          end
          route_setting :tier, :ultimate
          route_setting :authorization, permissions: :read_external_status_check, boundary_type: :project
          get '/', urgency: :low do
            merge_request = find_merge_request_with_access(params[:merge_request_iid], :read_external_status_check_response)

            ::Gitlab::PollingInterval.set_api_header(self, interval: 10_000)
            # `applicable_to_branch` returns an Array (filtered in Ruby
            # because wildcard matching cannot be expressed in SQL with
            # the existing schema), so we paginate in memory. The number
            # of external status checks per project is bounded in
            # practice; sort by `id` in Ruby for deterministic pagination.
            applicable_checks = user_project.external_status_checks
                                            .applicable_to_branch(merge_request.target_branch)
                                            .sort_by(&:id)
            present(paginate(::Kaminari.paginate_array(applicable_checks)), with: Entities::MergeRequests::StatusCheck, merge_request: merge_request, sha: merge_request.diff_head_sha, current_user: current_user)
          end

          desc 'Retry failed status check for a merge request' do
            detail 'Retries a specified failed external status check for a merge request. Even though the merge ' \
              'request has not changed, this endpoint resends the current state of merge request to the defined ' \
              'external service.'
            success code: 202
            tags ['external_status_checks']
          end
          params do
            requires :id, type: String, desc: 'ID or URL-encoded path of the project.', documentation: { example: '1' }
            requires :merge_request_iid,
              type: Integer,
              desc: 'Internal ID of the merge request.',
              documentation: { example: 1 }
            requires :external_status_check_id, as: :id, type: Integer, desc: 'ID of the failed external status check.'
          end
          route_setting :tier, :ultimate
          route_setting :authorization, permissions: :retry_external_status_check, boundary_type: :project
          post ':external_status_check_id/retry' do
            merge_request = find_merge_request_with_access(params[:merge_request_iid], :retry_failed_status_checks)
            response = ::ExternalStatusChecks::RetryService.new(
              container: user_project,
              current_user: current_user,
              params: declared_params(include_missing: false).merge(merge_request: merge_request)
            ).execute

            if response.success?
              accepted!
            else
              render_api_error!(response.payload[:errors], response.reason)
            end
          end
        end
      end
    end
  end
end
