# frozen_string_literal: true

module API
  class MergeTrains < ::API::Base
    include PaginationParams

    feature_category :continuous_integration
    urgency :low

    before do
      authorize_read_merge_trains!
    end

    params do
      requires :id, types: [String, Integer], desc: 'ID or URL-encoded path of the project.',
        documentation: { example: 11 }
    end
    resource 'projects/:id', requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
      resource :merge_trains do
        # Cars from many trains are mixed together in the response since no target_branch is provided.
        # Consider deprecating: https://gitlab.com/gitlab-org/gitlab/-/issues/406356
        desc 'List all merge trains for a project' do
          detail 'Lists all merge trains for a specified project.'
          success code: 200, model: ::API::Entities::MergeTrains::Car
          failure [
            { code: 401, message: 'Unauthorized' },
            { code: 403, message: 'Forbidden' },
            { code: 404, message: 'Not found' }
          ]
          is_array true
          tags %w[merge_trains]
        end
        params do
          optional :scope, type: String,
            desc: 'Filter merge trains by scope. `active` returns merge trains to be merged. `complete` returns ' \
              'merge trains that have been merged.',
            values: %w[active complete],
            documentation: { example: 'active' }
          optional :sort,
            type: String, desc: 'Sort results in ascending or descending order by `id`. A lower `id` value means the ' \
                            'merge request was added to the train earlier.', values: %w[asc desc], default: 'desc'
          use :pagination
        end
        route_setting :tier, :premium
        route_setting :authorization, permissions: :read_merge_train, boundary_type: :project
        get do
          all_project_cars = ::MergeTrains::CarsFinder
            .new(user_project, current_user, declared_params(include_missing: false))
            .execute
            .preload_api_entities

          present paginate(all_project_cars), with: ::API::Entities::MergeTrains::Car
        end

        params do
          requires :target_branch, type: String, desc: 'The target branch of the merge train'
        end
        resource ':target_branch' do
          desc 'List all merge requests in a merge train' do
            detail 'Lists all merge requests in a merge train for a target branch.'
            success code: 200, model: ::API::Entities::MergeTrains::Car
            failure [
              { code: 401, message: 'Unauthorized' },
              { code: 403, message: 'Forbidden' },
              { code: 404, message: 'Not found' }
            ]
            is_array true
            tags %w[merge_trains]
          end
          params do
            requires :target_branch, type: String, desc: 'Target branch of the merge train.',
              documentation: { example: 'main' }
            optional :scope, type: String,
              desc: 'Filter merge trains by scope. `active` returns merge trains to be merged. `complete` returns ' \
                'merge trains that have been merged.',
              values: %w[active complete],
              documentation: { example: 'active' }
            optional :sort,
              type: String, desc: 'Sort results in ascending or descending order by `id`. A lower ' \
                              '`id` value means the merge request was added to the train ' \
                              'earlier.', values: %w[asc desc], default: 'desc'
            use :pagination
          end
          route_setting :tier, :premium
          route_setting :authorization, permissions: :read_merge_train, boundary_type: :project
          get do
            merge_train = ::MergeTrains::CarsFinder
              .new(user_project, current_user, declared_params(include_missing: false))
              .execute
              .preload_api_entities

            present paginate(merge_train), with: ::API::Entities::MergeTrains::Car
          end
        end

        params do
          requires :merge_request_iid, type: Integer, desc: 'Internal ID of the merge request.'
        end
        resource 'merge_requests/:merge_request_iid', requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
          desc 'Retrieve merge train status' do
            detail 'Retrieves the merge train status of a specified merge request.'
            success code: 200, model: ::API::Entities::MergeTrains::Car
            failure [
              { code: 401, message: 'Unauthorized' },
              { code: 403, message: 'Forbidden' },
              { code: 404, message: 'Not found' }
            ]
            tags %w[merge_trains]
          end
          route_setting :tier, :premium
          route_setting :authorization, permissions: :read_merge_train_merge_request, boundary_type: :project
          get do
            train_car = find_project_merge_request(params[:merge_request_iid]).merge_train_car

            not_found!('Merge Train Merge Request') unless train_car

            present train_car, with: ::API::Entities::MergeTrains::Car
          end
        end

        desc 'Add a merge request to a merge train' do
          detail 'Adds a specified merge request to a merge train.'
          success [
            { code: 201, model: ::API::Entities::MergeTrains::Car },
            { code: 202, model: ::API::Entities::MergeTrains::Car }
          ]
          failure [
            { code: 400, message: 'Failed to merge' },
            { code: 401, message: 'Unauthorized' },
            { code: 404, message: 'Not found' },
            { code: 409, message: 'Conflict' },
            { code: 403, message: 'Forbidden' }
          ]
          is_array true
          tags %w[merge_trains]
        end
        params do
          requires :merge_request_iid, type: Integer, desc: 'Internal ID of the merge request.'
          optional :sha, type: String,
            desc: 'SHA that must match the `HEAD` of the source branch, otherwise the merge fails.'
          optional :squash, type: Grape::API::Boolean,
            desc: 'If `true`, the commits are squashed into a single commit on merge.'
          optional :when_pipeline_succeeds, type: Grape::API::Boolean,
            desc: '[Deprecated](https://gitlab.com/gitlab-org/gitlab/-/issues/521290) in GitLab 17.11. Use ' \
              '`auto_merge` instead.'
          optional :auto_merge, type: Grape::API::Boolean,
            desc: 'If `true`, the merge request is added to the merge train when checks pass. If `false` or ' \
              'unspecified, it is added to the merge train immediately.'
        end
        route_setting :tier, :premium
        route_setting :authorization, permissions: :add_merge_train_merge_request, boundary_type: :project
        post 'merge_requests/:merge_request_iid', requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
          merge_request = find_project_merge_request(params[:merge_request_iid])

          check_sha_param!(params, merge_request)

          merge_params = HashWithIndifferentAccess.new(
            squash: params[:squash],
            auto_merge: params[:when_pipeline_succeeds] || params[:auto_merge],
            sha: params[:sha] || merge_request.diff_head_sha
          )

          response = ::MergeTrains::AddMergeRequestService.new(
            merge_request,
            current_user,
            merge_params
          ).execute

          if response.success?
            whole_merge_train = ::MergeTrains::CarsFinder
              .new(user_project, current_user, { target_branch: merge_request.target_branch })
              .execute
              .preload_api_entities

            if merge_request.merge_train_car
              status 201
            else
              status 202
            end

            present paginate(whole_merge_train), with: ::API::Entities::MergeTrains::Car
          elsif response.reason == :forbidden
            unauthorized!
          elsif response.reason == :conflict
            conflict!(response.message)
          else
            bad_request!(response.message)
          end
        end
      end
    end

    helpers do
      def authorize_read_merge_trains!
        authorize! :read_merge_train, user_project
      end
    end
  end
end
