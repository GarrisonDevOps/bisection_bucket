# frozen_string_literal: true

module API
  class MergeRequestDependencies < ::API::Base
    include PaginationParams

    feature_category :code_review_workflow

    helpers do
      def find_block(merge_request)
        merge_request.blocks_as_blockee.find(params[:block_id])
      end
    end

    params do
      requires :id, types: [String, Integer], desc: 'ID or URL-encoded path of the project.'
    end
    resource :projects, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
      desc 'List all dependencies for a merge request' do
        detail 'List all merge request dependencies for a specified merge request. Dependencies must be resolved ' \
          'before the merge request can merge. If the user does not have access to a blocking merge request, the ' \
          '`blocking_merge_request` attribute is not returned.'
        success ::API::Entities::MergeRequestDependency
        tags %w[merge_requests]
        is_array true
      end

      params do
        requires :merge_request_iid, type: Integer, desc: 'Internal ID of the merge request.'
        use :pagination
      end
      route_setting :authorization, permissions: :read_merge_request_dependency, boundary_type: :project
      get ":id/merge_requests/:merge_request_iid/blocks" do
        merge_request = find_merge_request_with_access(params[:merge_request_iid])

        present paginate(merge_request.blocks_as_blockee), with: ::API::Entities::MergeRequestDependency,
          current_user: current_user
      end

      params do
        requires :merge_request_iid, type: Integer, desc: 'Internal ID of the merge request.'
        requires :block_id, type: Integer, desc: 'ID of the merge request block.'
      end
      desc 'Retrieve a merge request dependency' do
        detail 'Retrieves a specified merge request dependency.'
        tags %w[merge_requests]
      end
      route_setting :authorization, permissions: :read_merge_request_dependency, boundary_type: :project
      get ":id/merge_requests/:merge_request_iid/blocks/:block_id", urgency: :low do
        merge_request = find_merge_request_with_access(params[:merge_request_iid])

        present find_block(merge_request),
          with: ::API::Entities::MergeRequestDependency, current_user: current_user
      end

      params do
        requires :merge_request_iid, type: Integer, desc: 'Internal ID of the merge request.'
        requires :block_id, type: Integer, desc: 'ID of the merge request block.'
      end
      desc 'Remove a merge request dependency' do
        detail 'Removes a merge request dependency.'
        success code: 204, message: 'Resource deleted'
        tags %w[merge_requests]
      end
      route_setting :authorization, permissions: :delete_merge_request_dependency, boundary_type: :project
      delete ":id/merge_requests/:merge_request_iid/blocks/:block_id", urgency: :low do
        merge_request = find_merge_request_with_access(params[:merge_request_iid], :update_merge_request)
        block = find_block(merge_request)

        authorize! :read_merge_request, block.blocking_merge_request

        result = ::MergeRequests::DestroyBlockService.new(user: current_user, block: block).execute

        if result.success?
          no_content!
        else
          render_api_error!(result.message, result.reason)
        end
      end

      params do
        requires :merge_request_iid, type: Integer, desc: 'Internal ID of the merge request to be blocked.'
        optional :blocking_merge_request_id, type: Integer, desc: 'Global ID of the blocking merge request. Required ' \
                                                              'if `blocking_merge_request_iid` is not provided.'
        optional :blocking_merge_request_iid, type: Integer, desc: 'Internal ID of the blocking merge request. ' \
                                                               'Required if `blocking_merge_request_id` is not ' \
                                                               'provided.'
        optional :blocking_project_id, types: [String, Integer],
          desc: 'ID or URL-encoded path of the project containing the blocking merge request. Required when ' \
            '`blocking_merge_request_iid` refers to a merge request in a different project. Defaults to the ' \
            'current project.'
        mutually_exclusive :blocking_merge_request_id, :blocking_merge_request_iid
        exactly_one_of :blocking_merge_request_id, :blocking_merge_request_iid
      end
      desc 'Create a merge request dependency' do
        detail 'Creates a merge request dependency between two merge requests. The merge request is blocked ' \
          'until the dependency merges.'
        tags %w[merge_requests]
      end
      route_setting :authorization, permissions: :create_merge_request_dependency, boundary_type: :project
      post ":id/merge_requests/:merge_request_iid/blocks", urgency: :low do
        ::Gitlab::QueryLimiting.disable!('https://gitlab.com/gitlab-org/gitlab/-/issues/592204', new_threshold: 110)

        merge_request = find_project_merge_request(params[:merge_request_iid])

        blocking_merge_request_id =
          if params[:blocking_merge_request_id]
            params[:blocking_merge_request_id]
          else
            # IID-based lookup with optional project context
            blocking_project = params[:blocking_project_id] ? find_project!(params[:blocking_project_id]) : user_project
            blocking_merge_request = blocking_project.merge_requests.find_by_iid(params[:blocking_merge_request_iid])
            blocking_merge_request&.id
          end

        result =
          ::MergeRequests::CreateBlockService
            .new(
              merge_request: merge_request,
              user: current_user,
              blocking_merge_request_id: blocking_merge_request_id
            ).execute

        if result.success?
          present result.payload[:merge_request_block], with: ::API::Entities::MergeRequestDependency, current_user:
            current_user
        else
          render_api_error!(result.message, result.reason)
        end
      end

      desc 'Retrieve blocked merge requests' do
        detail 'Retrieves merge requests blocked by a specified merge request.'
        success ::API::Entities::MergeRequestDependency
        tags %w[merge_requests]
        is_array true
      end

      params do
        requires :merge_request_iid, type: Integer, desc: 'Internal ID of the merge request.'
        use :pagination
      end
      route_setting :authorization, permissions: :read_merge_request_dependency, boundary_type: :project
      get ":id/merge_requests/:merge_request_iid/blockees" do
        merge_request = find_merge_request_with_access(params[:merge_request_iid])

        blockees = merge_request.blocks_as_blocker

        present paginate(blockees), with: ::API::Entities::MergeRequestDependency, current_user: current_user
      end
    end
  end
end
