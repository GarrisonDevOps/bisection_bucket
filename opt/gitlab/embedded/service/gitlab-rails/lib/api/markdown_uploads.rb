# frozen_string_literal: true

module API
  class MarkdownUploads < ::API::Base
    include PaginationParams
    include APIGuard

    feature_category :team_planning

    FILENAME_QUERY_PARAM_REQUIREMENTS = ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS.merge(
      filename: ::API::NO_SLASH_URL_PART_REGEX
    )

    # Reads are opt-in per route: listing and ID lookup allow upload enumeration.
    allow_access_with_scope :ai_workflows, if: ->(request) do
      request.post? ||
        ((request.get? || request.head?) &&
          request.env[Grape::Env::API_ENDPOINT]&.route_setting(:ai_workflows_download).present?)
    end

    before { authenticate_non_get! }

    helpers do
      def find_uploads(parent)
        uploads = Banzai::UploadsFinder.new(parent: parent).execute
        uploads.preload_uploaded_by_user
      end

      def find_upload(parent, upload_id: nil, secret: nil, filename: nil)
        finder = Banzai::UploadsFinder.new(parent: parent)

        if upload_id
          finder.find(upload_id)
        else
          finder.find_by_secret_and_filename(secret, filename)
        end
      end
    end

    params do
      requires :id, types: [String, Integer], desc: 'ID or URL-encoded path of the project.'
    end
    resource :projects, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
      desc 'Workhorse authorize the file upload' do
        detail 'This feature was introduced in GitLab 13.11'
        success code: 200
        failure [
          { code: 403, message: 'Forbidden' },
          { code: 404, message: 'Not found' },
          { code: 429, message: 'Too many requests' }
        ]
        tags %w[projects]
      end
      route_setting :authorization, skip_granular_token_authorization: :workhorse_pre_authorization
      post ':id/uploads/authorize' do
        require_gitlab_workhorse!
        project = user_project
        authorize! :upload_file, project
        check_rate_limit_by_user_or_ip!(:markdown_upload_bytes, peek: true)

        status 200
        content_type Gitlab::Workhorse::INTERNAL_API_CONTENT_TYPE
        FileUploader.workhorse_authorize(has_length: false, maximum_size: project.max_attachment_size)
      end

      desc 'Create an upload' do
        detail 'Uploads a file to the specified project to be used in an issue or merge request description, or a ' \
          'comment. In the response, `full_path` is the absolute path to the file, and `url` can be used in ' \
          'Markdown contexts. The link is expanded when the format in `markdown` is used.'
        success code: 201, model: Entities::ProjectUpload
        failure [
          { code: 403, message: 'Forbidden' },
          { code: 404, message: 'Not found' },
          { code: 429, message: 'Too many requests' }
        ]
        tags %w[projects]
      end
      params do
        requires :file, types: [Rack::Multipart::UploadedFile, ::API::Validations::Types::WorkhorseFile],
          desc: 'The attachment file to be uploaded', documentation: { type: 'file' }
      end
      route_setting :authorization, permissions: :create_markdown_upload, boundary_type: :project
      post ':id/uploads' do
        project = user_project
        authorize! :upload_file, project
        check_rate_limit_by_user_or_ip!(:markdown_upload_bytes, cost: params[:file].size)

        upload = UploadService.new(project, params[:file], uploaded_by_user_id: current_user.id).execute

        present upload, with: Entities::ProjectUpload
      end

      desc 'List all uploads' do
        detail 'Lists all uploads of a project sorted by `created_at` in descending order. You must have the ' \
          'Maintainer or Owner role for the project. This feature was introduced in GitLab 17.2.'
        success code: 200, model: Entities::MarkdownUploadAdmin
        failure [
          { code: 403, message: 'Unauthenticated' },
          { code: 404, message: 'Not found' }
        ]
        is_array true
        tags %w[projects]
      end
      params do
        use :pagination
      end
      route_setting :authorization, permissions: :read_markdown_upload, boundary_type: :project
      get ':id/uploads' do
        authorize! :admin_upload, user_project

        uploads = find_uploads(user_project)

        present paginate(uploads), with: Entities::MarkdownUploadAdmin
      end

      desc 'Download an uploaded file by ID' do
        detail 'Downloads an uploaded file with a specified ID. You must have the Maintainer or Owner role for the ' \
          'project. This feature was introduced in GitLab 17.2.'
        success File
        failure [
          { code: 403, message: 'Unauthenticated' },
          { code: 404, message: 'Not found' }
        ]
        tags %w[projects]
      end
      params do
        requires :upload_id, type: Integer, desc: 'ID of the upload.'
      end
      route_setting :authorization, permissions: :read_markdown_upload, boundary_type: :project
      get ':id/uploads/:upload_id' do
        # Fetching uploads by ID is maintainer-only because it can be used to enumerate uploads
        # even without the secret
        authorize! :admin_upload, user_project

        upload = find_upload(user_project, upload_id: params[:upload_id])

        present_carrierwave_file!(upload.retrieve_uploader)
      end

      desc 'Download an uploaded file by secret and filename' do
        detail 'Downloads an uploaded file with a specified secret and filename. You must have the Guest, Planner, ' \
          'Reporter, Developer, Maintainer, or Owner role for the project. For a file linked from a description or ' \
          'comment, take the secret and filename from the link. On a rendered page, the link has the format ' \
          '`https://gitlab.example.com/-/project/<project_id>/uploads/<secret>/<filename>`. To get the API URL, ' \
          'replace `/-/project/` with `/api/v4/projects/`. In raw Markdown, the link is ' \
          '`/uploads/<secret>/<filename>` and does not include the project or group. Files that belong to a ' \
          'group, for example in an epic, use the group uploads endpoint. Use the filename from the link, ' \
          'not from the original file. GitLab can change the filename on upload, for example by replacing ' \
          'spaces with underscores. This feature was introduced in GitLab 17.4.'
        success File
        failure [
          { code: 403, message: 'Unauthenticated' },
          { code: 404, message: 'Not found' }
        ]
        tags %w[projects]
      end
      params do
        requires :secret, type: String, desc: '32-character secret of the upload.'
        requires :filename, type: String, file_path: true, desc: 'Filename of the upload.'
      end
      route_setting :authorization, permissions: :read_markdown_upload, boundary_type: :project
      route_setting :ai_workflows_download, true
      get ':id/uploads/:secret/:filename', requirements: FILENAME_QUERY_PARAM_REQUIREMENTS do
        authorize! :read_upload, user_project

        upload = find_upload(user_project, secret: params[:secret], filename: params[:filename])

        present_carrierwave_file!(upload&.retrieve_uploader)
      end

      desc 'Delete an uploaded file by ID' do
        detail 'Deletes an uploaded file with a specified ID. You must have the Maintainer or Owner role for the ' \
          'project. This feature was introduced in GitLab 17.2.'
        success code: 204
        failure [
          { code: 400, message: 'Bad request' },
          { code: 403, message: 'Unauthenticated' },
          { code: 404, message: 'Not found' }
        ]
        tags %w[projects]
      end
      params do
        requires :upload_id, type: Integer, desc: 'ID of the upload.'
      end
      route_setting :authorization, permissions: :delete_markdown_upload, boundary_type: :project
      delete ':id/uploads/:upload_id' do
        authorize! :destroy_upload, user_project

        upload = find_upload(user_project, upload_id: params[:upload_id])
        result = Uploads::DestroyService.new(user_project, current_user).execute(upload)

        if result[:status] == :success
          status 204
        else
          bad_request!(result[:message])
        end
      end

      desc 'Delete an uploaded file by secret and filename' do
        detail 'Deletes an uploaded file with a specified secret and filename. You must have the Maintainer or ' \
          'Owner role for the project. This feature was introduced in GitLab 17.4.'
        success code: 204
        failure [
          { code: 400, message: 'Bad request' },
          { code: 403, message: 'Unauthenticated' },
          { code: 404, message: 'Not found' }
        ]
        tags %w[projects]
      end
      params do
        requires :secret, type: String, desc: '32-character secret of the upload.'
        requires :filename, type: String, file_path: true, desc: 'Filename of the upload.'
      end
      route_setting :authorization, permissions: :delete_markdown_upload, boundary_type: :project
      delete ':id/uploads/:secret/:filename', requirements: FILENAME_QUERY_PARAM_REQUIREMENTS do
        authorize! :destroy_upload, user_project

        upload = find_upload(user_project, secret: params[:secret], filename: params[:filename])
        result = Uploads::DestroyService.new(user_project, current_user).execute(upload)

        if result[:status] == :success
          status 204
        else
          bad_request!(result[:message])
        end
      end
    end

    params do
      requires :id, types: [String, Integer], desc: 'ID or URL-encoded path of the group.'
    end
    resource :groups, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
      desc 'Workhorse authorize the file upload' do
        detail 'This feature was introduced in GitLab 19.0'
        success code: 200
        failure [
          { code: 403, message: 'Forbidden' },
          { code: 404, message: 'Not found' },
          { code: 429, message: 'Too many requests' }
        ]
        tags %w[groups]
      end
      route_setting :authorization, skip_granular_token_authorization: :workhorse_pre_authorization
      post ':id/uploads/authorize' do
        authorize! :upload_file, user_group

        require_gitlab_workhorse!
        check_rate_limit_by_user_or_ip!(:markdown_upload_bytes, peek: true)

        status 200
        content_type Gitlab::Workhorse::INTERNAL_API_CONTENT_TYPE
        NamespaceFileUploader.workhorse_authorize(
          has_length: false,
          maximum_size: Gitlab::CurrentSettings.max_attachment_size.megabytes.to_i
        )
      end

      desc 'Upload a file to a group' do
        detail 'Uploads a file to the specified group. Returns a markdown-formatted link to the file. ' \
          'This feature was introduced in GitLab 19.0.'
        success code: 201, model: Entities::GroupUpload
        failure [
          { code: 400, message: 'Bad request' },
          { code: 403, message: 'Forbidden' },
          { code: 404, message: 'Not found' },
          { code: 429, message: 'Too many requests' }
        ]
        tags %w[groups]
      end
      params do
        requires :file, types: [Rack::Multipart::UploadedFile, ::API::Validations::Types::WorkhorseFile],
          desc: 'The file to upload', documentation: { type: 'file' }
      end
      route_setting :authorization, permissions: :create_markdown_upload, boundary_type: :group
      post ':id/uploads' do
        group = user_group
        authorize! :upload_file, group
        check_rate_limit_by_user_or_ip!(:markdown_upload_bytes, cost: params[:file].size)

        upload = UploadService.new(group, params[:file], NamespaceFileUploader,
          uploaded_by_user_id: current_user.id).execute

        bad_request!('Failed to upload file') unless upload

        present upload, with: Entities::GroupUpload
      end

      desc 'List all uploads for a group' do
        detail 'Lists all uploads for a specified group sorted by `created_at` in descending order. You must have ' \
          'the Maintainer or Owner role for the group. This feature was introduced in GitLab 17.2.'
        success code: 200, model: Entities::MarkdownUploadAdmin
        failure [
          { code: 403, message: 'Unauthenticated' },
          { code: 404, message: 'Not found' }
        ]
        is_array true
        tags %w[groups]
      end
      params do
        use :pagination
      end
      route_setting :authorization, permissions: :read_markdown_upload, boundary_type: :group
      get ':id/uploads' do
        authorize! :admin_upload, user_group

        uploads = find_uploads(user_group)

        present paginate(uploads), with: Entities::MarkdownUploadAdmin
      end

      desc 'Download an uploaded file by ID' do
        detail 'Downloads an uploaded file with a specified ID. You must have the Maintainer or Owner role for the ' \
          'group. This feature was introduced in GitLab 17.2.'
        success File
        failure [
          { code: 403, message: 'Unauthenticated' },
          { code: 404, message: 'Not found' }
        ]
        tags %w[groups]
      end
      params do
        requires :upload_id, type: Integer, desc: 'ID of the upload.'
      end
      route_setting :authorization, permissions: :read_markdown_upload, boundary_type: :group
      get ':id/uploads/:upload_id' do
        # Fetching uploads by ID is maintainer-only because it can be used to enumerate uploads
        # even without the secret
        authorize! :admin_upload, user_group

        upload = find_upload(user_group, upload_id: params[:upload_id])

        present_carrierwave_file!(upload.retrieve_uploader)
      end

      desc 'Download an uploaded file by secret and filename' do
        detail 'Downloads an uploaded file with a specified secret and filename. You must have the Guest, Planner, ' \
          'Reporter, Developer, Maintainer, or Owner role for the group. For a file linked from a description or ' \
          'comment, take the secret and filename from the link. On a rendered page, the link has the format ' \
          '`https://gitlab.example.com/-/group/<group_id>/uploads/<secret>/<filename>`. To get the API URL, ' \
          'replace `/-/group/` with `/api/v4/groups/`. In raw Markdown, the link is ' \
          '`/uploads/<secret>/<filename>` and does not include the project or group. Files that belong to a ' \
          'project, for example in an issue or merge request, use the project uploads endpoint. ' \
          'Use the filename from the link, ' \
          'not from the original file. GitLab can change the filename on upload, for example by replacing ' \
          'spaces with underscores. This feature was introduced in GitLab 17.4.'
        success File
        failure [
          { code: 403, message: 'Unauthenticated' },
          { code: 404, message: 'Not found' }
        ]
        tags %w[groups]
      end
      params do
        requires :secret, type: String, desc: '32-character secret of the upload.'
        requires :filename, type: String, file_path: true, desc: 'Filename of the upload.'
      end
      route_setting :authorization, permissions: :read_markdown_upload, boundary_type: :group
      route_setting :ai_workflows_download, true
      get ':id/uploads/:secret/:filename', requirements: FILENAME_QUERY_PARAM_REQUIREMENTS do
        authorize! :read_upload, user_group

        upload = find_upload(user_group, secret: params[:secret], filename: params[:filename])

        present_carrierwave_file!(upload&.retrieve_uploader)
      end

      desc 'Delete an uploaded file by ID' do
        detail 'Deletes an uploaded file with a specified ID. You must have the Maintainer or Owner role for the ' \
          'group. This feature was introduced in GitLab 17.2.'
        success code: 204
        failure [
          { code: 400, message: 'Bad request' },
          { code: 403, message: 'Unauthenticated' },
          { code: 404, message: 'Not found' }
        ]
        tags %w[groups]
      end
      params do
        requires :upload_id, type: Integer, desc: 'ID of the upload.'
      end
      route_setting :authorization, permissions: :delete_markdown_upload, boundary_type: :group
      delete ':id/uploads/:upload_id' do
        authorize! :destroy_upload, user_group

        upload = find_upload(user_group, upload_id: params[:upload_id])
        result = Uploads::DestroyService.new(user_group, current_user).execute(upload)

        if result[:status] == :success
          status 204
        else
          bad_request!(result[:message])
        end
      end

      desc 'Delete an uploaded file by secret and filename' do
        detail 'Deletes an uploaded file with a specified secret and filename. You must have the Maintainer or Owner ' \
          'role for the group. This feature was introduced in GitLab 17.4.'
        success code: 204
        failure [
          { code: 400, message: 'Bad request' },
          { code: 403, message: 'Unauthenticated' },
          { code: 404, message: 'Not found' }
        ]
        tags %w[groups]
      end
      params do
        requires :secret, type: String, desc: '32-character secret of the upload.'
        requires :filename, type: String, file_path: true, desc: 'Filename of the upload.'
      end
      route_setting :authorization, permissions: :delete_markdown_upload, boundary_type: :group
      delete ':id/uploads/:secret/:filename', requirements: FILENAME_QUERY_PARAM_REQUIREMENTS do
        authorize! :destroy_upload, user_group

        upload = find_upload(user_group, secret: params[:secret], filename: params[:filename])
        result = Uploads::DestroyService.new(user_group, current_user).execute(upload)

        if result[:status] == :success
          status 204
        else
          bad_request!(result[:message])
        end
      end
    end
  end
end
