# frozen_string_literal: true

module Files
  class BaseService < Commits::CreateService
    FileChangedError = Class.new(StandardError)

    def initialize(*args)
      super

      if current_user.present?
        git_user = Gitlab::Git::User.from_gitlab(
          Gitlab::Auth::Identity.resolve_composite_identity_actor(current_user)
        )
      end

      @author_email = commit_email(git_user)
      @author_name = params[:author_name] || git_user&.name
      @commit_message = params[:commit_message]
      @last_commit_sha = params[:last_commit_sha]

      @file_path = params[:file_path]
      @previous_path = params[:previous_path]

      @file_content = params[:file_content]

      if params[:file_content_encoding] == 'base64' && @file_content.present?
        @file_content = Base64.decode64(@file_content)
      end

      @execute_filemode = params[:execute_filemode]
    end

    def file_has_changed?(path, commit_id)
      return false unless commit_id

      last_commit_from_branch = get_last_commit_for_path(ref: @start_branch, path: path)

      return false unless last_commit_from_branch

      last_commit_from_commit_id = get_last_commit_for_path(ref: commit_id, path: path)

      return false unless last_commit_from_commit_id

      last_commit_from_branch.sha != last_commit_from_commit_id.sha
    end

    private

    def validate!
      super

      raise_error(_('You must provide a commit message')) if @commit_message.to_s.empty?
    end

    def validate_permissions!
      super

      validate_start_project!
    end

    # A file commit may start from another project only when it is upstream of this fork and the
    # user can read its code; the REST and GraphQL commit endpoints rely on this check.
    def validate_start_project!
      return if @start_project == project
      return if project.forked_from?(@start_project) && can?(current_user, :read_code, @start_project)

      raise ForbiddenError, "Project is not included in the fork network for #{@start_project.full_name}"
    end

    def get_last_commit_for_path(ref:, path:)
      Gitlab::Git::Commit.last_for_path(@start_project.repository, ref, path, literal_pathspec: true)
    end

    def commit_email(git_user)
      return params[:author_email] if params[:author_email].present?
      return unless current_user

      namespace_commit_email = current_user.namespace_commit_email_for_project(@start_project)

      return namespace_commit_email.email.email if namespace_commit_email

      git_user.email
    end
  end
end
