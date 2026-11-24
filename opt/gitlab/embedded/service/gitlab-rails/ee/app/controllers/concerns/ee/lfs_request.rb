# frozen_string_literal: true

module EE
  module LfsRequest
    extend ActiveSupport::Concern
    extend ::Gitlab::Utils::Override
    include ::Gitlab::Utils::StrongMemoize

    LfsForbiddenError = Class.new(StandardError)

    private

    override :lfs_forbidden!
    def lfs_forbidden!
      check_free_user_cap_over_limit!

      limit_exceeded? ? render_size_error : super
    rescue LfsForbiddenError => e
      render_over_limit_error(e.message, 'user/free_user_limit')
    end

    override :limit_exceeded?
    def limit_exceeded?
      size_checker.changes_will_exceed_size_limit?(lfs_objects_change_size, project) ||
        ::Namespaces::FreeUserCap::Enforcement.new(project.root_ancestor).over_limit?
    end
    strong_memoize_attr :limit_exceeded?

    def render_size_error
      render(
        json: {
          message: error_message,
          documentation_url: help_url
        },
        content_type: ::LfsRequest::CONTENT_TYPE,
        status: :not_acceptable
      )
    end

    def check_free_user_cap_over_limit!
      ::Namespaces::FreeUserCap::Enforcement.new(project.root_ancestor)
                                            .git_check_over_limit!(::LfsRequest::LfsForbiddenError)
    end

    def render_over_limit_error(message, help_path)
      render(
        json: {
          message: message,
          documentation_url: help_url(help_path)
        },
        content_type: ::LfsRequest::CONTENT_TYPE,
        status: :not_acceptable
      )
    end

    def size_checker
      project.repository_size_checker
    end

    def error_message
      return size_checker.error_message.push_error if size_checker.above_size_limit?

      size_checker.error_message.new_changes_error
    end

    def lfs_objects_change_size
      return 0 if lfs_push_size == 0
      return lfs_push_size if existing_pushed_lfs_objects_size == 0

      lfs_push_size - existing_pushed_lfs_objects_size
    end
    strong_memoize_attr :lfs_objects_change_size

    def existing_pushed_lfs_objects_size
      oids = objects_oids
      project.lfs_objects.for_oids(oids).sum(:size)
    end

    # objects can contain LFS files that may not have been saved yet.
    def lfs_push_size
      objects.sum { |o| o[:size] }
    end
    strong_memoize_attr :lfs_push_size
  end
end
