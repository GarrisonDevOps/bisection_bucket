# frozen_string_literal: true

module DependencyManagement
  class BaseService
    include Gitlab::Loggable

    MERGE_REQUESTS_NOT_PERMITTED = 'Service account cannot create merge requests in this project'
    MERGE_REQUEST_DENIAL_REASONS = %i[
      repository_disabled merge_requests_disabled merge_requests_private access_denied
    ].freeze

    def initialize(project:, params: {})
      @project = project
      @params = params
    end

    private

    attr_reader :project, :params

    def success_response(message: nil, payload: {})
      ServiceResponse.success(message: message, payload: payload)
    end

    def error_response(message:, payload: {}, reason: nil)
      ServiceResponse.error(message: message, payload: payload, reason: reason)
    end

    def log_error(error)
      Gitlab::ErrorTracking.track_exception(
        error,
        class: self.class.name,
        project_id: project.id,
        message: error.message
      )
    end

    # Checks that the service account can open a merge request in the project, so no work starts
    # that cannot end in one. Every denial is logged.
    #
    # @param user [User] the project's service account
    # @return [Symbol, nil] the reason to stop for, or nil to carry on
    def merge_request_denial(user)
      reason = merge_request_denial_reason(user)
      log_merge_request_denial(reason) if reason

      reason
    end

    # @param reason [Symbol] one of MERGE_REQUEST_DENIAL_REASONS
    def log_merge_request_denial(reason)
      Gitlab::AppLogger.info(build_structured_payload_labkit(
        message: 'DependencyManagement: service account cannot create merge requests',
        Labkit::Fields::GL_PROJECT_ID => project.id,
        denial_reason: reason.to_s
      ))
    end

    # @param user [User] the project's service account
    # @return [ServiceResponse, nil] the error to stop with when the account cannot open a merge
    #   request, or nil to carry on
    def merge_request_denial_response(user)
      reason = merge_request_denial(user)
      merge_requests_not_permitted(reason) if reason
    end

    # @param reason [Symbol] one of MERGE_REQUEST_DENIAL_REASONS
    # @return [ServiceResponse]
    def merge_requests_not_permitted(reason)
      error_response(message: MERGE_REQUESTS_NOT_PERMITTED, reason: reason)
    end

    # The policy decides, with the two checks MergeRequests::CreateService makes. The project
    # settings only name the cause of a denial.
    #
    # @param user [User] the project's service account
    # @return [Symbol, nil] nil when the account may create merge requests
    def merge_request_denial_reason(user)
      return if Ability.allowed?(user, :create_merge_request_from, project) &&
        Ability.allowed?(user, :create_merge_request_in, project)

      feature = project.project_feature
      return :repository_disabled if feature.access_level(:repository) == ProjectFeature::DISABLED
      return :merge_requests_disabled if feature.access_level(:merge_requests) == ProjectFeature::DISABLED
      return :merge_requests_private if members_only_merge_requests_block?(user)

      :access_denied
    end

    # The members-only setting is the cause only when it alone blocks the account. Archiving or a
    # removed membership also deny push_code, which the same internal role grants.
    # A read-only namespace denies merge requests but not push_code, so it is checked by name.
    #
    # @param user [User] the project's service account
    # @return [Boolean]
    def members_only_merge_requests_block?(user)
      !project.feature_available?(:merge_requests, user) &&
        Ability.allowed?(user, :push_code, project) &&
        !project.root_namespace.read_only?
    end
  end
end
