# frozen_string_literal: true

module Notes
  # Applies the note creation rate limit to note entry points outside the web
  # and API layers, such as incoming email and chat slash commands.
  class CreateRateLimiter
    # @param author [User] the user the note is created as
    # @param project [Project, nil] the project the note belongs to
    # @param external_author [String, nil] the sender's email address when the
    #     note is created as the support bot for a Service Desk sender
    def initialize(author:, project:, external_author: nil)
      @author = author
      @project = project
      @external_author = external_author&.downcase
    end

    # Counts one note against the limit and reports whether it is over the limit.
    #
    # @return [Boolean]
    def throttled?
      return false unless Feature.enabled?(:notes_create_rate_limit_email_and_chat, :instance)

      throttled = ::Gitlab::ApplicationRateLimiter.throttled?(key, **rate_limit_options)

      log_throttled if throttled

      throttled
    end

    private

    attr_reader :author, :project, :external_author

    # Service Desk notes are all created as the support bot, so they are
    # counted per sender instead of per user. Mail without a sender shares
    # one bucket per project rather than the organization's support bot.
    def service_desk?
      author.support_bot?
    end

    def key
      service_desk? ? :notes_create_by_external_author : :notes_create
    end

    def rate_limit_options
      return { scope: { project: project, external_author: external_author } } if service_desk?

      Gitlab::NotesCreateRateLimit.rate_limit_options(author)
    end

    # Same message as ApplicationRateLimiter.log_request, which needs a web request.
    def log_throttled
      Gitlab::AuthLogger.error(
        message: 'Application_Rate_Limiter_Request',
        env: :"#{key}_request_limit",
        Labkit::Fields::GL_USER_ID => author.id,
        Labkit::Fields::GL_USER_NAME => author.username,
        Labkit::Fields::GL_PROJECT_ID => project&.id
      )
    end
  end
end
