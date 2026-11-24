# frozen_string_literal: true

module Security
  # https://docs.gitlab.com/ee/development/sec/token_revocation_api.html#get-v1revocable_token_types
  GLPAT_RULE_IDS = %w[
    gitlab_personal_access_token
    gitlab_personal_access_token_routable
    gitlab_personal_access_token_routable_versioned
  ].freeze

  # A GSS finding carries both identifier types, so one rule can reach us under either prefix.
  GLPAT_KEY_TYPES = [
    ::Security::SecretDetection::RuleIdentifiers::GITLEAKS_TYPE,
    ::Security::SecretDetection::RuleIdentifiers::GSS_TYPE
  ].product(GLPAT_RULE_IDS).map { |identifier_type, rule_id| "#{identifier_type}_#{rule_id}" }.freeze

  # Service for alerting revocation service of leaked security tokens
  #
  class TokenRevocationService < ::BaseService
    include Gitlab::InternalEventsTracking

    #########################################
    ### Reasons tokens could not be revoked
    UNSUPPORTED = 'unsupported'
    COMM_FAILURE = 'srs_comm_failure'
    ERROR = 'error'

    RevocationFailedError = Class.new(StandardError)

    def initialize(revocable_keys:, project:)
      @revocable_keys = revocable_keys
      @project = project
    end

    def execute
      glpats, @revocable_keys = @revocable_keys.partition { |key| GLPAT_KEY_TYPES.include?(key[:type]) }

      revoke_glpats(glpats)

      return success if @revocable_keys.empty? || !external_token_revocation_enabled?
      raise RevocationFailedError, 'Missing revocation token data' if missing_token_data?

      return success if revoke_token_body.blank?

      response = revoke_tokens

      unless response.success?
        @revocable_keys.each do |key|
          log_unable_to_revoke_token(key_type: key[:type], reason: COMM_FAILURE)
        end
        return error('Failed to revoke tokens')
      end

      @revocable_keys.each { |key| log_token_revocation(key_type: key[:type]) }

      success
    rescue RevocationFailedError => exception
      error(exception.message)
    rescue StandardError => exception
      log_token_revocation_error(exception)
      error(exception.message)
    end

    private

    attr_reader :project

    # Deduplicate pats before revocation regardless of file location
    def revoke_glpats(tokens)
      tokens
        .uniq { |pat| pat[:token] }
        .each { |token| revoke_glpat(token) }
    end

    def revoke_glpat(token)
      pat = PersonalAccessToken.active.find_by_token(token[:token])

      return unless pat
      return unless AccessTokenValidationService.new(pat).validate == :valid

      result = PersonalAccessTokens::RevokeService.new(
        Users::Internal.in_organization(project.organization).security_bot,
        token: pat,
        source: :secret_detection
      ).execute

      if result[:status] == :error
        log_unable_to_revoke_token(key_type: token[:type], reason: ERROR)
        raise RevocationFailedError, result[:message]
      end

      log_token_revocation(key_type: token[:type])

      return unless token[:vulnerability].present?

      SystemNoteService.change_vulnerability_state(
        token[:vulnerability],
        Users::Internal.in_organization(project.organization).security_bot,
        revocation_comment
      )
    end

    def external_token_revocation_enabled?
      ::Gitlab::CurrentSettings.secret_detection_token_revocation_enabled?
    end

    def revoke_tokens
      ::Gitlab::HTTP.post(
        token_revocation_url,
        body: revoke_token_body,
        headers: {
          'Content-Type' => 'application/json',
          'Authorization' => revocation_api_token
        }
      )
    end

    def missing_token_data?
      token_revocation_url.blank? || token_types_url.blank? || revocation_api_token.blank?
    end

    def log_token_revocation_error(error)
      log_error(
        error: error.class.name,
        message: error.message,
        source: "#{__FILE__}:#{__LINE__}",
        backtrace: error.backtrace
      )
    end

    def build_revoke_token_body(token_types:)
      if token_types.blank?
        @revocable_keys.each do |key|
          log_unable_to_revoke_token(key_type: key[:type], reason: UNSUPPORTED)
        end
        return
      end

      @revocable_keys.filter! do |key|
        revocable = token_types.include?(key[:type])
        log_unable_to_revoke_token(key_type: key[:type], reason: UNSUPPORTED) unless revocable
        revocable
      end

      return if @revocable_keys.blank?

      @revocable_keys.to_json
    end

    def revoke_token_body
      @revoke_token_body ||= begin
        response = ::Gitlab::HTTP.get(
          token_types_url,
          headers: {
            'Content-Type' => 'application/json',
            'Authorization' => revocation_api_token
          }
        )
        raise RevocationFailedError, 'Failed to get revocation token types' unless response.success?

        token_types = ::Gitlab::Json.safe_parse(response.body)['types']

        build_revoke_token_body(token_types: token_types)
      end
    end

    def token_types_url
      ::Gitlab::CurrentSettings.secret_detection_revocation_token_types_url
    end

    def token_revocation_url
      ::Gitlab::CurrentSettings.secret_detection_token_revocation_url
    end

    def revocation_api_token
      ::Gitlab::CurrentSettings.secret_detection_token_revocation_token
    end

    def revocation_comment
      s_("TokenRevocation|This personal access token has been automatically revoked on detection. " \
         "Consider investigating and rotating before marking this vulnerability as resolved.")
    end

    #################################################################
    ## Internal tracking methods

    def log_token_revocation(key_type:)
      track_internal_event(
        'revoke_leaked_token_after_vulnerability_report_is_ingested',
        project: project,
        namespace: project.namespace,
        additional_properties: {
          label: key_type
        }
      )
    end

    def log_unable_to_revoke_token(key_type:, reason:)
      track_internal_event(
        'leaked_token_unable_to_be_revoked_after_vulnerability_report_is_ingested',
        project: project,
        namespace: project.namespace,
        additional_properties: {
          label: key_type,
          property: reason
        }
      )
    end
  end
end
