# frozen_string_literal: true

module SecretsManagement
  module ProjectSecrets
    # Given a secret_detection vulnerability, resolves the leaked GLPAT server-side, then rotates
    # and stores it. The caller never sends the personal access token id or the token value.
    class CreateFromLeakedTokenService < ProjectBaseService
      include Gitlab::InternalEventsTracking

      def execute(vulnerability_id:, name:, environment: '*', branch: '*', description: nil)
        result = rotate_leaked_token(vulnerability_id, name: name, environment: environment, branch: branch,
          description: description)
        track_outcome(outcome_label(result))

        result
      rescue StandardError
        # The leaked token may already be revoked when the store raises, so record it before re-raising.
        track_outcome('exception')
        raise
      end

      private

      def rotate_leaked_token(vulnerability_id, name:, environment:, branch:, description:)
        vulnerability = project.vulnerabilities.find_by_id(vulnerability_id)
        unless vulnerability && Ability.allowed?(current_user, :read_vulnerability, vulnerability)
          return error(_('Vulnerability not found'), :vulnerability_not_found)
        end

        unless vulnerability.secret_detection?
          return error(_('Not a secret detection vulnerability'), :not_secret_detection)
        end

        @token = resolve_personal_access_token(vulnerability.finding)
        unless @token
          return error(
            _('Could not resolve a GitLab personal access token from this vulnerability'),
            :token_not_resolved
          )
        end

        result = CreateFromRotatedTokenService.new(project, current_user).execute(
          personal_access_token_id: @token.id,
          name: name,
          environment: environment,
          branch: branch,
          description: description
        )

        refresh_token_status(vulnerability.finding) if result.success?

        result
      end

      def track_outcome(label)
        track_internal_event(
          'rotate_leaked_token_from_vulnerability',
          user: current_user,
          project: project,
          namespace: project.namespace,
          additional_properties: {
            label: label,
            property: token_type
          }.compact
        )
      end

      def outcome_label(result)
        result.success? ? 'success' : (result.reason || :error).to_s
      end

      def token_type
        return unless @token

        @token.granular? ? 'granular' : 'legacy'
      end

      def resolve_personal_access_token(finding)
        token_value = finding&.token_value
        return unless token_value

        Security::SecretDetection::TokenLookupService.new
          .find('gitlab_personal_access_token', [token_value])[token_value]
      end

      # The token is already rotated and stored here, so a failed status refresh must not fail the request.
      def refresh_token_status(finding)
        # Mirrors UpdateTokenStatusService#can_run?; the service returns early when gated off and reports no reason.
        unless project.security_setting&.validity_checks_enabled
          Gitlab::AppLogger.info(
            Labkit::Fields::CLASS_NAME => self.class.name,
            Labkit::Fields::LOG_MESSAGE =>
              'Skipped token status refresh after rotating a leaked token: validity checks are disabled',
            Labkit::Fields::GL_PROJECT_ID => project.id,
            vulnerability_finding_id: finding.id
          )
          return
        end

        Security::SecretDetection::UpdateTokenStatusService.new.execute_for_vulnerability_finding(finding.id)
      rescue StandardError => e
        Gitlab::ErrorTracking.track_exception(e, vulnerability_finding_id: finding.id)
      end

      def error(message, reason)
        ServiceResponse.error(message: message, reason: reason)
      end
    end
  end
end
