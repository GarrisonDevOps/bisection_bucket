# frozen_string_literal: true

module Security
  module SecretDetection
    module ValidityChecks
      # Public entry point of the raw-token validity check. Transports call this
      # class only; every other class in this namespace is private to it.
      #
      # The caller names the project it acts for, and the project policy decides
      # whether it may. Nothing else in the namespace sees a User or a Project.
      #
      # Raw tokens have no finding, so nothing is persisted and no token value
      # leaves the batch except to the verifier.
      class VerifyRawTokensService
        # @param project [Project] the project the caller acts for, resolved by the transport
        # @param tokens [Array<Hash>] { id:, token_type:, raw_token: } per token, with unique ids
        # @param organization_id [Integer, nil] the caller's organization. Accepted but unused until lookups
        #   are narrowed in https://gitlab.com/gitlab-org/gitlab/-/work_items/637863; lookups are instance-wide today.
        def initialize(current_user:, project:, tokens:, organization_id:)
          @current_user = current_user
          @project = project
          @batch = RawTokenBatch.new(tokens)
          @organization_id = organization_id
        end

        # @return [ServiceResponse] success with payload { results: }, one entry per id;
        #   error with reason :not_found for every denial, so the endpoint stays invisible
        #   to callers it is not for
        def execute
          return not_found unless authorized?

          ServiceResponse.success(payload: { results: batch.results(verify) })
        end

        private

        attr_reader :current_user, :project, :batch, :organization_id

        def authorized?
          project && Ability.allowed?(current_user, :verify_secret_detection_raw_token, project)
        end

        def verify
          verifier = GitlabTokenVerifier.new(organization_id: organization_id)

          batch.by_type.to_h { |token_type, raw_tokens| [token_type, verifier.verify(token_type, raw_tokens)] }
        end

        def not_found
          ServiceResponse.error(message: 'Not found', reason: :not_found)
        end
      end
    end
  end
end
