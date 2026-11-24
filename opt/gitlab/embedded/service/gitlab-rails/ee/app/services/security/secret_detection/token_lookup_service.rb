# frozen_string_literal: true

module Security
  module SecretDetection
    class TokenLookupService
      DIGEST_CONFIG = {
        lookup_method: :with_token_digests,
        token_method: :token_digest
      }.freeze

      ENCRYPTION_CONFIG = {
        lookup_method: :with_encrypted_tokens,
        token_method: :token_encrypted
      }.freeze

      # Shared configuration for runner tokens
      RUNNER_TOKEN_CONFIG = {
        model: Ci::Runner,
        enabled_targets: Scanners::ALL,
        **ENCRYPTION_CONFIG
      }.freeze

      PERSONAL_ACCESS_TOKEN_CONFIG = {
        model: PersonalAccessToken,
        enabled_targets: Scanners::ALL,
        **DIGEST_CONFIG
      }.freeze

      CLUSTERS_AGENT_TOKEN_CONFIG = {
        model: Clusters::AgentToken,
        enabled_targets: Scanners::ALL,
        **ENCRYPTION_CONFIG
      }.freeze

      GROUP_SCIM_AUTH_ACCESS_TOKEN_CONFIG = {
        model: GroupScimAuthAccessToken,
        enabled_targets: Scanners::ALL,
        **ENCRYPTION_CONFIG
      }.freeze

      CI_BUILD_TOKEN_CONFIG = {
        model: Ci::Build,
        enabled_targets: Scanners::ALL,
        **ENCRYPTION_CONFIG
      }.freeze

      INCOMING_EMAIL_TOKEN_CONFIG = {
        insecure: true,
        model: User,
        enabled_targets: Scanners::ALL,
        lookup_method: :with_incoming_email_token,
        token_method: :incoming_email_token
      }.freeze

      FEED_TOKEN_CONFIG = {
        insecure: true,
        model: User,
        enabled_targets: Scanners::ALL,
        lookup_method: :with_feed_token,
        token_method: :feed_token
      }.freeze

      PIPELINE_TRIGGER_CONFIG = {
        insecure: true,
        model: Ci::Trigger,
        enabled_targets: Scanners::ALL,
        lookup_method: :with_token,
        token_method: :token
      }.freeze

      # Maps token type IDs (from secret-detection-rules) to their corresponding GitLab model classes
      # and the methods needed to look them up
      TOKEN_TYPE_CONFIG = {
        'gitlab_personal_access_token' => PERSONAL_ACCESS_TOKEN_CONFIG,
        'gitlab_personal_access_token_routable' => PERSONAL_ACCESS_TOKEN_CONFIG,
        'gitlab_personal_access_token_routable_versioned' => PERSONAL_ACCESS_TOKEN_CONFIG,
        'gitlab_deploy_token' => {
          model: DeployToken,
          enabled_targets: Scanners::ALL,
          **ENCRYPTION_CONFIG
        },
        'gitlab_runner_auth_token' => RUNNER_TOKEN_CONFIG,
        'gitlab_runner_auth_token_routable' => RUNNER_TOKEN_CONFIG,
        'gitlab_kubernetes_agent_token' => CLUSTERS_AGENT_TOKEN_CONFIG,
        'gitlab_scim_oauth_token' => GROUP_SCIM_AUTH_ACCESS_TOKEN_CONFIG,
        'gitlab_ci_build_token' => CI_BUILD_TOKEN_CONFIG,
        'gitlab_incoming_email_token' => INCOMING_EMAIL_TOKEN_CONFIG,
        'gitlab_feed_token_v2' => FEED_TOKEN_CONFIG,
        'gitlab_pipeline_trigger_token' => PIPELINE_TRIGGER_CONFIG,
        'gitlab_oauth_app_secret' => {
          model: ::Authn::OauthApplication,
          enabled_targets: Scanners::ALL,
          lookup_method: :with_token_digests,
          token_method: :secret
        }
      }.freeze

      # Checks if a given token type is supported by this service
      # @param token_type [String] The token type identifier from secret-detection-rules
      # @return [Boolean] true if the token type can be looked up, false otherwise
      def self.supported_token_type?(token_type)
        TOKEN_TYPE_CONFIG.key?(token_type)
      end

      # Returns the scanners whose findings are verified for a token type
      # @param token_type [String] The token type identifier from secret-detection-rules
      # @return [Array<Symbol>] the enabled targets, empty for an unsupported token type
      def self.enabled_targets_for(token_type)
        config = TOKEN_TYPE_CONFIG[token_type]
        return [] unless config

        config.fetch(:enabled_targets)
      end

      # Finds tokens in the database based on their type and raw values
      # @param token_type [String] The type of token to look for (e.g., 'gitlab_personal_access_token')
      # @param token_values [Array<String>] Array of raw token values to search for
      # @return [Hash<String, ActiveRecord::Base>] Hash mapping raw tokens to their database records
      def find(token_type, token_values)
        config = TOKEN_TYPE_CONFIG[token_type]
        return unless config

        if config[:insecure]
          return insecure_token_lookup(config[:model], config[:lookup_method], config[:token_method],
            token_values)
        end

        token_lookup(config[:model], config[:lookup_method], config[:token_method], token_values)
      end

      private

      # Performs token lookup for insecure tokens that are stored in plain text
      # @param model_class [Class] The ActiveRecord model class (e.g., User)
      # @param lookup_method [Symbol] The scope method to use for bulk lookup (e.g., :with_incoming_email_token)
      # @param token_method [Symbol] The method to call on found records to get their stored token value
      # @param token_values [Array<String>] Raw token values to search for
      # @return [Hash<String, ActiveRecord::Base>] Hash mapping raw tokens to their database records
      def insecure_token_lookup(model_class, lookup_method, token_method, token_values)
        results = model_class.public_send(lookup_method, token_values) # rubocop:disable GitlabSecurity/PublicSend -- lookup_method is defined in TOKEN_TYPE_CONFIG and cannot be overridden

        results.index_by { |record| record.public_send(token_method) } # rubocop:disable GitlabSecurity/PublicSend -- token_method is defined in TOKEN_TYPE_CONFIG and cannot be overridden
      end

      # Performs the actual token lookup using the appropriate model and methods
      # @param model_class [Class] The ActiveRecord model class (e.g., PersonalAccessToken)
      # @param lookup_method [Symbol] The scope method to use for bulk lookup (e.g., :with_token_digests)
      # @param token_method [Symbol] The method to call on found records to get their stored token value
      # @param token_values [Array<String>] Raw token values to search for
      # @return [Hash<String, ActiveRecord::Base>] Hash mapping raw tokens to their database records
      def token_lookup(model_class, lookup_method, token_method, token_values)
        # Create a hash mapping encoded tokens to their raw values
        # This allows us to map found records back to the original raw tokens
        #   e.g. `{ "encrypted_value_for_token1" => "raw_token1_value",
        #           "encrypted_value_for_token2" => "raw_token2_value" }`
        encrypted_to_raw_token = token_values.each_with_object({}) do |raw_token_value, result|
          encoded_candidates(model_class, raw_token_value).each { |encoded| result[encoded] = raw_token_value }
        end

        # Bulk lookup all tokens using the model's scope method
        results = model_class.public_send(lookup_method, encrypted_to_raw_token.keys) # rubocop:disable GitlabSecurity/PublicSend -- lookup_method is defined in TOKEN_TYPE_CONFIG and cannot be overridden

        # Build the final result hash mapping raw tokens to their database records
        results.each_with_object({}) do |found_token, result|
          raw_token = encrypted_to_raw_token[found_token.public_send(token_method)] # rubocop:disable GitlabSecurity/PublicSend -- token_method is defined in TOKEN_TYPE_CONFIG and cannot be overridden
          result[raw_token] = found_token
        end
      end

      # Token fields depending on db_key_base return one value per key, to find
      # tokens encoded before a rotation. Other models (e.g. OAuth apps) only encode.
      def encoded_candidates(model_class, raw_token_value)
        return model_class.encode_candidates(raw_token_value) if model_class.respond_to?(:encode_candidates)

        [model_class.encode(raw_token_value)]
      end
    end
  end
end
