# frozen_string_literal: true

module Ai
  class SelfHostedModel < ApplicationRecord
    include Gitlab::EncryptedAttribute

    self.table_name = "ai_self_hosted_models"

    RELEASE_STATE_GA = 'GA'
    RELEASE_STATE_BETA = 'BETA'
    RELEASE_STATE_EXPERIMENTAL = 'EXPERIMENTAL'

    # Matches arn:aws:iam::<12 digit account>:role/<optional/path/>role-name. Role names cannot contain
    # a slash and are at most 64 characters. Also accepts the aws-cn and aws-us-gov partitions.
    IAM_ROLE_ARN_REGEX = %r{\Aarn:aws(-cn|-us-gov)?:iam::\d{12}:role/(?:[\w+=,.@-]+/)*[\w+=,.@-]{1,64}\z}

    MODELS_RELEASE_STATE = {
      mistral: RELEASE_STATE_GA,
      llama3: RELEASE_STATE_BETA,
      codegemma: RELEASE_STATE_BETA,
      codestral: RELEASE_STATE_GA,
      codellama: RELEASE_STATE_BETA,
      deepseekcoder: RELEASE_STATE_BETA,
      claude_3: RELEASE_STATE_GA,
      gpt: RELEASE_STATE_GA,
      mixtral: RELEASE_STATE_GA,
      gemini: RELEASE_STATE_BETA,
      general: RELEASE_STATE_BETA,
      embedding: RELEASE_STATE_BETA,
      qwen: RELEASE_STATE_BETA
    }.freeze

    validates :model, presence: true
    validates :endpoint, presence: true, if: :api?
    validates :endpoint, addressable_url: true, if: :validate_api_endpoint?
    validates :name, presence: true, uniqueness: true
    validates :identifier, length: { maximum: 255 }, allow_nil: true
    validates :iam_role, length: { maximum: 2048 }, allow_nil: true
    validates :iam_role, format: { with: IAM_ROLE_ARN_REGEX, message: 'must be a valid IAM role ARN' },
      allow_blank: true, if: :bedrock?
    validates :iam_role, absence: { message: 'can only be set for the Amazon Bedrock provider' }, unless: :bedrock?
    validates :iam_role, absence: { message: 'cannot be set together with an API key' }, if: :bedrock_with_api_token?

    scope :ga_models, -> { where(model: ga_model_families) }

    has_many :feature_settings, foreign_key: :ai_self_hosted_model_id, inverse_of: :self_hosted_model

    attr_encrypted :api_token,
      mode: :per_attribute_iv,
      key: :db_key_base_32,
      algorithm: 'aes-256-gcm',
      encode: true

    enum :model, {
      mistral: 0,
      llama3: 1,
      codegemma: 2,
      codestral: 3,
      codellama: 4,
      deepseekcoder: 5,
      claude_3: 6,
      gpt: 7,
      mixtral: 8,
      general: 9, # internally, this works by using prompts of `claude_3`
      gemini: 10,
      embedding: 11, # supported in AIGW through the EmbeddingLiteLLM adapter
      qwen: 12
    }

    enum :provider, {
      api: 0,
      bedrock: 1,
      vertex_ai: 2
    }

    def self.ga_model_families
      MODELS_RELEASE_STATE.select { |_, state| state == RELEASE_STATE_GA }.keys
    end

    def self.allowed_models_with_family(model_family)
      if ::Ai::TestingTermsAcceptance.has_accepted? || ga_model_families.include?(model_family)
        return where(model: model_family)
      end

      none
    end

    def identifier
      self[:identifier] || ''
    end

    def model_ref
      identifier.presence || model.to_s
    end

    # AI Gateway rejects an IAM role combined with an API key.
    def iam_role_metadata
      return {} unless bedrock? && iam_role.present? && api_token.blank?

      { iam_role: iam_role }
    end

    def to_model_selection
      { ref: model_ref, name: name }
    end

    def release_state
      MODELS_RELEASE_STATE[self[:model]&.to_sym] || RELEASE_STATE_EXPERIMENTAL
    end

    def ga?
      release_state == RELEASE_STATE_GA
    end

    def unsupported_family_for_duo_agent_platform_code_review?
      %w[gpt general claude_3 qwen].exclude?(model)
    end

    private

    def bedrock_with_api_token?
      bedrock? && api_token.present?
    end

    def validate_api_endpoint?
      api? && endpoint.present?
    end
  end
end
