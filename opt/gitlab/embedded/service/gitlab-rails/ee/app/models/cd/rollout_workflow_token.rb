# frozen_string_literal: true

module Cd
  # The AutoFlow capabilities for one rollout's workflow: the token binding that
  # entitles a re-submission to them, and the workflow token every AutoFlow RPC other
  # than StartWorkflow requires. Relay only ever compares these, so neither is
  # readable from the database without the application's encryption keys.
  class RolloutWorkflowToken < ApplicationRecord
    self.table_name = 'cd_rollout_workflow_tokens'

    encrypts :token_binding, :token

    belongs_to :rollout, class_name: 'Cd::Rollout', inverse_of: :workflow_token, optional: false
    belongs_to :organization, class_name: '::Organizations::Organization', optional: false

    populate_sharding_key :organization_id, source: :rollout

    # on: :create so every StartWorkflow attempt for a rollout presents the same binding.
    before_validation :ensure_token_binding, on: :create

    # Both bounds mirror Relay's own rules rather than the generic 510 the encrypted
    # attribute guidelines suggest, so Rails never refuses a value Relay would accept:
    # token_binding must be exactly this length, and is_workflow_token caps a token at
    # 4096 bytes. A real workflow token is around 300 characters.
    validates :token_binding, presence: true,
      length: { is: ::Gitlab::Kas::Client::WORKFLOW_TOKEN_BINDING_BYTES }
    validates :token, length: { maximum: 4096 }

    private

    def ensure_token_binding
      self.token_binding ||= ::Gitlab::Kas::Client.generate_workflow_token_binding
    end
  end
end
