# frozen_string_literal: true

module Cd
  class DeploymentTransition < ApplicationRecord
    include BulkInsertSafe

    self.table_name = 'cd_deployment_transitions'

    STATES = {
      initial: 0,
      pending: 1,
      deploying: 2,
      healthy: 3,
      degraded: 4,
      failed: 5,
      cancelled: 6
    }.freeze

    belongs_to :deployment, class_name: 'Cd::Deployment', inverse_of: :deployment_transitions, optional: false
    belongs_to :organization, class_name: '::Organizations::Organization', optional: false

    populate_sharding_key :organization_id, source: :deployment

    scope :ordered, -> { order(created_at: :asc) }

    validates :event, presence: true, length: { maximum: 72 }
    validates :from_state, presence: true
    validates :to_state, presence: true
    validates :principal, presence: true, length: { maximum: 255 }
    validates :on_behalf_of, length: { maximum: 255 }
    validates :reason, length: { maximum: 2000 }
    validates :triggered_by, length: { maximum: 255 }

    enum :from_state, STATES, prefix: :from
    enum :to_state, STATES, prefix: :to

    def readonly?
      persisted?
    end
  end
end
