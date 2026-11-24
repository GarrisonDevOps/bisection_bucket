# frozen_string_literal: true

module MergeRequests
  class StatusCheckResponse < ApplicationRecord
    self.table_name = 'status_check_responses'

    include ShaAttribute

    TIMEOUT_INTERVAL = 2 # in minutes

    scope :timeout_new, -> { where('retried_at IS NULL AND created_at < ?', TIMEOUT_INTERVAL.minutes.ago) }
    scope :timeout_retried, -> { where('retried_at < ?', TIMEOUT_INTERVAL.minutes.ago) }

    sha_attribute :sha

    belongs_to :merge_request
    belongs_to :external_status_check, class_name: 'MergeRequests::ExternalStatusCheck'

    enum :status, %w[passed failed pending]

    validates :merge_request, presence: true
    validates :external_status_check, presence: true
    validates :sha, presence: true

    after_commit :publish_new_passing_event, if: ->(check) { check.passed? }

    def self.timeout_eligible
      timeout_new.or(timeout_retried)
    end

    private

    def publish_new_passing_event
      ::Gitlab::EventStore.publish(
        ::MergeRequests::ExternalStatusCheckPassedEvent.new(
          data: { merge_request_id: merge_request.id }
        )
      )
    end
  end
end

::MergeRequests::StatusCheckResponse.prepend_mod
