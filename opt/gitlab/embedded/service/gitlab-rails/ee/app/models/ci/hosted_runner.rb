# frozen_string_literal: true

module Ci
  # Today, this model stores dedicated hosted runners, which are instance level runners
  # managed by GitLab. Note that this does not include GitLab.com's shared
  # hosted runners, which can be identified as being the only instance-level runners on
  # GitLab.com (since users logically cannot create their own instance-level runners there,
  # given it's a shared instance).
  class HostedRunner < ApplicationRecord
    self.table_name = 'ci_hosted_runners'
    self.primary_key = 'runner_id'

    belongs_to :runner, class_name: 'Ci::Runner'

    validates :runner, presence: true
    validates :runner_id, uniqueness: true
    validate :validate_instance_type_runner

    private

    def validate_instance_type_runner
      return unless runner
      return if runner.instance_type?

      errors.add(:runner, 'is not an instance runner')
    end
  end
end
