# frozen_string_literal: true

module AuditEvents
  class AmazonS3ConfigurationPolicy < ::BasePolicy
    delegate { @subject.group }
  end
end
