# frozen_string_literal: true

module AuditEvents
  module Instance
    class AmazonS3ConfigurationPolicy < BasePolicy
      delegate { :global }
    end
  end
end
