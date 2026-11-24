# frozen_string_literal: true

module Resolvers
  module AuditEvents
    module Instance
      class AmazonS3ConfigurationsResolver < BaseResolver
        type [::Types::AuditEvents::Instance::AmazonS3ConfigurationType], null: true

        def resolve
          ::AuditEvents::Instance::AmazonS3Configuration.all
        end
      end
    end
  end
end
