# frozen_string_literal: true

module Labkit
  module Middleware
    module Sidekiq
      # This is a wrapper around all the sidekiq client-middleware in labkit
      # The only middleware that needs to be added to the chain in GitLab-rails
      #
      # It uses a new `Sidekiq::Middleware::Chain` to string multiple middlewares
      # together.
      class Client
        def self.chain
          @chain ||= ::Sidekiq::Middleware::Chain.new do |chain|
            chain.add Labkit::Middleware::Sidekiq::Context::Client
            chain.add Labkit::Middleware::Sidekiq::Tracing::Client if Labkit::Tracing.enabled?
            chain.add Labkit::Middleware::Sidekiq::UserExperienceSli::Client
          end
        end

        def call(*args)
          self.class.chain.invoke(*args) do
            yield
          end
        end
      end
    end
  end
end
