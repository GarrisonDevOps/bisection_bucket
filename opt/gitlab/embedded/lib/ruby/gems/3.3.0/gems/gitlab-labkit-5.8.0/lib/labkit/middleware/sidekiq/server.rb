# frozen_string_literal: true

module Labkit
  module Middleware
    module Sidekiq
      # This is a wrapper around all the sidekiq server-middleware in labkit
      # The only middleware that needs to be added to the chain in GitLab-rails
      #
      # It uses a new `Sidekiq::Middleware::Chain` to string multiple middlewares
      # together.
      class Server
        def self.chain
          @chain ||= ::Sidekiq::Middleware::Chain.new do |chain|
            chain.add Labkit::Middleware::Sidekiq::Context::Server
            chain.add Labkit::Middleware::Sidekiq::Tracing::Server if Labkit::Tracing.enabled?
            chain.add Labkit::Middleware::Sidekiq::UserExperienceSli::Server
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
