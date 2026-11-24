# frozen_string_literal: true

require 'active_model'

module Gitlab
  class Experiment
    include ActiveModel::Model

    # Used for generating routes. We've included the method and `ActiveModel::Model` here because these things don't
    # make sense outside of Rails environments.
    def self.model_name
      ActiveModel::Name.new(self, Gitlab)
    end

    class Engine < ::Rails::Engine
      isolate_namespace Experiment

      initializer('gitlab_experiment.include_dsl') { include_dsl }
      initializer('gitlab_experiment.mount_engine') { |app| mount_engine(app, Configuration.mount_at) }

      private

      def include_dsl
        Dsl.include_in(ActionController::API, with_helper: false) if defined?(ActionController)
        Dsl.include_in(ActionController::Base, with_helper: true) if defined?(ActionController)
        Dsl.include_in(ActionMailer::Base, with_helper: true) if defined?(ActionMailer)
      end

      def mount_engine(app, mount_at)
        return if mount_at.blank?

        engine = routes do
          default_url_options app.routes.default_url_options.clone.without(:script_name)
          resources :experiments, path: '/', only: :show
        end

        app.config.middleware.use(Middleware, mount_at)
        app.routes.append do
          mount Engine, at: mount_at, as: :experiment_engine
          direct(:experiment_redirect) do |ex, options|
            url = options[:url]
            "#{engine.url_helpers.experiment_url(ex)}?#{url}"
          end
        end
      end
    end
  end
end
