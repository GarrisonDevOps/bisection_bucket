# frozen_string_literal: true

require 'rails/generators'

module Gitlab
  module Generators
    module Experiment
      class InstallGenerator < Rails::Generators::Base
        source_root File.expand_path('templates', __dir__)

        desc 'Installs the Gitlab::Experiment initializer and optional ApplicationExperiment into your application.'

        class_option :skip_initializer,
          type: :boolean, default: false, desc: 'Skip the initializer with default configuration'

        class_option :skip_baseclass, type: :boolean, default: false, desc: 'Skip the ApplicationExperiment base class'

        def create_initializer
          return if options[:skip_initializer]

          template 'initializer.rb', 'config/initializers/gitlab_experiment.rb'
        end

        def create_baseclass
          return if options[:skip_baseclass]

          template 'application_experiment.rb', 'app/experiments/application_experiment.rb'
        end

        def display_post_install
          readme 'POST_INSTALL' if behavior == :invoke
        end
      end
    end
  end
end
