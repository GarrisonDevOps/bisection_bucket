# frozen_string_literal: true

require 'generators/rspec'

module Rspec
  module Generators
    class ExperimentGenerator < Rspec::Generators::Base
      source_root File.expand_path('templates/', __dir__)

      def create_experiment_spec
        template 'experiment_spec.rb', File.join('spec/experiments', class_path, "#{file_name}_experiment_spec.rb")
      end
    end
  end
end
