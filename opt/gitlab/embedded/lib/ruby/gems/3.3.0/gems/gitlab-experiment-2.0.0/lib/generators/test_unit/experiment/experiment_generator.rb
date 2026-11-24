# frozen_string_literal: true

require 'rails/generators/test_unit'

module TestUnit # :nodoc:
  module Generators # :nodoc:
    class ExperimentGenerator < TestUnit::Generators::Base # :nodoc:
      source_root File.expand_path('templates/', __dir__)

      check_class_collision suffix: 'Test'

      def create_test_file
        template 'experiment_test.rb', File.join('test/experiments', class_path, "#{file_name}_experiment_test.rb")
      end
    end
  end
end
