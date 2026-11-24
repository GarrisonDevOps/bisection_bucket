# frozen_string_literal: true

require 'rails/generators'

module Gitlab
  module Generators
    class ExperimentGenerator < Rails::Generators::NamedBase
      source_root File.expand_path('templates/', __dir__)
      check_class_collision suffix: 'Experiment'

      argument :variants, type: :array, default: %w[control candidate], banner: 'variant variant'

      class_option :skip_comments, type: :boolean, default: false, desc: 'Omit helpful comments from generated files'

      def create_experiment
        template 'experiment.rb', File.join('app/experiments', class_path, "#{file_name}_experiment.rb")
      end

      hook_for :test_framework

      private

      def file_name
        @_file_name ||= remove_possible_suffix(super)
      end

      def remove_possible_suffix(name)
        name.sub(/_?exp[ei]riment$/i, "") # be somewhat forgiving with spelling
      end
    end
  end
end
