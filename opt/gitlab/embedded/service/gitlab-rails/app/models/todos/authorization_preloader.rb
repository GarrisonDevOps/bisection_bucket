# frozen_string_literal: true

module Todos
  # Preloads the data that the target policy of each to-do reads to authorize it.
  class AuthorizationPreloader
    TARGET_PROJECT_ASSOCIATIONS = %i[project target_project].freeze

    def initialize(todos, current_user)
      @todos = todos
      @current_user = current_user
    end

    def execute
      preload_target_project_organizations
      ::Preloaders::UserMaxAccessLevelInProjectsPreloader.new(todos.filter_map(&:project), current_user).execute
    end

    private

    attr_reader :todos, :current_user

    # The target policy reads its own project instance, not the to-do project. Grouping by class
    # also covers targets of different classes that share one project.
    def preload_target_project_organizations
      todos.filter_map(&:target).group_by(&:class).each do |klass, targets|
        next unless klass.respond_to?(:reflect_on_association)

        association = TARGET_PROJECT_ASSOCIATIONS.find { |name| klass.reflect_on_association(name) }
        next unless association

        ActiveRecord::Associations::Preloader.new(records: targets, associations: { association => :organization }).call
      end
    end
  end
end
