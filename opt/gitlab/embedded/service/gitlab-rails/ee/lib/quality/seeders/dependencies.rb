# frozen_string_literal: true

module Quality
  module Seeders
    class Dependencies
      UNIQUE_COMPONENT_COUNT = 3
      PROJECT_COUNT = 2

      def initialize
        create_new_group
      end

      def seed!
        seed_data!
      end

      private

      attr_reader :group

      def seed_data!
        PROJECT_COUNT.times do
          project = create_new_project
          pipeline = create_pipeline(project)
          create_sbom_records(pipeline)
        end
        puts "Successfully seeded '#{group.full_path}' for Dependency list!"
        puts "URL: #{Rails.application.routes.url_helpers.group_url(group)}"
      end

      def create_new_group
        suffix = generate_suffix

        @group = FactoryBot.create(
          :group,
          name: "Group level dependencies #{suffix}",
          path: "group-level-dependencies-#{suffix}"
        )
        group.add_owner(admin)
      end

      def create_new_project
        suffix = generate_suffix

        FactoryBot.create(
          :project,
          :repository,
          name: "Project level dependencies #{suffix}",
          path: "project-level-dependencies-#{suffix}",
          creator: admin,
          namespace: group
        )
      end

      def create_pipeline(project)
        default_branch = project.default_branch

        FactoryBot.create(
          :ci_pipeline,
          :success,
          project: project,
          ref: default_branch
        )
      end

      def create_sbom_records(pipeline)
        component_versions.each do |component_version|
          create_occurrences(component_version, pipeline)
          create_occurrences(component_version, pipeline)
        end
      end

      def create_occurrences(component_version, pipeline)
        project = pipeline.project

        source = FactoryBot.create(:sbom_source, input_file_path: "qa-#{generate_suffix}/package-lock.json")
        FactoryBot.create(
          :sbom_occurrence,
          component_version: component_version,
          source: source,
          project: project,
          pipeline: pipeline)
      end

      def component_versions
        @component_versions ||= Array.new(UNIQUE_COMPONENT_COUNT) do |i|
          component = FactoryBot.create(:sbom_component, name: "component-#{generate_suffix}-#{i}")
          FactoryBot.create(:sbom_component_version, component: component)
        end
      end

      def admin
        @admin ||= User.admins.first
      end

      def generate_suffix
        SecureRandom.uuid
      end
    end
  end
end
