# frozen_string_literal: true

module API
  class Iterations < ::API::Base
    include PaginationParams

    feature_category :team_planning
    urgency :low

    before do
      adjust_deprecated_state
    end

    helpers do
      include ::API::Helpers::IterationsHelper

      params :list_params do
        optional :state,
          type: String, values: %w[opened upcoming started current closed all],
          default: 'all',
          desc: 'Filter iterations by state. Filtering by `started` is deprecated. Use `current` instead.',
          documentation: { example: 'opened' }
        optional :search,
          type: String,
          desc: 'Return only iterations with a title matching the provided string.',
          documentation: { example: 'version' }
        optional :in,
          type: Array[String], values: %w[title cadence_title],
          default: ['title'],
          desc: 'Fields to search with the `search` query. Possible values are `title` and `cadence_title`.',
          documentation: { example: %w[title cadence_title] }
        optional :include_ancestors,
          type: Grape::API::Boolean,
          default: true,
          desc: 'If `true`, includes iterations for the parent group and its ancestors.',
          documentation: { example: false }
        optional :include_descendants,
          type: Grape::API::Boolean,
          default: false,
          desc: 'If `true`, includes iterations for the parent group and its descendants.',
          documentation: { example: true }
        optional :updated_before,
          type: DateTime,
          desc: 'Return milestones updated before the specified datetime. Format: ISO 8601 YYYY-MM-DDTHH:MM:SSZ',
          documentation: { example: '2023-02-28T21:22:12Z' }
        optional :updated_after,
          type: DateTime,
          desc: 'Return milestones updated after the specified datetime. Format: ISO 8601 YYYY-MM-DDTHH:MM:SSZ',
          documentation: { example: '2023-02-28T21:22:12Z' }
        use :pagination
      end

      def list_iterations_for(parent)
        iterations = IterationsFinder.new(current_user, iterations_finder_params(parent)).execute

        present paginate(iterations), with: Entities::Iteration
      end

      def iterations_finder_params(parent)
        finder_params = {
          parent: parent,
          include_ancestors: params[:include_ancestors],
          include_descendants: params[:include_descendants],
          state: params[:state],
          search: nil,
          in: nil,
          updated_before: params[:updated_before],
          updated_after: params[:updated_after]
        }

        finder_params.merge!(search_params) if params[:search]

        finder_params
      end

      def search_params
        {
          search: params[:search],
          in: params[:in].map(&:to_sym)
        }
      end
    end

    params do
      requires :id,
        types: [String, Integer],
        desc: 'ID or URL-encoded path of the project.',
        documentation: { example: 5 }
    end
    resource :projects, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
      desc 'List all project iterations' do
        detail 'Lists all iterations for a specified project. ' \
          'Iterations created by **Enable automatic scheduling** in iteration cadences return `null` for ' \
          'the `title` and `description` fields. This feature was introduced in GitLab 13.5.'
        success Entities::Iteration
        is_array true
        tags ['iterations']
      end
      params do
        use :list_params
      end
      route_setting :tier, :premium
      route_setting :authorization, permissions: :read_iteration, boundary_type: :project
      get ":id/iterations" do
        authorize! :read_iteration, user_project

        list_iterations_for(user_project)
      end
    end

    params do
      requires :id, type: String, desc: 'ID or URL-encoded path of the group.', documentation: { example: '5' }
    end
    resource :groups, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
      desc 'List all group iterations' do
        detail 'Lists all iterations for a specified group. ' \
          'Iterations created by **Enable automatic scheduling** in iteration cadences return `null` for ' \
          'the `title` and `description` fields. This feature was introduced in GitLab 13.5.'
        success Entities::Iteration
        is_array true
        tags ['iterations']
      end
      params do
        use :list_params
      end
      route_setting :tier, :premium
      route_setting :authorization, permissions: :read_iteration, boundary_type: :group
      get ":id/iterations" do
        authorize! :read_iteration, user_group

        list_iterations_for(user_group)
      end
    end
  end
end
