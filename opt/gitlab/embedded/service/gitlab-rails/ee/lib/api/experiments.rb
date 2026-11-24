# frozen_string_literal: true

# rubocop:disable API/LifecycleInDescription -- "experiment" refers to GitLab A/B test experiments, not a lifecycle term

module API
  class Experiments < ::API::Base
    before { authorize_experiments_api! }

    feature_category :acquisition

    resource :experiments do
      desc 'List all experiments' do
        detail 'Lists all experiments on the GitLab instance. Each experiment has an `enabled` status that ' \
          'indicates whether the experiment is enabled globally, or only in specific contexts. Each experiment also ' \
          'has a `context` array with the context keys the experiment declares: `user`, `namespace`, `project`, or ' \
          '`actor`. The array is empty for experiments that declare no context keys. Pass these keys when you ' \
          'force, read, or clear a variant assignment. For an `actor` key, pass the `context[user]` parameter, ' \
          'because the actor is resolved from the user.'
        success ::API::Entities::Experiment
        is_array true
        failure [
          { code: 400, message: 'Bad request' },
          { code: 401, message: 'Unauthorized' },
          { code: 403, message: 'Forbidden' }
        ]
        tags %w[experiments]
      end
      route_setting :authorization, permissions: :read_experiment, boundary_type: :instance,
        assignable_when: [:gitlab_team_member]
      get do
        experiments = []

        experiment(:null_hypothesis, canary: true, user: current_user) do |e|
          e.control { bad_request! 'experimentation may not be working right now' }
          e.candidate do
            experiments = Feature::Definition.definitions.values.select { |d| d.attributes[:type] == 'experiment' }
          end
        end

        present experiments, with: ::API::Entities::Experiment, current_user: current_user
      end

      desc 'Delete cached assignments for an experiment' do
        detail 'Removes all cached variant assignments for the experiment with the given cache key. ' \
          'Useful for cleaning up completed experiments whose code has been removed from the codebase. The `name` ' \
          'value is used directly as the cache key, so this endpoint clears any matching cache entry, even one that ' \
          'does not belong to a currently defined experiment.'
        success code: 204
        failure [
          { code: 400, message: 'Bad request' },
          { code: 401, message: 'Unauthorized' },
          { code: 403, message: 'Forbidden' }
        ]
        tags %w[experiments]
      end
      params do
        requires :name, type: String, allow_blank: false, desc: 'Cache key of the experiment to clear.'
      end
      route_setting :authorization, permissions: :delete_experiment_cache, boundary_type: :instance,
        assignable_when: [:gitlab_team_member]
      delete ':name/cache' do
        ApplicationExperiment.new(params[:name]).cache.store.clear(key: params[:name])

        status :no_content
      rescue ArgumentError
        bad_request!('name does not reference an experiment cache')
      end

      route_param :experiment_name, type: String, desc: 'The experiment name' do
        resource :assignments do
          desc 'Get current variant assignment for an experiment context' do
            detail 'Returns the currently cached variant assignment for the given experiment and context. ' \
              'Defaults to current user if no context is provided. If the experiment declares multiple context ' \
              'keys, pass every declared key. The fallback to the authenticated user applies only when you omit ' \
              'the `context` parameter, and only for the `user` and `actor` keys. The `namespace` and `project` ' \
              'keys must always be passed.'
            success ::API::Entities::Experiments::Assignment
            failure [
              { code: 400, message: 'Bad request' },
              { code: 401, message: 'Unauthorized' },
              { code: 403, message: 'Forbidden' }
            ]
            tags %w[experiments]
          end
          params do
            optional :context, type: Hash,
              desc: 'Context parameters (user, namespace, project). Pass every key the experiment declares in ' \
                '`context_keys`. Experiments can declare multiple keys. An actor context is resolved from the ' \
                'user. The user defaults to the current user.'
          end
          route_setting :authorization, permissions: :read_experiment, boundary_type: :instance,
            assignable_when: [:gitlab_team_member]
          get do
            result = ::Experiments::AssignmentService.new(
              experiment_name: params[:experiment_name],
              context_params: params[:context] || {},
              current_user: current_user
            ).read

            if result.success?
              present result.payload, with: ::API::Entities::Experiments::Assignment
            else
              bad_request!(result.message)
            end
          end

          desc 'Force a variant assignment for an experiment context' do
            detail 'Forces a specific variant assignment for the given experiment and context. ' \
              'The assignment is stored in Redis cache and will persist until overwritten. ' \
              'Defaults to current user if no context is provided.'
            success code: 200, model: ::API::Entities::Experiments::Assignment
            failure [
              { code: 400, message: 'Bad request' },
              { code: 401, message: 'Unauthorized' },
              { code: 403, message: 'Forbidden' }
            ]
            tags %w[experiments]
          end
          params do
            requires :variant, type: String, allow_blank: false,
              desc: 'Variant name to assign, for example `control` or `candidate`.'
            optional :context, type: Hash,
              desc: 'Context parameters (user, namespace, project). An actor context is ' \
                'resolved from the user. Defaults to current user.'
          end
          route_setting :authorization, permissions: :create_experiment_assignment, boundary_type: :instance,
            assignable_when: [:gitlab_team_member]
          post do
            status 200

            result = ::Experiments::AssignmentService.new(
              experiment_name: params[:experiment_name],
              variant: params[:variant],
              context_params: params[:context] || {},
              current_user: current_user
            ).write

            if result.success?
              present result.payload, with: ::API::Entities::Experiments::Assignment
            else
              bad_request!(result.message)
            end
          end

          desc 'Clear a variant assignment for an experiment context' do
            detail 'Removes the cached variant assignment for the given experiment and context, ' \
              'returning the actor to normal rollout assignment. Defaults to current user if no ' \
              'context is provided.'
            success code: 204
            failure [
              { code: 400, message: 'Bad request' },
              { code: 401, message: 'Unauthorized' },
              { code: 403, message: 'Forbidden' }
            ]
            tags %w[experiments]
          end
          params do
            optional :context, type: Hash,
              desc: 'Context parameters (user, namespace, project). An actor context is ' \
                'resolved from the user. Defaults to current user.'
          end
          route_setting :authorization, permissions: :delete_experiment_assignment, boundary_type: :instance,
            assignable_when: [:gitlab_team_member]
          delete do
            result = ::Experiments::AssignmentService.new(
              experiment_name: params[:experiment_name],
              context_params: params[:context] || {},
              current_user: current_user
            ).clear

            if result.success?
              status :no_content
            else
              bad_request!(result.message)
            end
          end
        end
      end
    end

    helpers do
      include Gitlab::Experiment::Dsl

      def authorize_experiments_api!
        authenticate!

        forbidden! unless current_user.gitlab_team_member?
      end
    end
  end
end
# rubocop:enable API/LifecycleInDescription
