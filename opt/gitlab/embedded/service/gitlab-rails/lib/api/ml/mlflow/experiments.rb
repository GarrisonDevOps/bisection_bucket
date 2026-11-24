# frozen_string_literal: true

# rubocop:disable API/LifecycleInDescription -- "experiment" is an MLflow domain concept, not a lifecycle term

require 'mime/types'

module API
  # MLFlow integration API, replicating the Rest API https://www.mlflow.org/docs/latest/rest-api.html#rest-api
  module Ml
    module Mlflow
      class Experiments < ::API::Base
        feature_category :mlops

        before do
          check_api_read!
          check_api_write! unless request.get? || request.head?
        end

        resource :experiments do
          desc 'Fetch experiment by experiment_id' do
            success Entities::Ml::Mlflow::GetExperiment
            detail 'https://www.mlflow.org/docs/2.19.0/rest-api.html#get-experiment'
            tags ['mlops']
          end
          params do
            optional :experiment_id, type: String, default: '', desc: 'ID of the experiment, relative to the project.'
          end
          route_setting :authorization, permissions: :read_ml_experiment, boundary_type: :project
          get 'get', urgency: :low do
            present experiment, with: Entities::Ml::Mlflow::GetExperiment
          end

          desc 'Fetch experiment by experiment_name' do
            success Entities::Ml::Mlflow::GetExperiment
            detail 'https://www.mlflow.org/docs/2.19.0/rest-api.html#get-experiment-by-name'
            tags ['mlops']
          end
          params do
            optional :experiment_name, type: String, default: '', desc: 'Name of the experiment.'
          end
          route_setting :authorization, permissions: :read_ml_experiment, boundary_type: :project
          get 'get-by-name', urgency: :low do
            present experiment, with: Entities::Ml::Mlflow::GetExperiment
          end

          desc 'List experiments' do
            success Entities::Ml::Mlflow::ListExperiment
            detail 'https://mlflow.org/docs/1.28.0/rest-api.html#list-experiments'
            tags ['mlops']
          end
          params do
            optional :max_results,
              type: Integer,
              desc: 'Maximum number of experiments to fetch in a page. The maximum is 1000.',
              default: 1000
            optional :page_token,
              type: String,
              desc: 'Token for pagination.'
          end
          route_setting :authorization, permissions: :read_ml_experiment, boundary_type: :project
          get 'list', urgency: :low do
            experiments = experiment_repository.all.including_metadata

            if bounded_list_responses?
              paginator = keyset_paginator_for(experiments)
              result = { experiments: paginator.records, next_page_token: paginator.cursor_for_next_page }
            else
              result = { experiments: experiments.load }
            end

            track_mlflow_event('search_mlflow_experiments', label: 'list')

            present result, with: Entities::Ml::Mlflow::ListExperiment
          end

          desc 'Search experiments' do
            success Entities::Ml::Mlflow::ListExperiment
            detail 'https://www.mlflow.org/docs/2.19.0/rest-api.html#search-experiments'
            tags ['mlops']
          end
          params do
            optional :max_results,
              type: Integer,
              desc: 'Maximum number of experiments to fetch in a page. The maximum is 1000.',
              default: 200
            optional :order_by,
              types: [String, Array[String]],
              desc: 'Column and direction to sort experiments by, for example `created_at DESC` or `name`. Supported ' \
                'columns are `name`, `created_at`, `updated_at`, `last_updated_timestamp` and `id`. A list uses ' \
                'its first entry.',
              default: 'created_at DESC'
            optional :page_token,
              type: String,
              desc: 'Token for pagination.'
            optional :filter,
              type: String,
              desc: 'Ignored. Accepted for MLflow API compatibility.'
          end
          route_setting :authorization, permissions: :read_ml_experiment, boundary_type: :project
          post 'search', urgency: :low do
            finder_params = model_order_params(params)

            finder = ::Projects::Ml::ExperimentFinder.new(user_project, finder_params)
            paginator = keyset_paginator_for(finder.execute.including_metadata)

            result = {
              experiments: paginator.records,
              next_page_token: paginator.cursor_for_next_page
            }
            track_mlflow_event('search_mlflow_experiments', label: 'search')

            present result, with: Entities::Ml::Mlflow::SearchExperiments
          end

          desc 'Create experiment' do
            success Entities::Ml::Mlflow::NewExperiment
            detail 'https://www.mlflow.org/docs/2.19.0/rest-api.html#create-experiment'
            tags ['mlops']
          end
          params do
            requires :name, type: String, desc: 'Name of the experiment.'
            optional :tags, type: Array, desc: 'Tags containing metadata about the experiment.'
            optional :artifact_location, type: String, desc: 'Ignored. Accepted for MLflow API compatibility.'
          end
          route_setting :authorization, permissions: :create_ml_experiment, boundary_type: :project
          post 'create', urgency: :low do
            check_tags_limit!(ApiHelpers::MAX_TAGS_PER_BULK_CREATE_REQUEST)

            new_experiment = experiment_repository.create!(params[:name], params[:tags])
            track_mlflow_event('create_mlflow_experiment')

            present new_experiment, with: Entities::Ml::Mlflow::NewExperiment
          rescue ActiveRecord::RecordInvalid
            resource_already_exists!
          end

          desc 'Sets a tag for an experiment.' do
            summary 'Sets a tag for an experiment. '
            tags ['mlops']
            detail 'https://www.mlflow.org/docs/2.19.0/rest-api.html#set-experiment-tag'
          end
          params do
            requires :experiment_id, type: String, desc: 'ID of the experiment.'
            requires :key, type: String, desc: 'Name of the tag.'
            requires :value, type: String, desc: 'Value of the tag.'
          end
          route_setting :authorization, permissions: :update_ml_experiment, boundary_type: :project
          post 'set-experiment-tag', urgency: :low do
            bad_request! unless experiment_repository.add_tag!(experiment, params[:key], params[:value])
            track_mlflow_event('set_mlflow_experiment_tag')

            {}
          end

          desc 'Delete an experiment.' do
            summary 'Delete an experiment.'
            tags ['mlops']
            detail 'https://mlflow.org/docs/2.19.0/rest-api.html#delete-experiment'
          end
          params do
            requires :experiment_id, type: String, desc: 'ID of the experiment.'
          end
          route_setting :authorization, permissions: :delete_ml_experiment, boundary_type: :project
          post 'delete', urgency: :low do
            destroy = ::Ml::DestroyExperimentService.new(experiment).execute
            if destroy.success?
              present({})
            else
              render_api_error!(destroy.message.first, 400)
            end
          end
        end
      end
    end
  end
end
# rubocop:enable API/LifecycleInDescription
