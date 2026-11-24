# frozen_string_literal: true

module API
  module Ci
    class TestBalancing < ::API::Base
      MAX_TEST_SPLITS = 1_000

      feature_category :code_testing
      urgency :low

      default_format :json

      before do
        authenticate!
        require_job_token_authentication!
      end

      helpers do
        def require_job_token_authentication!
          not_found!('Job') unless current_authenticated_job

          ::Gitlab::ApplicationContext.push(job: current_authenticated_job)
        end

        def render_service_error!(response)
          case response.reason
          when :feature_unavailable
            not_found!
          else
            unprocessable_entity!(response.message)
          end
        end
      end

      resource :job do
        namespace :test_balancing do
          desc 'Initialize test balancing for a parallel job' do
            detail "Seeds the job group's shared pending pool with the caller's static test split and claims a " \
              'first batch of test splits. If the node already has claimed test splits (job retry or crash ' \
              'recovery), returns that set unchanged instead. Requires CI_JOB_TOKEN authentication from a ' \
              'parallel job.'
            success code: 201, model: Entities::Ci::TestBalancing::Batch
            failure [
              { code: 401, message: 'Unauthorized' },
              { code: 404, message: 'Not found' },
              { code: 422, message: 'Unprocessable entity' }
            ]
            tags %w[test_balancing]
            hidden true
          end
          params do
            requires :test_splits, type: Array, allow_blank: false, length: { max: MAX_TEST_SPLITS },
              desc: 'The test splits of the static split assigned to this node. When splitting by file, ' \
                'each test split is a test file.' do
              requires :path, type: String, allow_blank: false, length: { max: 1024 },
                desc: 'The path of the test split, relative to the repository root'
              optional :expected_duration, type: Float,
                desc: 'The expected duration of the test split, in seconds'
            end
          end
          route_setting :authentication, job_token_allowed: true
          route_setting :authorization, skip_job_token_policies: true,
            skip_granular_token_authorization: :job_token_auth
          route_setting :lifecycle, :experiment
          post 'initialize' do
            init = ::Ci::TestBalancing::InitializeService.new(current_authenticated_job).execute(params[:test_splits])
            render_service_error!(init) if init.error?

            test_splits_to_replay = init.payload[:test_splits_to_replay]

            if test_splits_to_replay.any?
              present({ mode: 'retry', test_splits: test_splits_to_replay }, with: Entities::Ci::TestBalancing::Batch)
            else
              claim = ::Ci::TestBalancing::ClaimService.new(current_authenticated_job).execute
              render_service_error!(claim) if claim.error?

              present({ mode: 'seed', test_splits: claim.payload[:test_splits] },
                with: Entities::Ci::TestBalancing::Batch)
            end
          end

          desc 'Request the next batch of test splits for a parallel job' do
            detail 'Atomically claims a duration-budgeted batch of pending test splits for the calling node, ' \
              'slowest first. An empty test_splits array means the queue is drained and the node should ' \
              'stop requesting. A retry that sends the same run_id and seq gets the same batch back. ' \
              'Requires CI_JOB_TOKEN authentication from a parallel job.'
            success code: 201, model: Entities::Ci::TestBalancing::Batch
            failure [
              { code: 401, message: 'Unauthorized' },
              { code: 404, message: 'Not found' },
              { code: 422, message: 'Unprocessable entity' }
            ]
            tags %w[test_balancing]
            hidden true
          end
          params do
            optional :run_id, type: String, allow_blank: false, length: { max: 64 },
              desc: 'Client-generated ID of the process making requests, the same for all of its requests.'
            optional :seq, type: Integer, values: 1..((2**31) - 1),
              desc: 'Sequence number of the request within the run. Increase it for each new request, ' \
                'and send the same value when retrying the request.'
            all_or_none_of :run_id, :seq
          end
          route_setting :authentication, job_token_allowed: true
          route_setting :authorization, skip_job_token_policies: true,
            skip_granular_token_authorization: :job_token_auth
          route_setting :lifecycle, :experiment
          post 'request' do
            claim = ::Ci::TestBalancing::ClaimService.new(current_authenticated_job)
              .execute(run_id: params[:run_id], seq: params[:seq])
            render_service_error!(claim) if claim.error?

            present({ test_splits: claim.payload[:test_splits] }, with: Entities::Ci::TestBalancing::Batch)
          end
        end
      end
    end
  end
end
