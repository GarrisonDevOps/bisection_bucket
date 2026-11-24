# frozen_string_literal: true

module API
  module Ai
    module DuoWorkflows
      module Tools
        module RiskAssessment
          # Writeback endpoint for the risk classification tool. Internal
          # tool endpoints (callable only by Duo Workflow Service via
          # composite identity, never by ordinary API tokens) live under this
          # tools namespace, one module per tool.
          class Results < ::API::Base
            include APIGuard

            helpers ::API::Helpers::DuoWorkflowHelpers

            allow_access_with_scope :ai_workflows

            feature_category :dap_code_review

            before do
              authenticate!
            end

            helpers do
              def project_from_params
                @project_from_params ||= find_project!(params[:project_id])
              end

              def merge_request_from_params
                @merge_request_from_params ||= find_project_merge_request(
                  params[:merge_request_iid],
                  project: project_from_params
                )
              end

              # Per-field limits bound each claim but not the payload as a whole, so the
              # assembled envelope is checked against the column's own limit here. Without
              # it an oversized payload is accepted and only fails later, in the scoring job.
              def validate_classification_size!(classification)
                size = ::Gitlab::Json.generate(classification).bytesize
                return if size <= ::MergeRequests::RiskAssessment::SCHEMA_SIZE_LIMIT

                bad_request!(
                  "classification is #{size} bytes, which exceeds the maximum of " \
                    "#{::MergeRequests::RiskAssessment::SCHEMA_SIZE_LIMIT} bytes"
                )
              end

              # The claim name is carried as a value rather than a hash key so a
              # new claim needs no API change, and casing can't drift between the
              # flow's snake_case names and the scoring function's lookups.
              def claims_to_hash(claims)
                claims.to_a.each_with_object({}) do |claim, hash|
                  name = claim[:name].to_s
                  bad_request!("Duplicate claim name: #{name}") if hash.key?(name)

                  hash[name] = { 'value' => claim[:value], 'evidence' => claim[:evidence] }.compact
                end
              end
            end

            namespace :ai do
              namespace :duo_workflows do
                namespace :tools do
                  namespace :risk_assessment do
                    desc 'Submit risk assessment results for a merge request' do
                      detail 'Submits the categorical claims and summary produced by the risk assessment tool.'
                      tags ['gitlab_duo_workflows']
                      success code: 204
                      failure [
                        { code: 400, message: 'Validation failed' },
                        { code: 401, message: 'Unauthorized' },
                        { code: 403, message: 'Forbidden' },
                        { code: 404, message: 'Not found' }
                      ]
                    end
                    params do
                      requires :project_id, type: String,
                        desc: 'The ID or path of the project'
                      requires :merge_request_iid, type: Integer,
                        desc: 'The IID of the merge request'
                      # Lowercase only, on purpose: Gitlab::Git::COMMIT_ID would also accept uppercase hex.
                      requires :diff_sha, type: String, regexp: /\A[0-9a-f]{40}(?:[0-9a-f]{24})?\z/,
                        desc: 'The full SHA of the diff revision the claims were assessed against'
                      requires :workflow_id, type: Integer,
                        desc: 'ID of the Duo workflow session that produced these claims'
                      requires :claims, type: Array, limit: 1000,
                        desc: 'Categorical claims about the merge request' do
                        requires :name, type: String, limit: 64, regexp: /\A[a-z0-9_]+\z/,
                          allow_blank: false,
                          desc: 'Name of the claim, for example authorization'
                        requires :value, type: String, limit: 256, allow_blank: false,
                          desc: 'Categorical answer, for example true, false, or behavioral. Never a score.'
                        optional :evidence, type: String, limit: 256,
                          desc: 'Where the claim was observed, as a path:line reference'
                      end
                      optional :summary, type: String, limit: 2048,
                        desc: 'Plain-language explanation of the change and where its risk lies'
                    end
                    route_setting :lifecycle, :experiment
                    route_setting :authorization, skip_granular_token_authorization: :ai_workflows_oauth_auth
                    post :results do
                      verify_flow_composite_identity!(
                        ::Ai::Catalog::FoundationalFlow.risk_classification_v1,
                        project_from_params
                      )

                      classification = {
                        'claims' => claims_to_hash(params[:claims]),
                        'summary' => params[:summary]
                      }
                      validate_classification_size!(classification)

                      result = ::Gitlab::Duo::RiskAssessment::UpdateResultsService.new(
                        merge_request: merge_request_from_params,
                        diff_sha: params[:diff_sha],
                        classification: classification,
                        workflow_id: params[:workflow_id]
                      ).execute

                      bad_request!(result.message) if result.error?

                      no_content!
                    end
                  end
                end
              end
            end
          end
        end
      end
    end
  end
end
