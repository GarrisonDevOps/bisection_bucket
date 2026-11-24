# frozen_string_literal: true

module Types
  module Ci
    class RunnerCloudProviderEnum < BaseEnum
      graphql_name 'CiRunnerCloudProvider'
      description 'Runner cloud provider.'

      value 'GOOGLE_CLOUD', value: :google_cloud, description: 'Google Cloud.'
      value 'GKE', value: :gke, description: 'Google Kubernetes Engine.'
    end
  end
end
