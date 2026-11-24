# frozen_string_literal: true

module Types
  module Security
    module ScanProfiles
      class DependencyResolutionJobEnum < BaseEnum
        graphql_name 'SecurityScanProfileDependencyResolutionJob'
        description 'Dependency resolution job that can be disabled.'

        value 'MAVEN', value: 'maven', description: 'Maven dependency resolution job.',
          experiment: { milestone: '19.5' }
        value 'GRADLE', value: 'gradle', description: 'Gradle dependency resolution job.',
          experiment: { milestone: '19.5' }
        value 'PYTHON', value: 'python', description: 'Python dependency resolution job.',
          experiment: { milestone: '19.5' }
      end
    end
  end
end
