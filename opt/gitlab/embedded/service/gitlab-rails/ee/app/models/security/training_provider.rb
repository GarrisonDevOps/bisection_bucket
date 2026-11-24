# frozen_string_literal: true

module Security
  class TrainingProvider
    include ActiveRecord::FixedItemsModel::Model
    include GlobalID::Identification

    ITEMS = [
      {
        id: 1,
        name: "Kontra",
        description: "Kontra Application Security provides interactive developer security education that enables \
        engineers to quickly learn security best practices and fix issues in their code by analysing real-world \
        software security vulnerabilities.",
        url: "https://application.security/api/webhook/gitlab/exercises/search",
        logo_url: nil,
        is_enabled: false,
        is_primary: false
      },
      {
        id: 2,
        name: "Secure Code Warrior",
        description: "Resolve vulnerabilities faster and confidently with highly relevant and bite-sized secure \
        coding learning.",
        url: "https://integration-api.securecodewarrior.com/api/v1/trial",
        logo_url: nil,
        is_enabled: false,
        is_primary: false
      },
      {
        id: 3,
        name: "SecureFlag",
        description: "Get remediation advice with example code and recommended hands-on labs in a fully \
        interactive virtualized environment.",
        url: "https://knowledge-base-api.secureflag.com/gitlab",
        logo_url: nil,
        is_enabled: false,
        is_primary: false
      }
    ].freeze

    attribute :id, :integer
    attribute :name, :string
    attribute :description, :string
    attribute :url, :string
    attribute :logo_url, :string
    attribute :is_enabled, :boolean
    attribute :is_primary, :boolean

    def self.for_project(project, only_enabled: false)
      configured_providers = project.security_trainings

      all.map(&:dup).filter_map do |provider|
        provider_configured = configured_providers.find { |configured| configured.training_provider_id == provider.id }

        if provider_configured
          provider.is_enabled = true
          provider.is_primary = provider_configured.is_primary
        elsif only_enabled
          next
        end

        provider
      end
    end
  end
end
