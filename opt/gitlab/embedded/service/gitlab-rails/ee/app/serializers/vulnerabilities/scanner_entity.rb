# frozen_string_literal: true

class Vulnerabilities::ScannerEntity < Grape::Entity
  expose :external_id
  expose :name
  expose :vendor
  expose :gitlab_sbom_vulnerability_scanner?, as: :is_vulnerability_scanner
end
