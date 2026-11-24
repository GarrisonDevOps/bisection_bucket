# frozen_string_literal: true

module Security
  class FindingPresenter < Vulnerabilities::FindingPresenter
    presents ::Security::Finding, as: :finding

    def location_link_with_raw_path
      return '' unless sha.present?
      return '' unless location.present? && location[:file].present?

      path = project_raw_url(finding.project, File.join(finding.sha, location[:file]))
      return path unless location[:start_line].present?

      path_with_line_numbers(path, location[:start_line], location[:end_line])
    end
  end
end
