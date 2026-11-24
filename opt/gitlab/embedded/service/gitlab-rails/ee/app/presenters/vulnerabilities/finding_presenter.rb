# frozen_string_literal: true

module Vulnerabilities
  class FindingPresenter < Gitlab::View::Presenter::Delegated
    include Vulnerabilities::SubmodulePath
    include Vulnerabilities::RelativeUrlRootPath

    presents ::Vulnerabilities::Finding, as: :finding

    delegator_override :location
    def location
      finding.location.presence&.with_indifferent_access ||
        {}.with_indifferent_access
    end

    def title
      name
    end

    def blob_path
      return '' if finding.respond_to?(:secret_redacted?) && finding.secret_redacted?
      return '' unless sha.present?
      return '' unless location.present? && location['file'].present?

      add_line_numbers(location['start_line'], location['end_line'])
    end

    def blob_url
      path = blob_path
      return '' if path.blank?

      project_path = project_blob_path(project, File.join(sha, location['file']))
      project_path = add_line_numbers(location['start_line'], location['end_line'], project_path)
      if path == project_path
        project_url = project_blob_url(project, File.join(sha, location['file']))
        return add_line_numbers(location['start_line'], location['end_line'], project_url)
      end

      absolutize_path(path)
    end

    delegator_override :links
    def links
      @links ||= finding.links.map(&:with_indifferent_access)
    end

    def location_text
      return location['file'] unless location["start_line"]

      "#{location['file']}:#{location['start_line']}"
    end

    def location_link
      return location_text unless location['blob_path']

      ::Gitlab::Utils.append_path(root_url, location['blob_path'])
    end

    private

    def add_line_numbers(start_line, end_line, path = vulnerability_path)
      return path unless start_line

      path_with_line_numbers(path, start_line, end_line)
    end

    def vulnerability_path
      @vulnerability_path ||= begin
        submodule_url = resolve_submodule_blob_url(project, sha, location['file'])
        submodule_url || project_blob_path(project, File.join(sha, location['file']))
      end
    end
  end
end
