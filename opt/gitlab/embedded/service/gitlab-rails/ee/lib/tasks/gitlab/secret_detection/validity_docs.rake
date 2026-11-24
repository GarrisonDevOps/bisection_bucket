# frozen_string_literal: true

namespace :gitlab do
  namespace :secret_detection do
    namespace :validity_docs do
      desc 'GitLab | Secret Detection | Update the validity check columns in detected_secrets.md'
      task compile: :environment do
        content, unlisted = Security::SecretDetection::ValidityCheckDocs.generate
        File.write(Security::SecretDetection::ValidityCheckDocs::DOC_PATH, content)
        warn "No table row for: #{unlisted.join(', ')}. Add them by hand." if unlisted.any?
      end

      desc 'GitLab | Secret Detection | Fail if the validity check columns are out of date'
      task check: :environment do
        klass = Security::SecretDetection::ValidityCheckDocs
        content, unlisted = klass.generate

        warn "No table row yet for: #{unlisted.join(', ')}. Add the rows when the rules sync lands." if unlisted.any?
        next if content == File.read(klass::DOC_PATH)

        abort 'Validity check columns are out of date. ' \
          'Run: bundle exec rake gitlab:secret_detection:validity_docs:compile'
      end
    end
  end
end
